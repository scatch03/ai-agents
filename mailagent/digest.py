"""
Складання тексту дайджесту.

Три обмеження Telegram, які визначили тут усе:

1. Розмітка не передається (`parse_mode` вимкнено), бо текст із листів не
   має ставати клікабельним. Жирні заголовки робляться через `entities` —
   список зсувів, який рахує код.

2. Зсуви в `entities` — у ОДИНИЦЯХ UTF-16, а не в символах Python. Кожен
   емодзі поза BMP (🚨 📮 ➕) важить дві одиниці. Порахувати len() і
   отримати з᾿їхавший жирний шрифт — класична помилка.

3. Inline-клавіатура кріпиться до ПОВІДОМЛЕННЯ, а не до рядка. Кнопку
   «під пунктом», як намальовано в архітектурі, зробити неможливо: усі
   кнопки збираються внизу, тому підпис кнопки має сам себе пояснювати.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Sequence

from .classify import CATEGORIES, Classified

MAX_TEXT = 4096
MAX_EVENT_BUTTONS = 8

# Рубрики, які показуються лічильником, без переказів кожного листа.
COLLAPSED = ("marketing", "other")
# Рубрики, які показуються завжди, навіть з одним листом.
ALWAYS_SHOWN = ("security", "finance")
# У якому порядку відбирати пункти, коли не вистачає місця (з кінця).
DROP_ORDER = ("worldnews", "marketing", "other", "education", "personal",
              "business", "logistics", "work")

# (значок, назва для лічильника, формулювання в рядку пояснення).
# Формулювання навмисно обережні — «схоже на», а не «це»: перевірки
# евристичні, і безапеляційний тон коштував би довіри при хибному спрацюванні.
THREAT_LABELS = {
    "phishing": ("🚨", "фішинг", "схоже на фішинг"),
    "scam": ("🚨", "шахрайство", "схоже на шахрайство"),
    "injection": ("⚠️", "спроба інструктувати асистента",
                  "спроба інструктувати асистента"),
    "spam": ("▪️", "спам", "схоже на спам"),
}

MONTHS = ("січня", "лютого", "березня", "квітня", "травня", "червня",
          "липня", "серпня", "вересня", "жовтня", "листопада", "грудня")


def utf16_len(text: str) -> int:
    """Довжина в одиницях UTF-16 — саме в них Telegram рахує зсуви entities."""
    return len(text.encode("utf-16-le")) // 2


@dataclass
class MailboxReport:
    """Що сталося з однією скринькою за цей запуск."""
    mailbox_id: str
    count: int = 0
    uid_from: int | None = None
    uid_to: int | None = None
    status: str = "ok"          # ok | empty | error
    error: str = ""
    remaining: int = 0          # скільки листів не влізло в limit

    def line(self) -> str:
        if self.status == "error":
            return f"{self.mailbox_id} — недоступна ({self.error})"
        if self.status == "empty" or not self.count:
            return f"{self.mailbox_id} 0 — порожньо"
        span = (f", uid {self.uid_from}–{self.uid_to}"
                if self.uid_from is not None else "")
        tail = f", ще {self.remaining} чекають" if self.remaining else ""
        word = plural(self.count, "лист", "листи", "листів")
        return f"{self.mailbox_id} {self.count} {word}{span}{tail}"


@dataclass
class Rendered:
    text: str
    entities: list[dict[str, Any]] = field(default_factory=list)
    reply_markup: dict[str, Any] | None = None
    dropped: int = 0            # скільки пунктів не влізло в ліміт

    @property
    def utf16_length(self) -> int:
        return utf16_len(self.text)


class _Builder:
    """Складає текст і паралельно веде зсуви для жирних заголовків."""

    def __init__(self):
        self.parts: list[str] = []
        self.entities: list[dict[str, Any]] = []
        self._offset = 0

    def add(self, text: str, *, bold: bool = False) -> None:
        if bold:
            self.entities.append({"type": "bold", "offset": self._offset,
                                  "length": utf16_len(text)})
        self.parts.append(text)
        self._offset += utf16_len(text)

    def newline(self, count: int = 1) -> None:
        self.add("\n" * count)

    def render(self) -> tuple[str, list[dict[str, Any]]]:
        return "".join(self.parts), self.entities


def _format_date(day: datetime) -> str:
    return f"{day.day} {MONTHS[day.month - 1]}"


def plural(count: int, one: str, few: str, many: str) -> str:
    """«1 лист», «2 листи», «5 листів» — інакше дайджест читається як машинний."""
    if count % 10 == 1 and count % 100 != 11:
        return one
    if count % 10 in (2, 3, 4) and count % 100 not in (12, 13, 14):
        return few
    return many


def _threat_summary(records: Sequence[Classified]) -> str:
    """«🚨 1 фішинг, ▪️ 4 спам» — лічильник позначок у заголовку рубрики."""
    counts: dict[str, int] = {}
    for record in records:
        if record.threat.kind != "none":
            counts[record.threat.kind] = counts.get(record.threat.kind, 0) + 1
    if not counts:
        return ""
    order = [k for k in ("phishing", "scam", "injection", "spam") if k in counts]
    return " " + ", ".join(
        f"{THREAT_LABELS[k][0]} {counts[k]} {THREAT_LABELS[k][1]}" for k in order)


def _item_lines(record: Classified) -> list[str]:
    """Пункт дайджесту. Позначений лист отримує другий рядок із причиною."""
    icon = THREAT_LABELS[record.threat.kind][0] + " " if record.threat.kind != "none" else ""
    head = f"• {icon}{record.summary} [{record.mailbox_id}]"
    lines = [head]
    if record.threat.kind != "none":
        phrase = THREAT_LABELS[record.threat.kind][2]
        reason = f": {record.threat.reason}" if record.threat.reason else ""
        lines.append(f"    {phrase}{reason} — {record.sender}")
    return lines


def _action_lines(records: Sequence[Classified]) -> list[str]:
    out = []
    for record in records:
        if not record.needs_action:
            continue
        deadline = f", до {record.deadline}" if record.deadline else ""
        out.append(f"• {record.summary} ({record.category}{deadline}) "
                   f"[{record.mailbox_id}]")
    return out


def render_digest(records: Sequence[Classified], *,
                  mailboxes: Sequence[MailboxReport],
                  day: datetime,
                  event_drafts: dict[int, tuple[str, dict[str, Any]]] | None = None,
                  notes: Iterable[str] = (),
                  budget: int = MAX_TEXT) -> Rendered:
    """
    Збирає повідомлення. `event_drafts` — uid → (event_id, чернетка події);
    з них будуються кнопки внизу повідомлення.
    `notes` — службові рядки (недоступна скринька, неповний дайджест):
    їх генерує код і тільки код, модель підробити їх не може.
    """
    event_drafts = event_drafts or {}
    by_category: dict[str, list[Classified]] = {c: [] for c in CATEGORIES}
    for record in records:
        by_category[record.category].append(record)

    # Спершу вирішуємо, скільки пунктів показувати, і лише потім рендеримо:
    # бюджет довжини розподіляється наперед, а не обрізається по факту.
    shown = _plan(by_category, budget=budget, mailboxes=mailboxes,
                  notes=list(notes), records=records, day=day,
                  events=len(event_drafts))
    return _compose(records, by_category, shown, mailboxes=mailboxes, day=day,
                    event_drafts=event_drafts, notes=list(notes))


def _plan(by_category: dict[str, list[Classified]], *, budget: int,
          mailboxes: Sequence[MailboxReport], notes: list[str],
          records: Sequence[Classified], day: datetime, events: int) -> dict[str, int]:
    """
    Скільки пунктів показати в кожній рубриці. Починаємо з «усе» і знімаємо
    з найменш термінових, доки не вліземо. Позначені листи не знімаються
    ніколи — інакше саме вони й зникнуть.
    """
    shown = {c: len(v) for c, v in by_category.items()}
    for category in COLLAPSED:
        shown[category] = 0  # згорнуті рубрики показують лише позначені листи

    while True:
        draft = _compose(records, by_category, shown, mailboxes=mailboxes, day=day,
                         event_drafts={}, notes=notes)
        if draft.utf16_length <= budget - 120:  # запас під кнопки і примітку
            return shown
        for category in DROP_ORDER:
            flagged = sum(1 for r in by_category[category] if r.threat.kind != "none")
            if shown[category] > flagged:
                shown[category] -= 1
                break
        else:
            return shown  # знімати більше нічого


def _compose(records, by_category, shown, *, mailboxes, day, event_drafts,
             notes) -> Rendered:
    builder = _Builder()
    total = len(records)
    builder.add(f"Дайджест {_format_date(day)}", bold=True)
    builder.add(f" — {total} {plural(total, 'лист', 'листи', 'листів')}")
    builder.newline(2)

    actions = _action_lines(records)
    if actions:
        builder.add("⚠️ Потребує дії", bold=True)
        builder.newline()
        for line in actions:
            builder.add(line)
            builder.newline()
        builder.newline()

    empty: list[str] = []
    dropped = 0
    for category in CATEGORIES:
        group = by_category[category]
        if not group:
            empty.append(category)
            continue

        header = f"{category} ({len(group)})"
        builder.add(header, bold=True)
        builder.add(_threat_summary(group))
        if category in COLLAPSED:
            builder.add(" — без деталей")
        builder.newline()

        limit = shown[category]
        listed = 0
        for record in group:
            flagged = record.threat.kind != "none"
            # Позначений лист показується завжди — навіть у згорнутій рубриці,
            # інакше саме там і сховається найцікавіше.
            if not flagged and listed >= limit:
                # Рубрики зі списку COLLAPSED згорнуті за задумом — це не
                # обрізання за лімітом, і примітку про Telegram воно не
                # виправдовує. Рахуємо лише те, що зняв планувальник бюджету.
                if category not in COLLAPSED:
                    dropped += 1
                continue
            for line in _item_lines(record):
                builder.add(line)
                builder.newline()
            listed += 1
        builder.newline()

    if empty:
        builder.add("порожньо: " + ", ".join(empty))
        builder.newline(2)

    builder.add("📮 Джерела", bold=True)
    builder.newline()
    for report in mailboxes:
        builder.add(report.line())
        builder.newline()

    if dropped:
        word = plural(dropped, "пункт", "пункти", "пунктів")
        notes = [*notes, f"{dropped} {word} згорнуто через ліміт Telegram"]
    if notes:
        builder.newline()
        for note in notes:
            builder.add(f"⚠️ {note}")
            builder.newline()

    text, entities = builder.render()
    return Rendered(text=text.rstrip() + "\n", entities=entities,
                    reply_markup=_buttons(event_drafts), dropped=dropped)


def _buttons(event_drafts: dict[int, tuple[str, dict[str, Any]]]) -> dict | None:
    """
    Кнопки збираються ВНИЗУ повідомлення — Telegram не вміє кріпити їх до
    рядка. Тому підпис має сам себе пояснювати: у ньому назва події й час,
    а не безлике «Додати».
    """
    if not event_drafts:
        return None
    rows = []
    for uid, (event_id, event) in list(event_drafts.items())[:MAX_EVENT_BUTTONS]:
        start = datetime.fromisoformat(event["start"])
        title = event["title"][:28]
        when = (start.strftime("%d.%m") if event.get("all_day")
                else start.strftime("%d.%m %H:%M"))
        rows.append([
            {"text": f"➕ {title} · {when}",
             "callback_data": f"add:{event_id}"},
            {"text": "✖️", "callback_data": f"skip:{event_id}"},
        ])
    return {"inline_keyboard": rows}

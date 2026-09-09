"""
Дві точки входу агента.

digest_run   — щоранку за розкладом: опитати скриньки, класифікувати,
               надіслати дайджест, і ЛИШЕ ПІСЛЯ цього зсунути курсори.
callback_run — коли власник натиснув кнопку: моделі тут немає взагалі,
               виконується перевірена вранці чернетка за непрозорим id.

Порядок дій у digest_run не гнучкий і зашитий тут навмисно: віддавати
його моделі означало б платити токенами за переплановування того самого
щоранку й ризикувати, що одного разу вона надішле дайджест двічі.
"""

from __future__ import annotations

import signal
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Callable, Sequence

from . import threats
from .classify import Classified, Letter, Usage, classify, triage
from .config import Config, load_config, telegram_owner_id
from .digest import MailboxReport, keyboard, render_digest
from .errors import ToolError
from .retry import ToolRetryError
from .state import State
from .tools import call
from .tools import calendar as cal
from .tools import mail, telegram


@dataclass
class Limits:
    """Стелі з архітектури. Досягнення будь-якої — не збій, а привід зупинитись."""
    max_iterations: int = 100
    max_cost_usd: float = 0.10
    max_seconds: float = 600.0
    # Наскільки будильник відстає від м'якого бюджету часу. Спершу має
    # спрацювати штатна зупинка з «неповним дайджестом», і лише якщо вона
    # недосяжна — бо виклик завис усередині SDK — рве будильник.
    hard_margin_seconds: float = 60.0


@dataclass
class Budget:
    limits: Limits = field(default_factory=Limits)
    iterations: int = 0
    started: float = field(default_factory=time.monotonic)
    usage: Usage = field(default_factory=Usage)

    def tick(self, count: int = 1) -> None:
        self.iterations += count

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def exceeded(self) -> str | None:
        if self.iterations >= self.limits.max_iterations:
            return f"ліміт ітерацій ({self.limits.max_iterations})"
        if self.usage.cost_usd >= self.limits.max_cost_usd:
            return f"ліміт бюджету (${self.limits.max_cost_usd})"
        if self.elapsed >= self.limits.max_seconds:
            return f"ліміт часу ({self.limits.max_seconds:.0f} c)"
        return None


@dataclass
class MailboxOutcome:
    """Результат опитування однієї скриньки. Скриньки незалежні одна від одної."""
    mailbox_id: str
    letters: list[Letter] = field(default_factory=list)
    uidvalidity: int | None = None
    max_uid: int = 0
    ok: bool = True
    error: str = ""
    remaining: int = 0
    polled: bool = False        # чи дійшли до неї взагалі

    label: str = ""             # адреса скриньки для тексту дайджесту

    def report(self) -> MailboxReport:
        if not self.polled:
            return MailboxReport(self.mailbox_id, self.label, status="error",
                                 error="не опитана: спрацював ліміт запуску")
        if not self.ok:
            return MailboxReport(self.mailbox_id, self.label, status="error",
                                 error=self.error)
        if not self.letters:
            return MailboxReport(self.mailbox_id, self.label, status="empty")
        uids = [letter.uid for letter in self.letters]
        return MailboxReport(self.mailbox_id, self.label, count=len(uids),
                             uid_from=min(uids), uid_to=max(uids),
                             remaining=self.remaining)


# --------------------------------------------------------------------------
# Збір пошти
# --------------------------------------------------------------------------
def collect(config: Config, state: State, conns: mail.Connections, budget: Budget,
            *, limit: int | None = None) -> list[MailboxOutcome]:
    outcomes: list[MailboxOutcome] = []
    for box in config.mailboxes:
        outcome = MailboxOutcome(mailbox_id=box.id, label=box.user)
        outcomes.append(outcome)
        if budget.exceeded():
            continue
        outcome.polled = True
        cursor = state.cursor(box.id)
        budget.tick()
        try:
            result = call(mail.list_new_emails, box.id, cursor.uid, conns=conns,
                          uidvalidity=cursor.uidvalidity,
                          limit=limit or config.max_letters_per_mailbox,
                          label=f"list_new_emails/{box.id}")
        except (ToolError, ToolRetryError) as exc:
            # Падіння однієї скриньки не зупиняє запуск: дайджест без неї
            # корисніший за відсутність дайджесту. Курсор при цьому не рухаємо.
            outcome.ok, outcome.error = False, _short(exc)
            continue

        outcome.uidvalidity = result["uidvalidity"]
        outcome.remaining = result.get("remaining", 0)
        for message in result["messages"]:
            outcome.letters.append(Letter(
                uid=message["uid"], mailbox_id=box.id, sender=message["from"],
                subject=message["subject"], date=message["date"],
                snippet=message["snippet"], auth_passed=message["auth_passed"],
                has_attachments=message["has_attachments"],
            ))
        if outcome.letters:
            outcome.max_uid = max(letter.uid for letter in outcome.letters)
        else:
            outcome.max_uid = cursor.uid
    return outcomes


def fetch_bodies(letters: Sequence[Letter], wanted: set[int],
                 conns: mail.Connections, budget: Budget, *,
                 max_chars: int) -> None:
    """Тягне тіла тільки для листів із вибірки. Промах — не привід падати."""
    by_uid = {letter.uid: letter for letter in letters}
    for uid in sorted(wanted):
        if budget.exceeded():
            return
        letter = by_uid.get(uid)
        if letter is None:
            continue  # uid поза вибіркою вже відфільтрував triage, це підстраховка
        budget.tick()
        try:
            body = call(mail.fetch_email_body, letter.mailbox_id, uid, conns=conns,
                        max_chars=max_chars, label=f"fetch_email_body/{uid}")
        except (ToolError, ToolRetryError):
            # Лист прибрали між опитуванням і читанням — класифікуємо
            # за темою і відправником, які вже маємо.
            continue
        letter.body = body["text"]
        letter.links = body["links"]
        letter.attachments = body["attachments"]


# --------------------------------------------------------------------------
# digest_run
# --------------------------------------------------------------------------
class RunTimeout(RuntimeError):
    """Спрацював жорсткий ліміт часу на весь запуск."""


@contextmanager
def _deadline(seconds: float):
    """
    Будильник на весь запуск. Бюджет часу перевіряється між кроками, тому
    один виклик, що завис усередині SDK, обходить його повністю: саме так
    ранковий дайджест 9 вересня провисів 57 хвилин замість десяти.
    Працює лише в головному потоці — інакше просто нічого не робить.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def _fire(signum, frame):
        raise RunTimeout(f"запуск перевищив {seconds:.0f} c і зупинений будильником")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def digest_run(*, config: Config | None = None, state: State | None = None,
               conns: mail.Connections | None = None,
               llm_fn: Callable[..., dict] | None = None,
               sender: Callable[..., dict] = telegram.send_message,
               day: date | None = None, limits: Limits | None = None,
               dry_run: bool = False) -> dict[str, Any]:
    config = config or load_config()
    state = state or State()
    budget = Budget(limits=limits or Limits())
    day = day or datetime.now(timezone.utc).date()
    owns_conns = conns is None
    conns = conns or mail.Connections(config)

    try:
        state.purge_expired_events()
        with _deadline(budget.limits.max_seconds + budget.limits.hard_margin_seconds):
            outcomes = collect(config, state, conns, budget)
            letters = [letter for outcome in outcomes for letter in outcome.letters]

            kwargs = {"llm_fn": llm_fn} if llm_fn else {}
            if letters and not budget.exceeded():
                budget.tick()
                wanted = triage(letters, usage=budget.usage, **kwargs)
                fetch_bodies(letters, wanted, conns, budget,
                             max_chars=config.body_max_chars)

            records: list[Classified] = []
            if letters:
                budget.tick()
                records, _ = classify(letters, usage=budget.usage,
                                      known_senders=state.known_senders, **kwargs)
    finally:
        if owns_conns:
            conns.close_all()

    labels = _labels(config)
    notes = [f"{labels.get(o.mailbox_id, o.mailbox_id)} недоступна: {o.error}"
             for o in outcomes if not o.ok]
    stopped = budget.exceeded()
    if stopped:
        notes.append(f"неповний дайджест: спрацював {stopped}")

    drafts = _make_drafts(records, state, ttl_days=config.pending_event_ttl_days)
    rendered = render_digest(
        records, mailboxes=[o.report() for o in outcomes],
        day=datetime.combine(day, datetime.min.time()), event_drafts=drafts,
        notes=notes,
        # Підписувати кожен рядок має сенс лише за кількох скриньок.
        labels=labels if len(config.mailboxes) > 1 else {})

    if dry_run:
        return _summary(rendered, records, outcomes, budget, sent=None,
                        cursors_moved=[])

    key = f"digest-{day.isoformat()}"
    sent = sender(rendered.text, state=state, idempotency_key=key,
                  entities=rendered.entities, reply_markup=rendered.reply_markup)
    budget.tick()

    # ЛИШЕ ТЕПЕР курсори. Зсунути їх до відправки означало б, що листи
    # вважаються обробленими, а людина їх ніколи не побачить — і не дізнається.
    cursors_moved: list[str] = []
    if sent.get("sent") or sent.get("already_sent"):
        state.remember_digest_events(event_id for event_id, _ in drafts.values())
        for outcome in outcomes:
            if outcome.ok and outcome.polled and not stopped:
                state.set_cursor(outcome.mailbox_id, outcome.max_uid,
                                 outcome.uidvalidity)
                cursors_moved.append(outcome.mailbox_id)
        state.note_senders(
            threats.registrable(threats.domain_of(letter.sender)) for letter in letters)
        state.save()

    return _summary(rendered, records, outcomes, budget, sent=sent,
                    cursors_moved=cursors_moved)


def _report_with_label(outcome: "MailboxOutcome", labels: dict[str, str]):
    report = outcome.report()
    report.label = labels.get(outcome.mailbox_id, outcome.mailbox_id)
    return report


def _labels(config: Config) -> dict[str, str]:
    """
    Як називати скриньки в тексті — адресою, а не внутрішнім id.
    Якщо дві скриньки на одній адресі (різні теки того самого акаунта),
    адреси замало: додаємо id, інакше в дайджесті вони нерозрізненні.
    """
    users = [box.user for box in config.mailboxes]
    return {
        box.id: (box.user if users.count(box.user) == 1
                 else f"{box.user} / {box.id}")
        for box in config.mailboxes
    }


def _make_drafts(records: Sequence[Classified], state: State, *, ttl_days: int
                 ) -> dict[int, tuple[str, dict[str, Any]]]:
    drafts: dict[int, tuple[str, dict[str, Any]]] = {}
    for record in records:
        if not record.event:
            continue
        event_id = state.put_pending_event(
            title=record.event["title"], start=record.event["start"],
            end=record.event["end"], location=record.event.get("location", ""),
            all_day=record.event.get("all_day", False),
            source=f"{record.mailbox_id}/{record.uid}", ttl_days=ttl_days)
        drafts[record.uid] = (event_id, record.event)
    return drafts


def _summary(rendered, records, outcomes, budget, *, sent, cursors_moved
             ) -> dict[str, Any]:
    return {
        "letters": len(records),
        "mailboxes_ok": [o.mailbox_id for o in outcomes if o.ok and o.polled],
        "mailboxes_failed": [o.mailbox_id for o in outcomes if not o.ok],
        "iterations": budget.iterations,
        "cost_usd": budget.usage.cost_usd,
        "seconds": round(budget.elapsed, 2),
        "stopped_by": budget.exceeded(),
        "cursors_moved": cursors_moved,
        "sent": sent,
        "text": rendered.text,
        "dropped": rendered.dropped,
    }


def _short(exc: Exception) -> str:
    text = str(exc)
    return text[:120] + ("…" if len(text) > 120 else "")


# --------------------------------------------------------------------------
# callback_run
# --------------------------------------------------------------------------
def callback_run(update: dict[str, Any], *, state: State | None = None,
                 owner_id: int | None = None,
                 answer: Callable[..., dict] = telegram.answer_callback,
                 edit: Callable[..., dict] = telegram.edit_message_buttons,
                 sender: Callable[..., dict] = telegram.send_message,
                 creator: Callable[..., dict] = cal.create_calendar_event,
                 ) -> dict[str, Any]:
    """
    Обробляє натискання кнопки. Моделі тут немає: виконується збережена
    чернетка за id, а не нове тлумачення листа.
    """
    state = state or State()
    query = update.get("callback_query") or {}
    callback_id = query.get("id", "")
    from_id = (query.get("from") or {}).get("id")
    data = query.get("data", "")

    owner = owner_id if owner_id is not None else telegram_owner_id()
    if from_id != owner:
        # Кнопку натиснув не власник (наприклад, повідомлення переслали).
        answer(callback_id, "Ця кнопка не для вас")
        return {"ok": False, "reason": "not_owner"}

    # Підтверджуємо ПЕРШИМ: доки бот не відповів, у клієнті крутиться
    # індикатор, а попереду похід у Google Calendar на кілька секунд.
    action, _, event_id = data.partition(":")
    answer(callback_id, "Додаю в календар…" if action == "add" else "Гаразд")

    if action == "skip":
        cal.decline_event(event_id, state=state)
        _refresh_buttons(edit, state)
        return {"ok": True, "action": "skip", "event_id": event_id}
    if action != "add":
        return {"ok": False, "reason": "unknown_action"}

    try:
        result = call(creator, event_id, state=state, label=f"create_event/{event_id}")
    except (ToolError, ToolRetryError) as exc:
        # Чернетку НЕ чіпаємо: коли власник перепідключить доступ,
        # кнопка має спрацювати з тими самими даними.
        sender(f"⚠️ Не вдалося додати подію: {_short(exc)}\n"
               f"Чернетка збережена — спробуйте ще раз пізніше.",
               state=state, idempotency_key=f"cb-{event_id}-error-{int(time.time())}")
        return {"ok": False, "reason": "create_failed", "error": str(exc)}

    event = state.event(event_id) or {}
    edited = _refresh_buttons(edit, state)
    if not edited:
        # Ранкове повідомлення видалили — редагувати нічого. Подія створена,
        # і це головне; мовчати не можна, тому шлемо окреме підтвердження.
        sender(f"✅ Додано в календар: {event.get('title', 'подія')}",
               state=state, idempotency_key=f"cb-{event_id}-done")
    return {"ok": True, "action": "add", "event_id": event_id,
            "already_created": result.get("already_created", False),
            "buttons_edited": edited}


def _refresh_buttons(edit: Callable[..., dict], state: State) -> bool:
    """
    Перемальовує клавіатуру ЦІЛКОМ за поточним станом усіх чернеток дайджесту.
    Часткового оновлення в Telegram немає: якщо надіслати один рядок, решта
    кнопок зникне — і сусідні події стануть недосяжними, хоча чернетки живі.
    """
    message_id = state.last_digest_message_id
    if not message_id:
        return False
    events = [(eid, state.event(eid)) for eid in state.digest_events]
    events = [(eid, ev) for eid, ev in events if ev]
    markup = keyboard(events) or {"inline_keyboard": []}
    return bool(edit(message_id, markup).get("edited"))

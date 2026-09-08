"""
Пам'ять між запусками: курсори, дата останнього дайджесту, ключі
ідемпотентності й чернетки подій.

Тут навмисно багато перевірок і мало гнучкості. Це те місце, де помилка
не помітна одразу: зсунутий курсор мовчки ховає пошту, а втрачена чернетка
перетворює кнопку в дайджесті на пустушку.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .errors import ToolError

DEFAULT_STATE_PATH = ".state/state.json"
STATE_VERSION = 1


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Cursor:
    uid: int
    uidvalidity: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {"uid": self.uid, "uidvalidity": self.uidvalidity}


class State:
    """Файл JSON із атомарним записом. Один процес, один запуск — блокування зайве."""

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path or os.getenv("MAILAGENT_STATE", DEFAULT_STATE_PATH))
        self._data = self._read()

    # ------------------------------------------------------------------ io
    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": STATE_VERSION, "cursors": {}, "sent_keys": {},
                    "pending_events": {}, "known_senders": {},
                    "last_digest_date": None, "last_digest_message_id": None}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            # Стан зіпсовано. Мовчки почати з нуля не можна: це означало б
            # перечитати всю пошту наново і надіслати гігантський дайджест.
            raise ToolError(
                f"стан {self.path} не читається як JSON ({exc}). Полагодь або "
                f"перейменуй файл вручну — почати з порожнього означає "
                f"продублювати всю пошту", status=400) from exc
        data.setdefault("cursors", {})
        data.setdefault("sent_keys", {})
        data.setdefault("pending_events", {})
        data.setdefault("known_senders", {})
        return data

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # tmp + replace: обрив живлення посеред запису не залишить огризок
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.path.parent, delete=False
        ) as fh:
            json.dump(self._data, fh, ensure_ascii=False, indent=2)
            tmp = Path(fh.name)
        tmp.replace(self.path)

    # ------------------------------------------------------------- курсори
    def cursor(self, mailbox_id: str) -> Cursor:
        raw = self._data["cursors"].get(mailbox_id)
        if not raw:
            return Cursor(uid=0, uidvalidity=None)
        return Cursor(uid=int(raw.get("uid", 0)), uidvalidity=raw.get("uidvalidity"))

    def set_cursor(self, mailbox_id: str, uid: int, uidvalidity: int | None) -> None:
        """
        Курсор рухається тільки вперед. Виняток — зміна UIDVALIDITY: тоді
        нумерація на сервері інша і порівнювати старий uid з новим немає сенсу.
        """
        old = self.cursor(mailbox_id)
        same_numbering = (
            old.uidvalidity is not None and uidvalidity is not None
            and old.uidvalidity == uidvalidity
        )
        if same_numbering and uid < old.uid:
            raise ToolError(
                f"курсор {mailbox_id} відкочується назад: {old.uid} → {uid}. "
                f"Це або помилка в коді, або спроба змусити агента перечитати "
                f"пошту — відхиляю", status=400)
        self._data["cursors"][mailbox_id] = Cursor(uid, uidvalidity).to_json()

    # ------------------------------------------------- ідемпотентність
    def sent(self, key: str) -> dict[str, Any] | None:
        return self._data["sent_keys"].get(key)

    def mark_sent(self, key: str, message_id: int) -> None:
        self._data["sent_keys"][key] = {
            "message_id": message_id, "at": _now().isoformat()
        }
        if key.startswith("digest-"):
            self._data["last_digest_date"] = key.removeprefix("digest-")
            self._data["last_digest_message_id"] = message_id

    @property
    def last_digest_date(self) -> str | None:
        return self._data.get("last_digest_date")

    @property
    def last_digest_message_id(self) -> int | None:
        return self._data.get("last_digest_message_id")

    # -------------------------------------------------- чернетки подій
    def put_pending_event(self, *, title: str, start: str, end: str,
                          source: str, location: str = "", all_day: bool = False,
                          ttl_days: int = 7) -> str:
        event_id = "ev_" + secrets.token_hex(3)
        self._data["pending_events"][event_id] = {
            "title": title, "start": start, "end": end, "location": location,
            "all_day": all_day, "source": source, "status": "pending",
            "created_at": _now().isoformat(),
            "expires_at": (_now() + timedelta(days=ttl_days)).isoformat(),
            "google_event_id": None,
        }
        return event_id

    def pending_event(self, event_id: str) -> dict[str, Any]:
        event = self._data["pending_events"].get(event_id)
        if event is None:
            raise ToolError(
                f"чернетки {event_id} немає: вона або виконана й прибрана, "
                f"або їй вийшов TTL", status=404)
        if datetime.fromisoformat(event["expires_at"]) < _now():
            raise ToolError(
                f"чернетці {event_id} вийшов термін ({event['expires_at']}) — "
                f"лист занадто старий, додай подію вручну", status=410)
        return event

    def mark_event_created(self, event_id: str, google_event_id: str) -> None:
        event = self._data["pending_events"][event_id]
        event["status"] = "created"
        event["google_event_id"] = google_event_id

    def mark_event_declined(self, event_id: str) -> None:
        self._data["pending_events"][event_id]["status"] = "declined"

    def purge_expired_events(self, *, today: date | None = None) -> int:
        now = datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc) \
            if today else _now()
        stale = [
            eid for eid, ev in self._data["pending_events"].items()
            if datetime.fromisoformat(ev["expires_at"]) < now
        ]
        for eid in stale:
            del self._data["pending_events"][eid]
        return len(stale)

    # ------------------------------------------------ курсор оновлень Telegram
    @property
    def last_update_id(self) -> int:
        return int(self._data.get("last_update_id", 0))

    def set_last_update_id(self, value: int) -> None:
        """Щоб після перезапуску не обробити ті самі натискання вдруге."""
        self._data["last_update_id"] = max(value, self.last_update_id)

    # ------------------------------------------------- відомі відправники
    @property
    def known_senders(self) -> set[str]:
        """
        Домени, від яких уже приходило. Потрібні перевірці «перший контакт»:
        терміновість плюс прохання про оплату від незнайомця важать більше,
        ніж те саме від підрядника, з яким листуєшся рік.
        """
        return set(self._data.setdefault("known_senders", {}))

    def note_senders(self, domains: "Iterable[str]") -> None:
        seen = self._data.setdefault("known_senders", {})
        for domain in domains:
            if domain:
                seen[domain] = seen.get(domain, 0) + 1

    # ------------------------------------------------------------- сервіс
    def snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._data))

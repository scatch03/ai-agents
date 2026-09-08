"""
Конфіг агента: список скриньок і адресати. Секретів тут немає — паролі
й токени живуть у .env, у конфізі лише імена змінних за домовленістю.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from .errors import ConfigError

load_dotenv()

DEFAULT_CONFIG_PATH = "mailboxes.json"
_ID_RE = re.compile(r"^[a-z0-9_]{2,32}$")


@dataclass(frozen=True)
class Mailbox:
    id: str
    host: str
    user: str
    port: int = 993
    folder: str = "INBOX"
    # readonly=True скрізь: агент не має права позначати листи прочитаними

    @property
    def password_env(self) -> str:
        """Домовленість: MAILBOX_<ID>_PASSWORD. У конфізі пароля немає."""
        return f"MAILBOX_{self.id.upper()}_PASSWORD"

    def password(self) -> str:
        value = os.environ.get(self.password_env, "").strip()
        if not value:
            raise ConfigError(
                f"{self.password_env} не заданий — додай app password скриньки "
                f"{self.id} у .env і перезапусти процес"
            )
        return value


@dataclass(frozen=True)
class Config:
    mailboxes: tuple[Mailbox, ...]
    timezone: str = "Europe/Kyiv"
    digest_hour: int = 8
    calendar_name: str = "Пошта (агент)"
    max_letters_per_mailbox: int = 200
    # Скільки днів забирати на першому запуску (або після зміни UIDVALIDITY).
    # У скриньці можуть лежати тисячі листів — весь архів нам не потрібен.
    first_run_days: int = 1
    body_max_chars: int = 3000
    pending_event_ttl_days: int = 7
    _by_id: dict[str, Mailbox] = field(default_factory=dict, repr=False, compare=False)

    def mailbox(self, mailbox_id: str) -> Mailbox:
        """Скринька поза конфігом не існує — це і є перевірка з архітектури."""
        try:
            return self._by_id[mailbox_id]
        except KeyError:
            known = ", ".join(self._by_id) or "(жодної)"
            raise ConfigError(
                f"скриньки {mailbox_id!r} немає в конфізі; відомі: {known}"
            ) from None

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(self._by_id)


def _require_env(name: str, hint: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} не заданий — {hint}")
    return value


def telegram_token() -> str:
    return _require_env("TELEGRAM_BOT_TOKEN", "візьми його у @BotFather")


def telegram_chat_id() -> str:
    """Єдиний адресат. Змінити його вмістом листа неможливо — його тут просто немає."""
    return _require_env("TELEGRAM_CHAT_ID", "id приватного чату з ботом")


def telegram_owner_id() -> int:
    """Чиї натискання кнопок агент взагалі розглядає."""
    raw = _require_env("TELEGRAM_OWNER_ID", "твій числовий user id у Telegram")
    try:
        return int(raw)
    except ValueError:
        raise ConfigError("TELEGRAM_OWNER_ID має бути числом") from None


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    path = Path(path or os.getenv("MAILAGENT_CONFIG", DEFAULT_CONFIG_PATH))
    if not path.exists():
        raise ConfigError(
            f"немає конфігу {path}. Скопіюй mailboxes.example.json у {path} "
            f"і впиши свої скриньки"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"конфіг {path} — некоректний JSON: {exc}") from exc

    entries = raw.get("mailboxes")
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"у конфізі {path} немає непорожнього списку mailboxes")

    mailboxes: list[Mailbox] = []
    seen: set[str] = set()
    for entry in entries:
        try:
            box = Mailbox(
                id=entry["id"], host=entry["host"], user=entry["user"],
                port=int(entry.get("port", 993)),
                folder=entry.get("folder", "INBOX"),
            )
        except (KeyError, TypeError) as exc:
            raise ConfigError(f"скринька {entry!r}: бракує поля {exc}") from exc
        if not _ID_RE.match(box.id):
            raise ConfigError(
                f"id скриньки {box.id!r} не годиться: лише [a-z0-9_], 2–32 символи "
                f"(з нього будується імʼя змінної з паролем)"
            )
        if box.id in seen:
            raise ConfigError(f"id скриньки {box.id!r} трапляється двічі")
        seen.add(box.id)
        mailboxes.append(box)

    settings = raw.get("settings", {})
    return Config(
        mailboxes=tuple(mailboxes),
        timezone=settings.get("timezone", "Europe/Kyiv"),
        digest_hour=int(settings.get("digest_hour", 8)),
        calendar_name=settings.get("calendar_name", "Пошта (агент)"),
        max_letters_per_mailbox=int(settings.get("max_letters_per_mailbox", 200)),
        first_run_days=int(settings.get("first_run_days", 1)),
        body_max_chars=int(settings.get("body_max_chars", 3000)),
        pending_event_ttl_days=int(settings.get("pending_event_ttl_days", 7)),
        _by_id={box.id: box for box in mailboxes},
    )

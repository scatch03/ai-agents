"""
Інструмент запису в Google Calendar.

Єдиний параметр — event_id. Ані назва, ані час не приходять іззовні:
все береться з чернетки, яку перевірив і зберіг ранковий запуск. Кнопка
запускає збережені дані, а не нове тлумачення листа.

Учасників і запрошень у цьому інструменті немає взагалі. Це не забуто —
це вимкнено: з полем attendees лист від стороннього перетворював би
календар на канал розсилки листів третім особам від імені власника.
"""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from ..errors import ConfigError, ToolError
from ..state import State

TOKEN_URL = "https://oauth2.googleapis.com/token"
API = "https://www.googleapis.com/calendar/v3"
HTTP_TIMEOUT = 20

_token_cache: dict[str, Any] = {"value": None, "expires_at": 0.0}


def _env(name: str, hint: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} не заданий — {hint}")
    return value


def calendar_id() -> str:
    """Окремий календар «Пошта (агент)»: інший колір, вимикається одним перемикачем."""
    return _env("GOOGLE_CALENDAR_ID", "id окремого календаря для подій з пошти")


def access_token(*, client: httpx.Client | None = None,
                 now: Callable[[], float] = lambda: datetime.now(timezone.utc).timestamp()
                 ) -> str:
    """Обмінює refresh token на access token і тримає його в пам'яті до згасання."""
    if _token_cache["value"] and _token_cache["expires_at"] > now() + 60:
        return _token_cache["value"]

    payload = {
        "client_id": _env("GOOGLE_OAUTH_CLIENT_ID", "з Google Cloud Console"),
        "client_secret": _env("GOOGLE_OAUTH_CLIENT_SECRET", "з Google Cloud Console"),
        "refresh_token": _env("GOOGLE_OAUTH_REFRESH_TOKEN",
                              "одноразовий OAuth-обмін; помічника ще не написано"),
        "grant_type": "refresh_token",
    }
    owns = client is None
    client = client or httpx.Client(timeout=HTTP_TIMEOUT)
    try:
        response = client.post(TOKEN_URL, data=payload)
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ToolError(f"google oauth: {exc}", status=503) from exc
    finally:
        if owns:
            client.close()

    if response.status_code != 200:
        # invalid_grant = доступ відкликано. Повторні спроби це не полагодять:
        # потрібна дія людини, і чернетку при цьому втрачати не можна.
        raise ToolError(
            f"google oauth: {response.status_code} {body.get('error')} — "
            f"{body.get('error_description', '')}", status=response.status_code)

    _token_cache["value"] = body["access_token"]
    _token_cache["expires_at"] = now() + float(body.get("expires_in", 3600))
    return _token_cache["value"]


def _google_event_id(event_id: str) -> str:
    """
    Детермінований id події з нашого event_id. Google дозволяє задавати id
    самому і на повторне створення відповідає 409 — це другий, серверний
    захист від дублю, поверх нашого статусу в стані.
    Алфавіт Google: base32hex у нижньому регістрі, 5–1024 символи.
    """
    digest = hashlib.sha1(event_id.encode()).digest()
    return base64.b32hexencode(digest).decode().lower().rstrip("=")


def create_calendar_event(event_id: str, *, state: State,
                          client: httpx.Client | None = None,
                          token_provider: Callable[..., str] = access_token
                          ) -> dict[str, Any]:
    """
    Створює подію з чернетки. Повертає
    {created, google_event_id, html_link, already_created}.
    """
    event = state.pending_event(event_id)  # кине 404/410, якщо немає або протермінована

    if event["status"] == "created" and event.get("google_event_id"):
        return {"created": False, "google_event_id": event["google_event_id"],
                "html_link": event.get("html_link", ""), "already_created": True}
    if event["status"] == "declined":
        raise ToolError(f"чернетку {event_id} власник уже відхилив", status=409)

    all_day = bool(event.get("all_day"))
    start = datetime.fromisoformat(event["start"])
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    # Подія на цілий день «сьогодні» ще не минула — звіряємо з початком доби.
    if start < (now.replace(hour=0, minute=0, second=0, microsecond=0)
                if all_day else now):
        raise ToolError(
            f"подія {event_id} у минулому ({event['start']}) — не створюю",
            status=400)

    gid = _google_event_id(event_id)
    # Google розрізняє події з часом і на цілий день полем: dateTime проти date.
    key = "date" if all_day else "dateTime"
    body = {
        "id": gid,
        "summary": event["title"][:120],
        "start": {key: event["start"]},
        "end": {key: event["end"]},
        # Джерело завжди видно: з якого листа приїхала подія.
        "description": f"Створено з листа: {event['source']}",
        # attendees НЕ передаємо — див. докстрінг модуля.
    }
    if event.get("location"):
        body["location"] = event["location"][:200]

    token = token_provider(client=client)
    owns = client is None
    client = client or httpx.Client(timeout=HTTP_TIMEOUT)
    try:
        response = client.post(
            f"{API}/calendars/{calendar_id()}/events",
            params={"sendUpdates": "none"},  # нікого не сповіщати, нікому не писати
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        )
    except httpx.HTTPError as exc:
        raise ToolError(f"google calendar: {exc}", status=503) from exc
    finally:
        if owns:
            client.close()

    if response.status_code == 409:
        # Подія з таким id уже є — кнопку натиснули двічі. Це успіх, не помилка.
        state.mark_event_created(event_id, gid)
        state.save()
        return {"created": False, "google_event_id": gid, "html_link": "",
                "already_created": True}

    if response.status_code >= 300:
        raise ToolError(
            f"google calendar: {response.status_code} {response.text[:300]}",
            status=response.status_code)

    created = response.json()
    state.mark_event_created(event_id, created.get("id", gid))
    state._data["pending_events"][event_id]["html_link"] = created.get("htmlLink", "")
    state.save()
    return {"created": True, "google_event_id": created.get("id", gid),
            "html_link": created.get("htmlLink", ""), "already_created": False}


def decline_event(event_id: str, *, state: State) -> dict[str, Any]:
    """Кнопка «✖️ Не треба»: чернетка більше не пропонується, у календар нічого не йде."""
    state.pending_event(event_id)
    state.mark_event_declined(event_id)
    state.save()
    return {"declined": True}

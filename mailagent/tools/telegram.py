"""
Інструменти Telegram: надсилання дайджесту і службові виклики для кнопок.

Два рішення, які тут головні і які видно прямо в сигнатурах:

1. chat_id НЕ є параметром. Адресат один і береться з конфігу — це те, що
   робить неможливим «переслати кудись» за вказівкою з листа.
2. parse_mode не передається ніколи. Текст із листів іде голим, а жирні
   заголовки рубрик робляться через entities, зсуви для яких рахує код.
   Інакше тема листа «[ваш банк](http://evil.example)» стала б клікабельним
   посиланням усередині повідомлення від довіреного бота.
"""

from __future__ import annotations

from typing import Any, Callable

import httpx

from ..config import telegram_chat_id, telegram_token
from ..errors import ToolError
from ..state import State

API = "https://api.telegram.org"
MAX_TEXT = 4096
TRUNCATION_NOTE = "\n… дайджест обрізано за лімітом Telegram"
HTTP_TIMEOUT = 20


def _call(method: str, payload: dict[str, Any], *,
          client: httpx.Client | None = None) -> dict[str, Any]:
    url = f"{API}/bot{telegram_token()}/{method}"
    owns = client is None
    client = client or httpx.Client(timeout=HTTP_TIMEOUT)
    try:
        response = client.post(url, json=payload)
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ToolError(f"telegram {method}: {exc}", status=503) from exc
    finally:
        if owns:
            client.close()

    if not body.get("ok"):
        # Telegram сам каже, скільки чекати при 429 — це точніше за наш backoff.
        retry_after = (body.get("parameters") or {}).get("retry_after")
        raise ToolError(
            f"telegram {method}: {response.status_code} {body.get('description')}",
            status=response.status_code, retry_after=retry_after)
    return body["result"]


def send_message(text: str, *, state: State, idempotency_key: str,
                 entities: list[dict[str, Any]] | None = None,
                 reply_markup: dict[str, Any] | None = None,
                 client: httpx.Client | None = None,
                 caller: Callable[..., dict] = _call) -> dict[str, Any]:
    """
    Надсилає повідомлення. idempotency_key формує КОД (наприклад
    "digest-2026-09-08"), не модель: ключ, яким розпоряджається модель,
    перестає бути захистом від дублю.

    Повертає {sent, message_id, already_sent}.
    """
    seen = state.sent(idempotency_key)
    if seen:
        return {"sent": False, "message_id": seen["message_id"], "already_sent": True}

    if len(text) > MAX_TEXT:
        # Довжину має розподіляти той, хто складає дайджест; тут — останній
        # запобіжник, щоб не отримати 400 і не втратити повідомлення цілком.
        text = text[:MAX_TEXT - len(TRUNCATION_NOTE)] + TRUNCATION_NOTE
        entities = [e for e in (entities or []) if e["offset"] + e["length"] <= len(text)]

    payload: dict[str, Any] = {"chat_id": telegram_chat_id(), "text": text,
                               "disable_web_page_preview": True}
    if entities:
        payload["entities"] = entities
    if reply_markup:
        payload["reply_markup"] = reply_markup

    result = caller("sendMessage", payload, client=client)
    message_id = result["message_id"]
    state.mark_sent(idempotency_key, message_id)
    state.save()
    return {"sent": True, "message_id": message_id, "already_sent": False}


def answer_callback(callback_id: str, text: str = "", *,
                    client: httpx.Client | None = None,
                    caller: Callable[..., dict] = _call) -> dict[str, Any]:
    """
    Підтверджує натискання кнопки. Викликається ПЕРШИМ, до будь-якої роботи:
    доки бот не відповів, у клієнті крутиться індикатор, а попереду похід
    у Google Calendar на кілька секунд.
    """
    payload: dict[str, Any] = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text[:200]
    caller("answerCallbackQuery", payload, client=client)
    return {"answered": True}


def edit_message_buttons(message_id: int, reply_markup: dict[str, Any], *,
                         client: httpx.Client | None = None,
                         caller: Callable[..., dict] = _call) -> dict[str, Any]:
    """
    Оновлює кнопки під ранковим дайджестом. НЕ кидає помилку, якщо не вийшло:
    напис на кнопці — косметика, а подія в календарі вже створена. Викликач
    сам вирішує, чи слати окреме підтвердження.

    Поширений міф про «48 годин» тут ні до чого: ліміт стосується
    business-повідомлень, надісланих не ботом і без inline-клавіатури.
    Реальна причина відмови — повідомлення видалили з чату.
    """
    payload = {"chat_id": telegram_chat_id(), "message_id": message_id,
               "reply_markup": reply_markup}
    try:
        caller("editMessageReplyMarkup", payload, client=client)
        return {"edited": True, "reason": None}
    except ToolError as exc:
        return {"edited": False, "reason": str(exc)}


def event_buttons(event_id: str, *, done_label: str | None = None) -> dict[str, Any]:
    """Клавіатура під пунктом з подією. callback_data — лише непрозорий id."""
    if done_label:
        return {"inline_keyboard": [[{"text": done_label, "callback_data": "noop"}]]}
    return {"inline_keyboard": [[
        {"text": "➕ У календар", "callback_data": f"add:{event_id}"},
        {"text": "✖️ Не треба", "callback_data": f"skip:{event_id}"},
    ]]}

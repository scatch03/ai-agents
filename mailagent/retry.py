"""
Політика повторів для інструментів — та сама, що в llm.py із заняття 3:
1 → 2 → 4 → 8 секунд, максимум 5 спроб, після останньої падаємо помилкою.

Свідомо окремий модуль, а не імпорт із llm.py: llm.py — це зданий артефакт
ДЗ 3, і його публічний контракт краще не чіпати. Правила збігаються, і якщо
колись розійдуться — розходження має бути видно в диффі, а не приховане
спільним кодом.
"""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime
from typing import Any, Callable

MAX_ATTEMPTS = 5


def stamp() -> str:
    """
    Мітка часу для логів. Без неї в журналі launchd неможливо сказати,
    коли саме почалося зависання і скільки воно тривало — доводиться
    з'ясовувати це через ps по вцілілому процесу.
    """
    return datetime.now().strftime("%H:%M:%S")

TRANSIENT_STATUSES = {408, 409, 425, 429, 500, 502, 503, 504, 529}
FATAL_STATUSES = {400, 401, 403, 404, 422}

# «Немає грошей» і «немає прав» не минають самі — на відміну від «занадто часто».
FATAL_MARKERS = (
    "insufficient_quota", "no credits remaining", "credit balance is too low",
    "invalid_grant", "invalid credentials", "authenticationfailed",
)

TRANSIENT_MARKERS = (
    "rate limit", "ratelimit", "too many requests", "overloaded", "unavailable",
    "timeout", "timed out", "connection", "temporarily", "try again", "reset by peer",
    # Обриви сокета. Без них перший тайм-аут IMAP робив «невідновлюваними»
    # усі наступні виклики, і запуск тихо лишався без половини листів.
    "broken pipe", "socket error", "eof occurred", "not connected",
    "connection closed", "server closed",
)

_DELAY_PATTERNS = (
    re.compile(r"retry[_ ]after[\"']?[:= ]+([\d.]+)", re.I),
    re.compile(r"retry in ([\d.]+)\s*s", re.I),
    re.compile(r"try again in ([\d.]+)s", re.I),
)
MAX_SERVER_DELAY = 60.0


def base_delay() -> float:
    return float(os.getenv("LLM_RETRY_BASE_DELAY", "1"))


def status_of(exc: Exception) -> int | None:
    for attr in ("status", "status_code", "http_status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) else None


def is_transient(exc: Exception) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    if any(marker in text for marker in FATAL_MARKERS):
        return False
    status = status_of(exc)
    if status in TRANSIENT_STATUSES:
        return True
    if status in FATAL_STATUSES:
        return False
    return any(marker in text for marker in TRANSIENT_MARKERS)


def suggested_delay(exc: Exception) -> float | None:
    """Скільки чекати за словами сервера — точніше за сліпий backoff."""
    value = getattr(exc, "retry_after", None)
    if isinstance(value, (int, float)) and value > 0:
        return min(float(value), MAX_SERVER_DELAY)
    for pattern in _DELAY_PATTERNS:
        match = pattern.search(str(exc))
        if match:
            return min(float(match.group(1)), MAX_SERVER_DELAY)
    return None


def with_retry(call: Callable[[], Any], *, label: str,
               max_attempts: int = MAX_ATTEMPTS,
               sleep: Callable[[float], None] = time.sleep) -> tuple[Any, int, float]:
    """Повертає (результат, скільки спроб знадобилось, тривалість вдалої спроби)."""
    last: Exception | None = None
    used = 0
    for attempt in range(1, max_attempts + 1):
        used = attempt
        try:
            started = time.perf_counter()
            result = call()
            return result, attempt, time.perf_counter() - started
        except Exception as exc:  # noqa: BLE001 — свідомо ловимо все від бібліотек
            last = exc
            status = status_of(exc)
            print(f"{stamp()} [retry] {label} спроба {attempt}/{max_attempts} впала: "
                  f"{type(exc).__name__} status={status}: {exc}"[:400],
                  file=sys.stderr, flush=True)
            if not is_transient(exc):
                print(f"{stamp()} [retry] {label}: помилка невідновлювана — "
                      f"падаємо одразу",
                      file=sys.stderr, flush=True)
                break
            if attempt == max_attempts:
                break
            delay = base_delay() * (2 ** (attempt - 1))
            server = suggested_delay(exc)
            note = ""
            if server and server > delay:
                delay, note = server + 0.5, f" (сервер попросив {server:g} c)"
            print(f"{stamp()} [retry] {label}: чекаю {delay:g} c і пробую ще раз{note}",
                  file=sys.stderr, flush=True)
            sleep(delay)

    reason = "усі спроби вичерпано" if used == max_attempts else "помилка невідновлювана"
    raise ToolRetryError(f"{label}: {reason} ({used}/{max_attempts} спроб) — {last}",
                         cause=last) from last


class ToolRetryError(RuntimeError):
    def __init__(self, message: str, *, cause: Exception | None = None):
        super().__init__(message)
        self.cause = cause
        self.status = status_of(cause) if cause else None

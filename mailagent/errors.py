"""Помилки інструментального шару."""

from __future__ import annotations


class ToolError(RuntimeError):
    """
    Помилка виклику інструмента.

    status — HTTP-подібний код, за яким політика ретраю вирішує, чи має сенс
    повторювати. Для не-HTTP джерел (IMAP) підбираємо найближчий за змістом:
    401 — не пустили, 404 — немає такого, 503 — сервер зараз не може.
    """

    def __init__(self, message: str, *, status: int | None = None,
                 retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class ConfigError(ToolError):
    """Немає ключа, немає скриньки в конфізі, зламаний конфіг. Не ретраїться."""

    def __init__(self, message: str):
        super().__init__(message, status=400)

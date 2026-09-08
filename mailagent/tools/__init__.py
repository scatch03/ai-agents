"""
Інструменти агента і єдина точка, через яку їх варто викликати.

`call()` загортає будь-який інструмент у політику повторів з retry.py:
429/5xx/тайм-аути повторюємо з backoff 1→2→4→8, а 401/404 — ні, бо
відкликаний пароль і видалений лист від повторів не зʼявляються.
"""

from __future__ import annotations

from typing import Any, Callable

from ..retry import with_retry

__all__ = ["call"]


def call(tool: Callable[..., Any], *args: Any, label: str | None = None,
         max_attempts: int = 5, **kwargs: Any) -> Any:
    """
    Виклик інструмента з повторами. Повертає результат самого інструмента;
    скільки знадобилося спроб — у полі `_attempts` результату-словника.
    """
    label = label or tool.__name__
    result, attempts, seconds = with_retry(
        lambda: tool(*args, **kwargs), label=label, max_attempts=max_attempts)
    if isinstance(result, dict):
        result["_attempts"] = attempts
        result["_seconds"] = round(seconds, 3)
    return result

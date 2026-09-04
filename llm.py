"""
llm.py — один контракт, кілька провайдерів.

    from llm import llm
    r = llm("Привіт", system="Відповідай українською", provider="google")
    print(r["text"], r["in_tokens"], r["out_tokens"], r["cost_usd"])

Усе, що залежить від провайдера, живе всередині цього файлу.
Виклик назовні не змінюється — у цьому й сенс абстракції.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Callable

from dotenv import load_dotenv

load_dotenv()  # читаємо .env один раз на старті процесу

# google-genai пише в лог пораду про AFC на кожен generate_content — зайвий шум у консолі
logging.getLogger("google_genai.models").setLevel(logging.ERROR)

# ---------------------------------------------------------------------------
# Ціни. ОБОВ'ЯЗКОВО звірити перед здачею — прайси змінюються.
# Формат: (price_in, price_out) у доларах за 1_000_000 токенів.
# ---------------------------------------------------------------------------
PRICING_SOURCES = {
    "google": "https://ai.google.dev/gemini-api/docs/pricing",
    "openai": "https://openai.com/api/pricing/",
    "anthropic": "https://www.anthropic.com/pricing#api",
}

PRICES: dict[str, tuple[float, float]] = {
    # google
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-flash-lite": (0.10, 0.40),
    # openai
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4o-mini": (0.15, 0.60),
    # anthropic
    "claude-haiku-4-5": (1.00, 5.00),
}

DEFAULT_MODELS = {
    "google": "gemini-2.5-flash",
    "openai": "gpt-4.1-mini",
    "anthropic": "claude-haiku-4-5",
}

ENV_KEYS = {
    "google": "GOOGLE_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

MAX_ATTEMPTS = 5


def _base_delay() -> float:
    """Базова затримка ретраю. Читаємо щоразу, щоб демо могло її підмінити."""
    return float(os.getenv("LLM_RETRY_BASE_DELAY", "1"))


def _retry_all_errors() -> bool:
    """Ретраїти навіть 401/403. За замовчуванням ні — це лише для демо ретраю."""
    return os.getenv("LLM_RETRY_ALL_ERRORS", "0") == "1"


# ---------------------------------------------------------------------------
# Помилки
# ---------------------------------------------------------------------------
class LLMError(RuntimeError):
    """Виклик не вдався. Після вичерпання спроб падаємо цим, а не повертаємо None."""


class ConfigError(LLMError):
    """Немає ключа / невідомий провайдер / не встановлений SDK."""


def key_tail(provider: str) -> str:
    """Останні 4 символи ключа — для перевірки, що .env узагалі прочитався."""
    key = os.environ.get(ENV_KEYS[provider], "")
    return f"...{key[-4:]}" if len(key) >= 4 else "(немає)"


def _require_key(provider: str) -> str:
    key = os.environ.get(ENV_KEYS[provider], "").strip()
    if not key:
        raise ConfigError(
            f"{ENV_KEYS[provider]} не заданий. Додай його в .env і ПЕРЕЗАПУСТИ процес."
        )
    return key


# ---------------------------------------------------------------------------
# Класифікація помилок: що має сенс повторювати, а що ні
# ---------------------------------------------------------------------------
_TRANSIENT_STATUSES = {408, 409, 429, 500, 502, 503, 504, 529}
_FATAL_STATUSES = {400, 401, 403, 404, 422}

_TRANSIENT_MARKERS = (
    "rate limit", "ratelimit", "resource_exhausted", "quota",
    "overloaded", "unavailable", "timeout", "timed out",
    "connection", "temporarily", "try again", "deadline",
)


def _status_of(exc: Exception) -> int | None:
    for attr in ("status_code", "code", "http_status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) else None


def _is_transient(exc: Exception) -> bool:
    """True — має сенс повторити. False — повтор нічого не змінить."""
    status = _status_of(exc)
    if status in _TRANSIENT_STATUSES:
        return True
    if status in _FATAL_STATUSES:
        return False
    text = f"{type(exc).__name__} {exc}".lower()
    if any(str(s) in text for s in _TRANSIENT_STATUSES):
        return True
    return any(marker in text for marker in _TRANSIENT_MARKERS)


# ---------------------------------------------------------------------------
# Retry: 1 → 2 → 4 → 8 c, максимум 5 спроб
# ---------------------------------------------------------------------------
def _with_retry(call: Callable[[], Any], *, label: str) -> Any:
    last: Exception | None = None
    used = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        used = attempt
        try:
            return call()
        except ConfigError:
            raise  # ключа немає — повторювати нічого
        except Exception as exc:  # noqa: BLE001 — навмисно ловимо все від SDK
            last = exc
            status = _status_of(exc)
            transient = _is_transient(exc)
            retryable = transient or _retry_all_errors()

            head = f"[retry] {label} спроба {attempt}/{MAX_ATTEMPTS} впала"
            print(f"{head}: {type(exc).__name__} status={status}: {exc}"[:400],
                  file=sys.stderr, flush=True)

            if not retryable:
                print(f"[retry] {label}: помилка невідновлювана — повтор не допоможе, "
                      f"падаємо одразу", file=sys.stderr, flush=True)
                break
            if attempt == MAX_ATTEMPTS:
                break

            delay = _base_delay() * (2 ** (attempt - 1))  # 1, 2, 4, 8
            print(f"[retry] {label}: чекаю {delay:g} c і пробую ще раз",
                  file=sys.stderr, flush=True)
            time.sleep(delay)

    reason = ("усі спроби вичерпано" if used == MAX_ATTEMPTS
              else "помилка невідновлювана")
    raise LLMError(f"{label}: {reason} ({used}/{MAX_ATTEMPTS} спроб) — {last}") from last


# ---------------------------------------------------------------------------
# Гілки провайдерів. Кожна повертає (text, in_tokens, out_tokens, stop_reason).
# ---------------------------------------------------------------------------
def _call_google(prompt, system, model, max_tokens, temperature, json_mode):
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise ConfigError("pip install google-genai") from exc

    client = genai.Client(api_key=_require_key("google"))
    config = types.GenerateContentConfig(
        system_instruction=system or None,
        temperature=temperature,
        max_output_tokens=max_tokens,
        # gemini-2.5-* «думає» за замовчуванням, і ці токени їдять max_output_tokens:
        # відповідь приходить порожня з finish_reason=MAX_TOKENS. Вимикаємо.
        thinking_config=types.ThinkingConfig(thinking_budget=0),
        response_mime_type="application/json" if json_mode else None,
    )
    resp = client.models.generate_content(model=model, contents=prompt, config=config)

    usage = resp.usage_metadata
    in_tokens = usage.prompt_token_count or 0
    out_tokens = (usage.candidates_token_count or 0) + (usage.thoughts_token_count or 0)
    finish = resp.candidates[0].finish_reason if resp.candidates else None
    stop_reason = getattr(finish, "name", str(finish)).lower() if finish else "unknown"
    return (resp.text or ""), in_tokens, out_tokens, stop_reason


def _call_openai(prompt, system, model, max_tokens, temperature, json_mode):
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise ConfigError("pip install openai") from exc

    client = OpenAI(api_key=_require_key("openai"), max_retries=0)  # ретраї — наші
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        response_format={"type": "json_object"} if json_mode else {"type": "text"},
    )
    choice = resp.choices[0]
    return (
        choice.message.content or "",
        resp.usage.prompt_tokens,
        resp.usage.completion_tokens,
        choice.finish_reason,
    )


def _call_anthropic(prompt, system, model, max_tokens, temperature, json_mode):
    try:
        import anthropic
    except ImportError as exc:
        raise ConfigError("pip install anthropic") from exc

    client = anthropic.Anthropic(api_key=_require_key("anthropic"), max_retries=0)
    # У Anthropic: max_tokens ОБОВ'ЯЗКОВИЙ, а system — окремий параметр,
    # а не елемент messages (інакше 400).
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system or anthropic.NOT_GIVEN,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    return text, resp.usage.input_tokens, resp.usage.output_tokens, resp.stop_reason


_PROVIDERS = {
    "google": _call_google,
    "openai": _call_openai,
    "anthropic": _call_anthropic,
}


# ---------------------------------------------------------------------------
# Публічний контракт
# ---------------------------------------------------------------------------
def llm(
    prompt: str,
    system: str = "",
    provider: str = "google",
    *,
    model: str | None = None,
    max_tokens: int = 800,
    temperature: float = 0.0,
    json_mode: bool = False,
) -> dict:
    """
    Один виклик моделі. Повертає:
    {
      "text": "...",            # відповідь моделі
      "in_tokens": 412,
      "out_tokens": 87,
      "stop_reason": "end_turn",
      "seconds": 1.8,
      "cost_usd": 0.00042,
      "provider": "google",
      "model": "gemini-2.5-flash",
    }
    Помилка після 5 спроб — LLMError, не None.
    """
    if provider not in _PROVIDERS:
        raise ConfigError(
            f"Невідомий провайдер {provider!r}. Доступні: {', '.join(_PROVIDERS)}"
        )
    model = model or DEFAULT_MODELS[provider]
    call = _PROVIDERS[provider]

    started = time.perf_counter()
    text, in_tokens, out_tokens, stop_reason = _with_retry(
        lambda: call(prompt, system, model, max_tokens, temperature, json_mode),
        label=f"{provider}/{model}",
    )
    seconds = time.perf_counter() - started

    return {
        "text": text,
        "in_tokens": in_tokens,
        "out_tokens": out_tokens,
        "stop_reason": stop_reason,
        "seconds": round(seconds, 2),
        "cost_usd": cost_usd(model, in_tokens, out_tokens),
        "provider": provider,
        "model": model,
    }


def cost_usd(model: str, in_tokens: int, out_tokens: int) -> float:
    """cost = (in_tokens * price_in + out_tokens * price_out) / 1_000_000"""
    if model not in PRICES:
        raise ConfigError(f"Немає ціни для моделі {model!r} — додай її в PRICES.")
    price_in, price_out = PRICES[model]
    return round((in_tokens * price_in + out_tokens * price_out) / 1_000_000, 8)


# ---------------------------------------------------------------------------
# Крок 2: перший виклик до кожного провайдера
#     python llm.py            — усі провайдери, у яких є ключ
#     python llm.py google      — конкретний
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    wanted = sys.argv[1:] or list(_PROVIDERS)
    for name in wanted:
        print(f"\n=== {name} ({DEFAULT_MODELS[name]}) ключ {key_tail(name)} ===")
        if key_tail(name) == "(немає)":
            print("пропускаю: ключа в .env немає")
            continue
        r = llm(
            "Назви столицю України одним словом.",
            system="Відповідай коротко, без пояснень.",
            provider=name,
            max_tokens=64,
        )
        print("text        :", r["text"].strip())
        print("stop_reason :", r["stop_reason"])
        print("tokens      : in", r["in_tokens"], "/ out", r["out_tokens"])
        print("time / cost :", r["seconds"], "c /", f'${r["cost_usd"]:.8f}')

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
import re
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
    "groq": "https://console.groq.com/docs/models",
    "anthropic": "https://www.anthropic.com/pricing#api",
}

PRICES: dict[str, tuple[float, float]] = {
    # google — звірено 2026-09-04 на ai.google.dev/gemini-api/docs/pricing.
    # УВАГА: 0.75/3.75 — акційна ціна до 31.12.2026, з 01.01.2027 буде 1.50/7.50.
    "gemini-3.8-flash": (0.75, 3.75),
    "gemini-3.7-flash": (0.75, 3.75),
    "gemini-3.6-flash": (0.75, 3.75),
    "gemini-3.5-flash-lite": (0.30, 2.50),
    "gemini-3.1-flash-lite": (0.25, 1.50),
    # openai
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4o-mini": (0.15, 0.60),
    # groq — звірено 2026-09-04 на console.groq.com/docs/models
    "openai/gpt-oss-120b": (0.15, 0.60),
    "openai/gpt-oss-20b": (0.075, 0.30),
    "qwen/qwen3.8-27b": (0.80, 4.00),
    "qwen/qwen3.6-27b": (0.60, 3.00),
    # anthropic
    "claude-haiku-4-5": (1.00, 5.00),
}

DEFAULT_MODELS = {
    # gemini-2.5-flash новим ключам більше не видають (404 з підказкою оновитися).
    # 3.6 і 3.5-flash-lite не приймають thinking_budget=0 (400) і зʼїдають весь
    # max_tokens на міркування; 3.7 і 3.8 вимкнути міркування дозволяють.
    # Квота безкоштовного тарифу (20 запитів) рахується ОКРЕМО на кожну модель,
    # тому впертися в ліміт на одній ще не означає, що Google недоступний.
    "google": "gemini-3.7-flash",
    "openai": "gpt-4.1-mini",
    # gpt-oss-20b валить 400 на json_object, qwen утричі дорожчий за той самий результат
    "groq": "openai/gpt-oss-120b",
    "anthropic": "claude-haiku-4-5",
}

ENV_KEYS = {
    "google": "GOOGLE_API_KEY",
    "openai": "OPENAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

MAX_ATTEMPTS = 5
# Без явного таймауту виклик може висіти годинами: SDK читає з сокета, який
# сервер уже не обслуговує, а наш бюджет часу перевіряється лише МІЖ кроками.
REQUEST_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "120"))


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

# 429 буває двох різних сортів: «занадто часто» (мине саме) і «немає грошей»
# (не мине ніколи). Другий не ретраїмо — інакше 5 спроб по 15 c на кожен виклик.
# Маркери мають бути ВУЗЬКІ: у Google 429 про ліміт частоти теж згадує billing,
# і надто широкий маркер ховав цілком відновлювану помилку.
_FATAL_MARKERS = (
    "insufficient_quota", "no credits remaining", "credit balance is too low",
    "purchase credits",
)

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
    text_all = f"{type(exc).__name__} {exc}".lower()
    if any(marker in text_all for marker in _FATAL_MARKERS):
        return False
    status = _status_of(exc)
    if status in _TRANSIENT_STATUSES:
        return True
    if status in _FATAL_STATUSES:
        return False
    text = f"{type(exc).__name__} {exc}".lower()
    if any(str(s) in text for s in _TRANSIENT_STATUSES):
        return True
    return any(marker in text for marker in _TRANSIENT_MARKERS)


_DELAY_PATTERNS = (
    re.compile(r"retry in ([\d.]+)\s*s", re.I),        # google: "Please retry in 23.9s"
    re.compile(r"retryDelay['\"]?:\s*['\"]?(\d+)s"),   # google, поле в details
    re.compile(r"try again in ([\d.]+)s", re.I),        # openai / groq
)
MAX_SERVER_DELAY = 60.0


def _suggested_delay(exc: Exception) -> float | None:
    """Скільки чекати за словами сервера. Це точніше за наш сліпий backoff."""
    for attr in ("retry_after", "retry_delay"):
        value = getattr(exc, attr, None)
        if isinstance(value, (int, float)) and value > 0:
            return min(float(value), MAX_SERVER_DELAY)
    text = str(exc)
    for pattern in _DELAY_PATTERNS:
        match = pattern.search(text)
        if match:
            return min(float(match.group(1)), MAX_SERVER_DELAY)
    return None


# ---------------------------------------------------------------------------
# Retry: 1 → 2 → 4 → 8 c, максимум 5 спроб.
# Якщо сервер назвав власну затримку — беремо більшу з двох.
# ---------------------------------------------------------------------------
def _with_retry(call: Callable[[], Any], *, label: str) -> tuple[Any, int, float]:
    """Повертає (результат, скільки спроб знадобилось, тривалість вдалої спроби)."""
    last: Exception | None = None
    used = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        used = attempt
        try:
            started = time.perf_counter()
            result = call()
            return result, attempt, time.perf_counter() - started
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
            server = _suggested_delay(exc)
            if server and server > delay:
                delay = server + 0.5  # +0.5 c, щоб не впертися в межу вікна
                note = f" (сервер попросив {server:g} c)"
            else:
                note = ""
            print(f"[retry] {label}: чекаю {delay:g} c і пробую ще раз{note}",
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

    client = genai.Client(
        api_key=_require_key("google"),
        http_options=types.HttpOptions(timeout=int(REQUEST_TIMEOUT * 1000)),
    )
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


def _openai_compatible(provider: str, base_url: str | None = None):
    """
    Фабрика гілки для будь-якого провайдера, що говорить протоколом OpenAI.
    Groq — саме такий: той самий SDK, інший base_url. Своя гілка йому не потрібна.
    """

    def _call(prompt, system, model, max_tokens, temperature, json_mode):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ConfigError("pip install openai") from exc

        client = OpenAI(  # max_retries=0: ретраї робить наша функція, не SDK
            api_key=_require_key(provider), base_url=base_url, max_retries=0,
            timeout=REQUEST_TIMEOUT,
        )
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

    return _call


_call_openai = _openai_compatible("openai")
_call_groq = _openai_compatible("groq", base_url="https://api.groq.com/openai/v1")


def _call_anthropic(prompt, system, model, max_tokens, temperature, json_mode):
    try:
        import anthropic
    except ImportError as exc:
        raise ConfigError("pip install anthropic") from exc

    client = anthropic.Anthropic(api_key=_require_key("anthropic"), max_retries=0,
                                 timeout=REQUEST_TIMEOUT)
    # Три відмінності від решти провайдерів:
    # 1. max_tokens ОБОВ'ЯЗКОВИЙ (без нього 400);
    # 2. system — окремий параметр, а не елемент messages (інакше 400);
    # 3. temperature НЕ ІСНУЄ: сімплінг-параметри прибрані з API, у SDK 1.x їх
    #    немає в сигнатурі. Передати temperature=0 неможливо — приймаємо аргумент
    #    заради єдиного контракту і ігноруємо. Відтворюваність тут не гарантована.
    del temperature
    # Корпоративні (identity-linked) ключі вимагають ще й id воркспейсу —
    # інакше 400 «anthropic-workspace-id is required». Для звичайних ключів
    # змінна не потрібна: заголовок просто не додається.
    workspace = os.getenv("ANTHROPIC_WORKSPACE_ID", "").strip()
    headers = {"anthropic-workspace-id": workspace} if workspace else None
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system or anthropic.NOT_GIVEN,
        messages=[{"role": "user", "content": prompt}],
        extra_headers=headers,
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    return text, resp.usage.input_tokens, resp.usage.output_tokens, resp.stop_reason


_PROVIDERS = {
    "google": _call_google,
    "openai": _call_openai,
    "groq": _call_groq,
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
    temperature: float = 0.0,   # anthropic його не підтримує і мовчки ігнорує
    json_mode: bool = False,
) -> dict:
    """
    Один виклик моделі. Повертає:
    {
      "text": "...",            # відповідь моделі
      "in_tokens": 412,
      "out_tokens": 87,
      "stop_reason": "end_turn",
      "seconds": 1.8,        # час вдалого виклику
      "total_seconds": 1.8,  # разом із паузами ретраю
      "attempts": 1,
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
    (text, in_tokens, out_tokens, stop_reason), attempts, api_seconds = _with_retry(
        lambda: call(prompt, system, model, max_tokens, temperature, json_mode),
        label=f"{provider}/{model}",
    )
    total_seconds = time.perf_counter() - started

    return {
        "text": text,
        "in_tokens": in_tokens,
        "out_tokens": out_tokens,
        "stop_reason": stop_reason,
        # seconds — час самого вдалого виклику; total_seconds — разом із паузами
        # ретраю. Для «сер. час» у таблиці треба перше, інакше міряєш свій backoff.
        "seconds": round(api_seconds, 2),
        "total_seconds": round(total_seconds, 2),
        "attempts": attempts,
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

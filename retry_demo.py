"""
retry_demo.py — Крок 4: доказ, що retry працює. Скріншот консолі — у звіт.

    python retry_demo.py                 # офлайн: імітований 429, без мережі й ключів
    python retry_demo.py badkey google   # реальний виклик з навмисно невірним ключем
    python retry_demo.py fatal  google   # той самий невірний ключ, але політика за замовчуванням

Політика:
- 429 / 5xx / таймаути повторюємо: 1 → 2 → 4 → 8 c, максимум 5 спроб;
- 401 (невірний ключ) за замовчуванням НЕ повторюємо — повтор нічого не змінить;
  для скріншота в ДЗ вмикаємо LLM_RETRY_ALL_ERRORS=1 і бачимо всі 5 спроб.
Після останньої спроби функція падає з LLMError, а не повертає None.
"""

from __future__ import annotations

import os
import sys


def demo_simulated() -> int:
    """Офлайн-демо: провайдер, який завжди повертає 429."""
    import llm as llm_mod

    calls = {"n": 0}

    class FakeRateLimit(Exception):
        status_code = 429

        def __str__(self) -> str:
            return "429 Too Many Requests: rate limit exceeded (імітація)"

    def fake_provider(prompt, system, model, max_tokens, temperature, json_mode):
        calls["n"] += 1
        raise FakeRateLimit()

    llm_mod._PROVIDERS["fake429"] = fake_provider
    llm_mod.DEFAULT_MODELS["fake429"] = "gemini-2.5-flash"  # щоб знайшлася ціна
    llm_mod.ENV_KEYS["fake429"] = "GOOGLE_API_KEY"

    os.environ["LLM_RETRY_BASE_DELAY"] = os.getenv("LLM_RETRY_BASE_DELAY", "1")
    print("Сценарій: провайдер завжди віддає 429. "
          "Очікуємо 5 спроб і паузи 1→2→4→8 c.\n", flush=True)
    try:
        llm_mod.llm("тест", provider="fake429")
    except llm_mod.LLMError as exc:
        print(f"\nФІНАЛ: LLMError — {exc}")
        print(f"Викликів до провайдера: {calls['n']} (очікували {llm_mod.MAX_ATTEMPTS})")
        return 0
    print("НЕОЧІКУВАНО: помилки не було", file=sys.stderr)
    return 1


def demo_bad_key(provider: str, retry_everything: bool) -> int:
    """Реальний виклик із навмисно невірним ключем."""
    import llm as llm_mod

    env_key = llm_mod.ENV_KEYS[provider]
    # ключ навмисно невірний, але ASCII: не-ASCII символи впадуть ще в HTTP-заголовку,
    # і ти побачиш UnicodeEncodeError замість справжньої відповіді сервера
    os.environ[env_key] = "INVALID-KEY-0000"
    os.environ["LLM_RETRY_ALL_ERRORS"] = "1" if retry_everything else "0"

    policy = ("повторюємо всі помилки: буде 5 спроб і паузи 1→2→4→8 c"
              if retry_everything else
              "401/403 вважаємо невідновлюваними: падаємо після 1-ї спроби")
    print(f"Сценарій: {provider}, підставлений невірний ключ "
          f"{llm_mod.key_tail(provider)}", flush=True)
    print(f"LLM_RETRY_ALL_ERRORS={os.environ['LLM_RETRY_ALL_ERRORS']} → {policy}\n",
          flush=True)
    try:
        llm_mod.llm("тест", provider=provider, max_tokens=32)
    except llm_mod.LLMError as exc:
        print(f"\nФІНАЛ: LLMError — {exc}")
        return 0
    print("НЕОЧІКУВАНО: помилки не було", file=sys.stderr)
    return 1


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "simulate"
    target = sys.argv[2] if len(sys.argv) > 2 else "google"
    if mode == "simulate":
        raise SystemExit(demo_simulated())
    if mode == "badkey":
        raise SystemExit(demo_bad_key(target, retry_everything=True))
    if mode == "fatal":
        raise SystemExit(demo_bad_key(target, retry_everything=False))
    print(f"Невідомий режим {mode!r}: simulate | badkey | fatal", file=sys.stderr)
    raise SystemExit(2)

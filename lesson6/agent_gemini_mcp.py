"""Крок 3 ДЗ 6: хост, який віддає моделі Gemini весь MCP-сервер DeepWiki.

Запуск:  python agent_gemini_mcp.py
Ключ береться зі змінної середовища GEMINI_API_KEY (або GOOGLE_API_KEY).

Версії: fastmcp>=4 (команди list/call у CLI), google-genai<2
(у 2.x tools=[mcp_client.session] падає на config.model_copy(deep=True)).
"""

import asyncio

from google.genai import _mcp_utils

# fastmcp 4 кладе в схему "additionalProperties": false, а конвертер google-genai 1.x
# рекурсивно заходить у кожне значення й чекає там словник. Не словник — віддаємо як є.
_orig_filter = _mcp_utils._filter_to_supported_schema
_mcp_utils._filter_to_supported_schema = (
    lambda schema: _orig_filter(schema) if isinstance(schema, dict) else schema
)

from fastmcp import Client  # noqa: E402
from google import genai  # noqa: E402
from google.genai import errors, types  # noqa: E402

MODEL = "gemini-3.7-flash"  # gemini-2.5-flash новим ключам більше не видається (404)
QUESTION = (
    "Як у репозиторії python-telegram-bot/python-telegram-bot реалізовано "
    "обмеження частоти запитів (rate limiting): які класи за це відповідають "
    "і як їх підключити до застосунку? Відповідай українською."
)

mcp_client = Client("https://mcp.deepwiki.com/mcp")  # MCP-клієнт
gemini = genai.Client()  # ключ береться зі змінної GEMINI_API_KEY


async def ask_once():
    async with mcp_client:  # відкрили з'єднання із сервером
        config = types.GenerateContentConfig(
            temperature=0,
            tools=[mcp_client.session],  # передали моделі весь MCP-сервер
        )
        return await gemini.aio.models.generate_content(
            model=MODEL, contents=QUESTION, config=config
        )


async def main():
    # 429/503 на безкоштовному тарифі — звична справа. Пауза живе поза "async with"
    # і робиться через await asyncio.sleep(): блокуючий time.sleep() усередині сесії
    # зупиняє event loop, з'єднання з MCP-сервером рветься і замість повтору
    # прилітає CancelledError.
    for attempt in range(4):
        try:
            response = await ask_once()
            break
        except (errors.ClientError, errors.ServerError) as e:
            if e.code in (429, 503) and attempt < 3:
                pause = 20 * (attempt + 1)
                print(f"{e.code}: чекаю {pause} с і повторюю")
                await asyncio.sleep(pause)
                continue
            raise
        except Exception as e:  # мережа могла впасти і на підключенні до MCP-сервера
            if attempt < 3:
                pause = 20 * (attempt + 1)
                print(f"{type(e).__name__}: чекаю {pause} с і повторюю")
                await asyncio.sleep(pause)
                continue
            raise

    print(response.text)

    print("\n--- Що відбулося всередині ---")
    history = response.automatic_function_calling_history or []
    for content in history:
        for part in content.parts or []:
            if part.function_call:
                print("інструмент:", part.function_call.name)
                print("аргументи:", dict(part.function_call.args))


asyncio.run(main())  # у Colab/Jupyter: await main()

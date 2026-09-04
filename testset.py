"""
testset.py — промпт-переможець v2 із заняття 2 (шаблон на 6 блоків)
плюс той самий тестсет із 5 входів і автоматична перевірка відповіді.

Задача: розібрати звернення клієнта в підтримку на 6 полів JSON.
Якщо у твоєму ДЗ до заняття 2 була інша задача — заміни SYSTEM/TESTSET,
решта коду (llm.py, run_testset.py) не змінюється.
"""

CATEGORIES = ["оплата", "доставка", "технічна", "повернення", "інше"]
URGENCIES = ["низька", "середня", "висока"]

# --- промпт v2: роль + задача + шаблон на 6 блоків + правила + приклад ---
SYSTEM = f"""Ти — оператор першої лінії підтримки інтернет-магазину.
Твоя задача: розібрати звернення клієнта на структуровані поля.

Поверни РІВНО один JSON-об'єкт із шістьма ключами, без markdown і без пояснень:
{{
  "category":     один із {CATEGORIES},
  "urgency":      один із {URGENCIES},
  "summary":      суть звернення одним реченням, до 200 символів,
  "client_intent": чого клієнт хоче отримати в результаті, одне речення,
  "next_action":  конкретна наступна дія оператора, одне речення,
  "missing_info": масив рядків — яких даних бракує, щоб закрити звернення;
                  порожній масив, якщо все є
}}

Правила:
- Тільки значення зі списків для category і urgency, дослівно.
- Нічого не вигадуй: якщо даних немає — вони йдуть у missing_info.
- Якщо звернення взагалі не про магазин — category="інше", urgency="низька".
- Відповідь українською.

Приклад входу: "Замовлення 123 йде вже три тижні, де воно?"
Приклад виходу:
{{"category": "доставка", "urgency": "середня",
  "summary": "Замовлення 123 не доставлено протягом трьох тижнів.",
  "client_intent": "Дізнатися статус і строк доставки замовлення 123.",
  "next_action": "Перевірити трек-номер замовлення 123 і повідомити клієнту дату.",
  "missing_info": []}}"""

# --- 5 входів; expected_category — золота мітка для підрахунку «правильних із 5» ---
TESTSET = [
    {
        "id": "t1_оплата",
        "expected_category": "оплата",
        "input": "Списали двічі за одне замовлення №4417, картка Visa ****1234. "
                 "Поверніть зайві 1250 грн.",
    },
    {
        "id": "t2_доставка",
        "expected_category": "доставка",
        "input": "Доброго дня! Коли приїде моє замовлення? Оформив у понеділок, "
                 "трек не приходив.",
    },
    {
        "id": "t3_технічна",
        "expected_category": "технічна",
        "input": "Не можу залогінитись у застосунку: після введення пароля крутиться "
                 "колесо і викидає на головну. Android 14, версія 3.2.1. "
                 "Завтра мені треба оформити замовлення для клієнта!",
    },
    {
        "id": "t4_коротке",
        "expected_category": "повернення",
        "input": "хочу повернути товар",
    },
    {
        "id": "t5_нерелевантне",
        "expected_category": "інше",
        "input": "Вітаю! Пропоную вам послуги SEO-просування, перший місяць безкоштовно. "
                 "Зателефонуйте нам.",
    },
]

REQUIRED_KEYS = {
    "category", "urgency", "summary", "client_intent", "next_action", "missing_info",
}


def validate(raw_text: str, expected_category: str) -> tuple[bool, list[str]]:
    """
    Перевіряє відповідь автоматично. Повертає (зараховано, список проблем).
    Зараховано = валідний JSON + усі 6 блоків + коректні enum + правильна категорія.
    """
    import json

    problems: list[str] = []
    text = raw_text.strip()
    # деякі моделі попри інструкцію обгортають JSON у ```json ... ```
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):] if "{" in text else text
        problems.append("відповідь обгорнута у markdown-фенс")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, [f"не парситься як JSON: {exc}"]

    if not isinstance(data, dict):
        return False, ["JSON не є об'єктом"]

    missing = REQUIRED_KEYS - data.keys()
    extra = data.keys() - REQUIRED_KEYS
    if missing:
        problems.append(f"немає блоків: {sorted(missing)}")
    if extra:
        problems.append(f"зайві блоки: {sorted(extra)}")

    if data.get("category") not in CATEGORIES:
        problems.append(f"category={data.get('category')!r} поза списком")
    elif data["category"] != expected_category:
        problems.append(f"category={data['category']!r}, очікували {expected_category!r}")
    if data.get("urgency") not in URGENCIES:
        problems.append(f"urgency={data.get('urgency')!r} поза списком")
    for key in ("summary", "client_intent", "next_action"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{key}: порожньо або не рядок")
    if len(str(data.get("summary", ""))) > 200:
        problems.append("summary довший за 200 символів")
    if not isinstance(data.get("missing_info"), list):
        problems.append("missing_info не є масивом")

    return (not problems), problems

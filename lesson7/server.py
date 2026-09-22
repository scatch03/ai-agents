"""ДЗ 7: MCP-сервер обліку витрат.

Чотири інструменти (додати / підсумок за категорією / показати останні /
видалити) і два ресурси «тільки для читання». Транспорт — stdio, тому в
stdout не можна писати нічого, крім протоколу: усі повідомлення йдуть
через logging у stderr.

Запуск:  python server.py          (як MCP-сервер по stdio)
         mcp dev server.py         (як сервер + MCP Inspector у браузері)

Дані лежать у JSON-файлі поруч зі скриптом; шлях можна перевизначити
змінною середовища EXPENSES_FILE.
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from mcp.server.mcpserver import MCPServer

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(message)s")
log = logging.getLogger("expenses")

mcp = MCPServer("expense-tracker", version="0.1.0")

DATA_FILE = Path(os.environ.get("EXPENSES_FILE") or Path(__file__).with_name("expenses.json"))
CURRENCY = "грн"


# ── сховище ─────────────────────────────────────────────────────────────────
# Файла може не бути (чистий клон) або він може бути зіпсований руками.
# В обох випадках працюємо з порожнім списком, а не падаємо.
def load() -> list[dict]:
    """Читає витрати з JSON-файлу. Немає файлу або він побитий — порожній список."""
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, OSError) as e:
        log.warning("не читається %s (%s), починаю з порожнього списку", DATA_FILE, e)
        return []
    return data if isinstance(data, list) else []


def save(expenses: list[dict]) -> None:
    """Записує витрати у JSON-файл."""
    DATA_FILE.write_text(
        json.dumps(expenses, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def next_id(expenses: list[dict]) -> int:
    """Наступний вільний номер: максимальний наявний + 1, щоб номери не повторювались."""
    return max((e["id"] for e in expenses), default=0) + 1


def plural(n: int, one: str, few: str, many: str) -> str:
    """Українська форма слова після числа: 1 витрата, 2 витрати, 5 витрат."""
    if 11 <= n % 100 <= 14:
        return many
    last = n % 10
    if last == 1:
        return one
    if 2 <= last <= 4:
        return few
    return many


def line(e: dict) -> str:
    """Один рядок витрати у вигляді, зрозумілому людині."""
    note = f" — {e['note']}" if e.get("note") else ""
    return f"#{e['id']} {e['date']}: {e['amount']:.2f} {CURRENCY}, {e['category']}{note}"


def known_categories(expenses: list[dict]) -> list[str]:
    """Категорії, які вже зустрічались, без повторів і за алфавітом."""
    return sorted({e["category"] for e in expenses})


# ── інструменти ─────────────────────────────────────────────────────────────
@mcp.tool()
def add_expense(amount: float, category: str, note: str = "") -> str:
    """Записує одну витрату: суму, категорію і необов'язковий коментар.

    ЩО РОБИТЬ: додає витрату до списку і зберігає її на диск.
    КОЛИ ВИКЛИКАТИ: коли користувач каже, що на щось витратив гроші
    («купив каву за 60», «заправився на 1200», «запиши 300 гривень на ліки»).
    Категорію візьми з контексту (їжа, транспорт, здоров'я, розваги тощо).
    ЩО ПОВЕРНЕТЬСЯ, ЯКЩО ПІДЕ НЕ ЗА ПЛАНОМ: якщо сума нульова або від'ємна,
    або категорія порожня — повернеться текст із поясненням, і нічого не
    запишеться. Інакше — підтвердження з номером витрати і сумою за цю категорію.
    """
    if amount <= 0:
        return (
            f"Не записав: сума має бути більшою за нуль, а прийшло {amount:.2f}. "
            "Уточни в користувача, скільки саме він витратив."
        )
    category = category.strip()
    if not category:
        return (
            "Не записав: не вказана категорія витрати. "
            "Приклади категорій: їжа, транспорт, житло, здоров'я, розваги."
        )

    expenses = load()
    expense = {
        "id": next_id(expenses),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "amount": round(float(amount), 2),
        "category": category,
        "note": note.strip(),
    }
    expenses.append(expense)
    save(expenses)
    log.info("додано витрату #%s на %.2f (%s)", expense["id"], expense["amount"], category)

    same = sum(e["amount"] for e in expenses if e["category"].casefold() == category.casefold())
    return (
        f"Записав витрату #{expense['id']}: {expense['amount']:.2f} {CURRENCY}, "
        f"категорія «{category}». Разом у цій категорії: {same:.2f} {CURRENCY}."
    )


@mcp.tool()
def category_summary(category: str) -> str:
    """Рахує підсумок витрат за однією категорією.

    ЩО РОБИТЬ: повертає кількість витрат, загальну і середню суму за категорією.
    КОЛИ ВИКЛИКАТИ: коли питають, скільки пішло на щось конкретне
    («скільки я витратив на їжу», «багато вийшло на транспорт?»).
    ЩО ПОВЕРНЕТЬСЯ, ЯКЩО ПІДЕ НЕ ЗА ПЛАНОМ: якщо такої категорії ще немає,
    повернеться текст зі списком категорій, які вже є, — запропонуй їх користувачу.
    """
    category = category.strip()
    expenses = load()
    if not expenses:
        return "Витрат ще немає — спочатку треба щось записати через add_expense."

    picked = [e for e in expenses if e["category"].casefold() == category.casefold()]
    if not picked:
        return (
            f"Категорії «{category}» серед витрат немає. "
            f"Наявні категорії: {', '.join(known_categories(expenses))}."
        )

    total = sum(e["amount"] for e in picked)
    return (
        f"Категорія «{picked[0]['category']}»: {len(picked)} "
        f"{plural(len(picked), 'витрата', 'витрати', 'витрат')} на {total:.2f} {CURRENCY}, "
        f"у середньому {total / len(picked):.2f} {CURRENCY}. "
        f"Найбільша — {max(e['amount'] for e in picked):.2f} {CURRENCY}."
    )


@mcp.tool()
def list_expenses(limit: int = 10) -> str:
    """Показує останні записані витрати.

    ЩО РОБИТЬ: повертає до `limit` останніх витрат, кожну окремим рядком
    із номером, датою, сумою і категорією, і загальну суму за весь час.
    КОЛИ ВИКЛИКАТИ: коли просять показати витрати, згадати останні покупки
    або коли треба дізнатись номер витрати перед видаленням.
    ЩО ПОВЕРНЕТЬСЯ, ЯКЩО ПІДЕ НЕ ЗА ПЛАНОМ: якщо витрат ще немає — фраза
    «Витрат ще немає»; якщо limit менший за 1 — буде показана одна витрата.
    """
    expenses = load()
    if not expenses:
        return "Витрат ще немає — список порожній."

    limit = max(1, int(limit))
    tail = expenses[-limit:]
    total = sum(e["amount"] for e in expenses)
    header = (
        f"Показую {len(tail)} {plural(len(tail), 'витрату', 'витрати', 'витрат')} "
        f"з {len(expenses)}, від найновішої:"
    )
    return "\n".join([header, *(line(e) for e in reversed(tail))]) + (
        f"\nЗагалом за весь час: {total:.2f} {CURRENCY}."
    )


@mcp.tool()
def delete_expense(expense_id: int) -> str:
    """Видаляє одну витрату за її номером.

    ЩО РОБИТЬ: прибирає зі списку витрату із заданим номером (номер видно
    у відповіді add_expense і в list_expenses).
    КОЛИ ВИКЛИКАТИ: коли користувач каже, що запис помилковий або дубльований
    («видали останню витрату», «прибери запис номер 3»).
    ЩО ПОВЕРНЕТЬСЯ, ЯКЩО ПІДЕ НЕ ЗА ПЛАНОМ: якщо витрати з таким номером немає,
    повернеться текст із переліком наявних номерів, і нічого не видалиться.
    """
    expenses = load()
    if not expenses:
        return "Видаляти нічого: витрат ще немає."

    found = next((e for e in expenses if e["id"] == expense_id), None)
    if found is None:
        numbers = ", ".join(f"#{e['id']}" for e in expenses)
        return f"Витрати з номером {expense_id} не існує. Наявні номери: {numbers}."

    expenses.remove(found)
    save(expenses)
    log.info("видалено витрату #%s", expense_id)
    left = f"{len(expenses)} {plural(len(expenses), 'запис', 'записи', 'записів')}"
    return f"Видалив витрату {line(found)}. Залишилось {left}."


# ── ресурси (тільки для читання) ────────────────────────────────────────────
@mcp.resource("expenses://all")
def all_expenses() -> str:
    """Повний список витрат одним текстом."""
    expenses = load()
    if not expenses:
        return "Витрат ще немає."
    total = sum(e["amount"] for e in expenses)
    return "\n".join(
        [
            f"Усі витрати: {len(expenses)} "
            f"{plural(len(expenses), 'запис', 'записи', 'записів')} на {total:.2f} {CURRENCY}"
        ]
        + [line(e) for e in expenses]
    )


@mcp.resource("expenses://categories")
def categories() -> str:
    """Категорії з підсумковою сумою за кожною, від більшої до меншої."""
    expenses = load()
    if not expenses:
        return "Категорій ще немає — жодної витрати не записано."
    totals: dict[str, float] = {}
    for e in expenses:
        totals[e["category"]] = totals.get(e["category"], 0.0) + e["amount"]
    rows = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    return "\n".join(f"{name}: {amount:.2f} {CURRENCY}" for name, amount in rows)


if __name__ == "__main__":
    mcp.run(transport="stdio")

"""
run_testset.py — Крок 5 і 6: 5 входів × N провайдерів через llm(),
підрахунок токенів/вартості/часу, таблиця у results.md.

    python run_testset.py                # усі провайдери, у яких є ключ
    python run_testset.py google openai  # конкретні
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import date

from llm import (
    DEFAULT_MODELS, ENV_KEYS, PRICES, PRICING_SOURCES,
    LLMError, key_tail, llm,
)
from testset import SYSTEM, TESTSET, validate

SLEEP_BETWEEN = float(os.getenv("LLM_SLEEP_BETWEEN", "4"))  # проти 429 на free tier
# Шість коротких блоків JSON — це ~150 токенів, але моделі з міркуваннями
# (gpt-oss на Groq) пишуть роздуми в ті самі вихідні токени: на 500 відповідь
# обривало посеред JSON і Groq повертав 400 json_validate_failed.
MAX_TOKENS = 1200
OUT_PREFIX = "results"  # mock_run.py підміняє на "results.mock", щоб не затерти здачу


def available_providers() -> list[str]:
    return [p for p in DEFAULT_MODELS if os.environ.get(ENV_KEYS[p], "").strip()]


def run_one(provider: str, case: dict) -> dict:
    row = {"provider": provider, "model": DEFAULT_MODELS[provider], "case": case["id"]}
    try:
        r = llm(
            case["input"],
            system=SYSTEM,
            provider=provider,
            max_tokens=MAX_TOKENS,
            json_mode=True,
        )
    except LLMError as exc:
        row.update(ok=False, error=str(exc), in_tokens=0, out_tokens=0,
                   cost_usd=0.0, seconds=0.0, total_seconds=0.0, attempts=0,
                   stop_reason="error", problems=[str(exc)])
        return row

    ok, problems = validate(r["text"], case["expected_category"])
    if r["stop_reason"] in ("max_tokens", "length", "MAX_TOKENS"):
        problems.append(f"обрізано по max_tokens ({MAX_TOKENS}) — це не провина промпту")
    row.update(
        ok=ok, error=None, text=r["text"],
        in_tokens=r["in_tokens"], out_tokens=r["out_tokens"],
        cost_usd=r["cost_usd"], seconds=r["seconds"],
        total_seconds=r["total_seconds"], attempts=r["attempts"],
        stop_reason=r["stop_reason"], problems=problems,
    )
    return row


def summarize(rows: list[dict]) -> list[dict]:
    out = []
    for provider in dict.fromkeys(r["provider"] for r in rows):
        group = [r for r in rows if r["provider"] == provider]
        out.append({
            "provider": provider,
            "model": group[0]["model"],
            "correct": sum(1 for r in group if r["ok"]),
            "total": len(group),
            "in_tokens": sum(r["in_tokens"] for r in group),
            "out_tokens": sum(r["out_tokens"] for r in group),
            "cost_usd": sum(r["cost_usd"] for r in group),
            "avg_seconds": sum(r["seconds"] for r in group) / len(group),
            "retried": sum(1 for r in group if r["attempts"] > 1),
        })
    return out


CONCLUSION_FILE = "conclusion.md"


def draft_conclusion(summary: list[dict]) -> str:
    """
    Висновок, написаний руками, важливіший за згенерований: якщо поруч лежить
    conclusion.md — беремо його, інакше генеруємо чернетку з трьох критеріїв.
    Інакше кожен наступний прогін затирав би текст, який ти щойно написав.
    """
    if os.path.exists(CONCLUSION_FILE):
        with open(CONCLUSION_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    return _draft_conclusion(summary)


def _draft_conclusion(summary: list[dict]) -> str:
    if len(summary) < 2:
        return "_Додай другого провайдера, щоб було що порівнювати._"

    best_quality = max(s["correct"] for s in summary)
    top = [s for s in summary if s["correct"] == best_quality]
    pick = min(top, key=lambda s: s["cost_usd"])          # серед найкращих за якістю — найдешевший
    cheapest = min(summary, key=lambda s: s["cost_usd"])
    fastest = min(summary, key=lambda s: s["avg_seconds"])

    lines = [
        "Чернетка — звір із власними даними і залиш ОДИН критерій:", "",
        f"- якість: " + ", ".join(
            f"{s['provider']} {s['correct']}/{s['total']}" for s in summary) + ";",
        f"- ціна за 5 запитів: " + ", ".join(
            f"{s['provider']} ${s['cost_usd']:.5f}" for s in summary) + ";",
        f"- сер. час: " + ", ".join(
            f"{s['provider']} {s['avg_seconds']:.1f} c" for s in summary) + ".", "",
    ]
    if len(top) > 1:
        lines.append(
            f"Якість однакова ({best_quality}/{pick['total']} в обох), тож критерій — "
            f"**ціна**: обираю **{pick['provider']}** ({pick['model']}), "
            f"${pick['cost_usd'] / pick['total']:.6f} за запит проти "
            f"${max(s['cost_usd'] for s in summary) / pick['total']:.6f}. "
            f"Швидкість тут не критерій: різниця {fastest['avg_seconds']:.1f} c проти "
            f"{max(s['avg_seconds'] for s in summary):.1f} c для фонової обробки не важлива."
        )
    else:
        lines.append(
            f"Критерій — **якість**: обираю **{pick['provider']}** ({pick['model']}), "
            f"{pick['correct']}/{pick['total']} проти "
            f"{min(s['correct'] for s in summary)}/{pick['total']} у конкурента. "
            f"{cheapest['provider']} дешевший (${cheapest['cost_usd']:.5f} проти "
            f"${pick['cost_usd']:.5f}), але невалідний JSON доводиться перезапускати — "
            f"економія з'їдається ретраями. Якби якість зрівнялася, критерієм стала б ціна."
        )
    return "\n".join(lines)


def write_results(rows: list[dict], summary: list[dict]) -> None:
    lines = [
        "# Результати прогону тестсету",
        "",
        f"Дата прогону: {date.today().isoformat()}  ",
        f"Тестсет: 5 входів × {len(summary)} провайдер(и) = {len(rows)} викликів  ",
        f"Промпт: v2 із заняття 2 (шаблон на 6 блоків), `temperature=0`, "
        f"`max_tokens={MAX_TOKENS}`, JSON-режим увімкнено",
        "",
        "«Сер. час» — тривалість вдалого виклику без пауз ретраю: інакше міряєш "
        "власний backoff, а не провайдера. Скільки спроб знадобилось — окрема колонка.",
        "",
        "## Таблиця",
        "",
        "| провайдер | модель | правильних із 5 | in tok | out tok | вартість $ | сер. час, с |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in summary:
        lines.append(
            f"| {s['provider']} | {s['model']} | {s['correct']} | {s['in_tokens']} | "
            f"{s['out_tokens']} | {s['cost_usd']:.5f} | {s['avg_seconds']:.1f} |"
        )

    lines += ["", "## Ціни", "",
              "`cost = (in_tokens * price_in + out_tokens * price_out) / 1_000_000`", "",
              "| модель | price_in $/1M | price_out $/1M | джерело |", "|---|---|---|---|"]
    for s in summary:
        pin, pout = PRICES[s["model"]]
        lines.append(f"| {s['model']} | {pin} | {pout} | {PRICING_SOURCES[s['provider']]} |")

    lines += ["", "## Деталі по викликах", "",
              "| провайдер | кейс | зараховано | stop_reason | in | out | $ | с | спроб | що не так |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        problems = "; ".join(r["problems"])[:160] or "—"
        lines.append(
            f"| {r['provider']} | {r['case']} | {'✅' if r['ok'] else '❌'} | "
            f"{r['stop_reason']} | {r['in_tokens']} | {r['out_tokens']} | "
            f"{r['cost_usd']:.6f} | {r['seconds']:.1f} | {r['attempts']} | {problems} |"
        )

    lines += ["", "## Висновок", "", draft_conclusion(summary), ""]

    with open(f"{OUT_PREFIX}.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    with open(f"{OUT_PREFIX}.json", "w", encoding="utf-8") as fh:
        json.dump({"rows": rows, "summary": summary}, fh, ensure_ascii=False, indent=2)


def main() -> int:
    providers = sys.argv[1:] or available_providers()
    if not providers:
        print("Немає жодного ключа в .env — заповни його і перезапусти.", file=sys.stderr)
        return 1
    if len(providers) < 2:
        print(f"УВАГА: провайдер лише один ({providers[0]}) — ДЗ вимагає двох.",
              file=sys.stderr)

    print("Провайдери:", ", ".join(f"{p} (ключ {key_tail(p)})" for p in providers))
    rows: list[dict] = []
    total = len(providers) * len(TESTSET)
    n = 0
    for provider in providers:
        for case in TESTSET:
            n += 1
            print(f"[{n}/{total}] {provider} ← {case['id']} ... ", end="", flush=True)
            row = run_one(provider, case)
            rows.append(row)
            mark = "OK" if row["ok"] else "FAIL"
            retries = "" if row["attempts"] <= 1 else f", спроб: {row['attempts']}"
            print(f"{mark}  {row['in_tokens']}→{row['out_tokens']} tok, "
                  f"{row['seconds']:.1f} c, ${row['cost_usd']:.6f}{retries}")
            if row["problems"]:
                print("      ↳", "; ".join(row["problems"])[:200])
            if n < total:
                time.sleep(SLEEP_BETWEEN)  # пауза, щоб не впертися в 429

    summary = summarize(rows)
    write_results(rows, summary)
    print(f"\nЗаписано {OUT_PREFIX}.md і {OUT_PREFIX}.json")
    for s in summary:
        print(f"  {s['provider']:<10} {s['correct']}/{s['total']} правильних, "
              f"${s['cost_usd']:.5f}, сер. {s['avg_seconds']:.1f} c")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

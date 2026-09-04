"""
mock_run.py — прогін усього конвеєра БЕЗ ключів і без мережі.
Перевіряє, що run_testset.py, валідатор і таблиця працюють, поки ключі ще не приїхали.
Цифри тут вигадані і пишуться в results.mock.md — справжній results.md не чіпаємо.

    python mock_run.py
"""
import json
import os
import random
import sys
import llm as llm_mod
import run_testset as rt

random.seed(7)
GOOD = {"category": None, "urgency": "середня", "summary": "Стисла суть звернення.",
        "client_intent": "Що хоче клієнт.", "next_action": "Що робить оператор.",
        "missing_info": []}

def fake_llm(prompt, system="", provider="google", *, model=None, max_tokens=800,
             temperature=0.0, json_mode=False):
    model = model or llm_mod.DEFAULT_MODELS[provider]
    case = next(c for c in __import__("testset").TESTSET if c["input"] == prompt)
    body = dict(GOOD, category=case["expected_category"])
    # openai навмисно ламає один кейс — щоб перевірити колонку «правильних із 5»
    if provider == "openai" and case["id"] == "t4_коротке":
        body["category"] = "інше"
    text = json.dumps(body, ensure_ascii=False)
    in_tok, out_tok = random.randint(380, 460), random.randint(70, 110)
    return {"text": text, "in_tokens": in_tok, "out_tokens": out_tok,
            "stop_reason": "end_turn" if provider != "openai" else "stop",
            "seconds": round(random.uniform(1.2, 2.6), 2),
            "cost_usd": llm_mod.cost_usd(model, in_tok, out_tok),
            "provider": provider, "model": model}

if __name__ == "__main__":
    rt.llm = fake_llm            # підміняємо реальний виклик
    rt.SLEEP_BETWEEN = 0         # паузи проти 429 у моці не потрібні
    rt.OUT_PREFIX = "results.mock"  # щоб не затерти справжній results.md
    os.environ.setdefault("GOOGLE_API_KEY", "mock")
    os.environ.setdefault("OPENAI_API_KEY", "mock")
    sys.argv = ["run_testset.py", "google", "openai"]
    print("МОК-ПРОГІН: мережі немає, цифри вигадані.\n")
    raise SystemExit(rt.main())

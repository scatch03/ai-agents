"""
Тести конвеєра: digest_run і callback_run.

Мережі немає взагалі — IMAP, модель, Telegram і Google підмінені.
Перевіряється не «чи гарний дайджест», а інваріанти, ціна помилки в яких
висока: курсори, ідемпотентність, поведінка при збоях і лімітах.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailagent.config import Config, Mailbox                       # noqa: E402
from mailagent.errors import ToolError                             # noqa: E402
from mailagent.run import Limits, callback_run, digest_run         # noqa: E402
from mailagent.state import State                                  # noqa: E402
from mailagent.tools import mail                                   # noqa: E402
from tests.fakes import FakeIMAP                                   # noqa: E402

DAY = date(2026, 9, 3)
WORK = Mailbox(id="work_gmail", host="h", user="u")
NEWS = Mailbox(id="news_gmail", host="h", user="u")


def config(*boxes: Mailbox) -> Config:
    boxes = boxes or (WORK,)
    return Config(mailboxes=boxes, _by_id={b.id: b for b in boxes})


def fresh_state() -> State:
    return State(tempfile.mktemp(suffix=".json"))


def imap_with(uids, uidvalidity=42) -> FakeIMAP:
    headers = {u: f"From: someone@partner.com\r\nSubject: лист {u}\r\n"
                  f"Authentication-Results: dkim=pass\r\n\r\n" for u in uids}
    body = ("From: someone@partner.com\r\nSubject: s\r\n\r\n"
            "текст листа\r\n").encode()
    bodies = {u: body for u in uids}
    return FakeIMAP(uidvalidity=uidvalidity, uids=uids, headers=headers, bodies=bodies)


class FailingIMAP(FakeIMAP):
    def select(self, folder, readonly=False):
        raise ToolError("IMAP authentication failed — app password revoked", status=401)


def model(**per_uid):
    """Модель, яка кожному листу дає задану рубрику (за замовчуванням work)."""
    def _fake(prompt, system="", provider="groq", **kwargs):
        if "сортуєш" in system:
            payload = {"needs_body": []}
        else:
            uids = [int(u) for u in __import__("re").findall(r'uid="(\d+)"', prompt)]
            payload = {"letters": [
                {"uid": u, "category": per_uid.get(u, "work"),
                 "summary": f"переказ {u}", "needs_action": False,
                 "deadline": None, "event": None, "threat": {"kind": "none"}}
                for u in uids]}
        return {"text": json.dumps(payload, ensure_ascii=False), "in_tokens": 100,
                "out_tokens": 50, "cost_usd": 0.0005, "seconds": 0.3}
    return _fake


class Sender:
    """Фейковий send_message: рахує виклики, за потреби падає."""

    def __init__(self, *, fail: Exception | None = None):
        self.calls: list[dict] = []
        self.fail = fail

    def __call__(self, text, *, state, idempotency_key, entities=None,
                 reply_markup=None, **kwargs):
        if self.fail:
            raise self.fail
        self.calls.append({"text": text, "key": idempotency_key,
                           "markup": reply_markup})
        state.mark_sent(idempotency_key, 8871)
        state.save()
        return {"sent": True, "message_id": 8871, "already_sent": False}


def run(state, imap, *, boxes=(WORK,), sender=None, llm=None, limits=None,
        dry_run=False):
    sender = sender or Sender()
    conf = config(*boxes)
    conns = mail.Connections(conf, opener=lambda box: imap)
    result = digest_run(config=conf, state=state, conns=conns,
                        llm_fn=llm or model(), sender=sender, day=DAY,
                        limits=limits, dry_run=dry_run)
    return result, sender


class TestCursorDiscipline(unittest.TestCase):
    def test_cursor_moves_only_after_successful_send(self):
        state = fresh_state()
        result, _ = run(state, imap_with([101, 102, 103]))
        self.assertEqual(state.cursor("work_gmail").uid, 103)
        self.assertEqual(result["cursors_moved"], ["work_gmail"])

    def test_cursor_frozen_when_send_fails(self):
        """
        Найдорожча помилка цього агента: зсунути курсор і не надіслати.
        Листи вважаються обробленими, а людина їх ніколи не побачить.
        """
        state = fresh_state()
        sender = Sender(fail=ToolError("telegram down", status=503))
        with self.assertRaises(ToolError):
            run(state, imap_with([101, 102]), sender=sender)
        self.assertEqual(state.cursor("work_gmail").uid, 0)

    def test_failed_mailbox_keeps_its_cursor(self):
        state = fresh_state()
        state.set_cursor("news_gmail", 500, 42)
        state.save()
        conf = config(WORK, NEWS)
        good, bad = imap_with([101]), FailingIMAP()
        conns = mail.Connections(conf, opener=lambda box: good if box.id == "work_gmail" else bad)
        sender = Sender()
        result = digest_run(config=conf, state=state, conns=conns, llm_fn=model(),
                            sender=sender, day=DAY)
        self.assertEqual(state.cursor("work_gmail").uid, 101)
        self.assertEqual(state.cursor("news_gmail").uid, 500)
        self.assertEqual(result["mailboxes_failed"], ["news_gmail"])

    def test_broken_mailbox_is_named_in_digest(self):
        conf = config(WORK, NEWS)
        good, bad = imap_with([101]), FailingIMAP()
        conns = mail.Connections(conf, opener=lambda box: good if box.id == "work_gmail" else bad)
        result = digest_run(config=conf, state=fresh_state(), conns=conns,
                            llm_fn=model(), sender=Sender(), day=DAY)
        self.assertIn("news_gmail недоступна", result["text"])


class TestFirstRun(unittest.TestCase):
    def test_archive_is_skipped_and_never_comes_back(self):
        """
        Перший запуск на скриньці з тисячами листів: у дайджест іде вікно
        за добу, а курсор стає одразу за ним — архів не приїде й завтра.
        """
        state = fresh_state()
        imap = imap_with(list(range(1, 5001)))
        imap.recent_uids = [4999, 5000]
        result, _ = run(state, imap)
        self.assertEqual(result["letters"], 2)
        self.assertEqual(state.cursor("work_gmail").uid, 5000)

        # Другий запуск: пошук уже за UID, і старе не підтягується.
        imap2 = imap_with(list(range(1, 5001)))
        conf = config(WORK)
        conns = mail.Connections(conf, opener=lambda box: imap2)
        second = digest_run(config=conf, state=state, conns=conns, llm_fn=model(),
                            sender=Sender(), day=date(2026, 9, 4))
        self.assertEqual(second["letters"], 0)


class TestIdempotency(unittest.TestCase):
    def test_second_run_same_day_sends_nothing(self):
        state = fresh_state()
        run(state, imap_with([101]))
        sender = Sender()
        conf = config(WORK)
        conns = mail.Connections(conf, opener=lambda box: imap_with([102]))
        # Другий запуск того самого дня: справжній send_message побачив би
        # ключ і повернув already_sent. Емулюємо це.
        def already(text, *, state, idempotency_key, **kwargs):
            seen = state.sent(idempotency_key)
            if seen:
                return {"sent": False, "message_id": seen["message_id"],
                        "already_sent": True}
            return Sender()(text, state=state, idempotency_key=idempotency_key)
        result = digest_run(config=conf, state=state, conns=conns, llm_fn=model(),
                            sender=already, day=DAY)
        self.assertTrue(result["sent"]["already_sent"])


class TestLimits(unittest.TestCase):
    def test_iteration_limit_stops_and_freezes_cursors(self):
        state = fresh_state()
        result, _ = run(state, imap_with([101, 102]),
                        limits=Limits(max_iterations=1))
        self.assertIn("ліміт ітерацій", result["stopped_by"])
        self.assertIn("неповний дайджест", result["text"])
        self.assertEqual(state.cursor("work_gmail").uid, 0,
                         "недочитане має піти в наступний запуск")

    def test_cost_limit_respected(self):
        state = fresh_state()
        result, _ = run(state, imap_with([101]), limits=Limits(max_cost_usd=0.0001))
        self.assertIn("бюджет", result["stopped_by"])


class TestDryRun(unittest.TestCase):
    def test_dry_run_sends_nothing_and_moves_nothing(self):
        state = fresh_state()
        result, sender = run(state, imap_with([101, 102]), dry_run=True)
        self.assertIsNone(result["sent"])
        self.assertEqual(sender.calls, [])
        self.assertEqual(state.cursor("work_gmail").uid, 0)
        self.assertIn("Дайджест", result["text"])


class TestEventDrafts(unittest.TestCase):
    def model_with_event(self):
        start = datetime.now(timezone.utc) + timedelta(days=1)

        def _fake(prompt, system="", provider="groq", **kwargs):
            if "сортуєш" in system:
                payload = {"needs_body": []}
            else:
                payload = {"letters": [{
                    "uid": 101, "category": "work", "summary": "зустріч",
                    "needs_action": False, "deadline": None,
                    "threat": {"kind": "none"},
                    "event": {"title": "зустріч з підрядником",
                              "start": start.isoformat(),
                              "end": (start + timedelta(hours=1)).isoformat(),
                              "confidence": 0.9}}]}
            return {"text": json.dumps(payload), "in_tokens": 10, "out_tokens": 5,
                    "cost_usd": 0.0, "seconds": 0.1}
        return _fake

    def test_draft_saved_and_button_built(self):
        state = fresh_state()
        result, sender = run(state, imap_with([101]), llm=self.model_with_event())
        markup = sender.calls[0]["markup"]
        self.assertIsNotNone(markup)
        data = markup["inline_keyboard"][0][0]["callback_data"]
        self.assertTrue(data.startswith("add:ev_"))
        event_id = data.removeprefix("add:")
        self.assertEqual(state.pending_event(event_id)["status"], "pending")


class TestCallback(unittest.TestCase):
    def setUp(self):
        self.state = fresh_state()
        start = datetime.now(timezone.utc) + timedelta(days=1)
        self.event_id = self.state.put_pending_event(
            title="зустріч", start=start.isoformat(),
            end=(start + timedelta(hours=1)).isoformat(), source="work/101")
        self.state.mark_sent("digest-2026-09-03", 8871)
        self.state.save()
        self.answered: list[str] = []
        self.order: list[str] = []

    def update(self, data="add:", from_id=777):
        return {"callback_query": {"id": "cb1", "from": {"id": from_id},
                                   "data": data + self.event_id if data.endswith(":")
                                   else data}}

    def answer(self, callback_id, text=""):
        self.order.append("answer")
        self.answered.append(text)
        return {"answered": True}

    def creator(self, event_id, *, state, **kwargs):
        self.order.append("create")
        state.mark_event_created(event_id, "g1")
        state.save()
        return {"created": True, "google_event_id": "g1", "already_created": False}

    def test_stranger_gets_nothing(self):
        result = callback_run(self.update(from_id=999), state=self.state,
                              owner_id=777, answer=self.answer,
                              creator=self.creator)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "not_owner")
        self.assertNotIn("create", self.order)

    def test_callback_answered_before_any_work(self):
        """Доки бот не відповів, у клієнті крутиться індикатор."""
        callback_run(self.update(), state=self.state, owner_id=777,
                     answer=self.answer, creator=self.creator,
                     edit=lambda mid, markup: {"edited": True})
        self.assertEqual(self.order[:2], ["answer", "create"])

    def test_edit_failure_falls_back_to_message(self):
        sent: list[str] = []

        def sender(text, *, state, idempotency_key, **kwargs):
            sent.append(text)
            return {"sent": True, "message_id": 1, "already_sent": False}

        result = callback_run(self.update(), state=self.state, owner_id=777,
                              answer=self.answer, creator=self.creator,
                              edit=lambda mid, markup: {"edited": False,
                                                        "reason": "not found"},
                              sender=sender)
        self.assertTrue(result["ok"])
        self.assertTrue(sent and sent[0].startswith("✅ Додано"))

    def test_other_buttons_survive_a_press(self):
        """
        Знайдено вживу: натискання однієї кнопки стирало всю клавіатуру,
        і сусідня подія ставала недосяжною, лишившись живою чернеткою
        у стані. Telegram замінює клавіатуру ЦІЛКОМ — перемальовувати
        треба всі рядки.
        """
        start = datetime.now(timezone.utc) + timedelta(days=2)
        second = self.state.put_pending_event(
            title="переліт до Анталії", start=start.isoformat(),
            end=(start + timedelta(hours=3)).isoformat(), source="work/102")
        self.state.remember_digest_events([self.event_id, second])
        self.state.save()

        sent_markup = {}

        def edit(message_id, markup):
            sent_markup.update(markup)
            return {"edited": True}

        callback_run(self.update(), state=self.state, owner_id=777,
                     answer=self.answer, creator=self.creator, edit=edit)

        rows = sent_markup["inline_keyboard"]
        self.assertEqual(len(rows), 2, "друга кнопка не має зникати")
        self.assertIn("✅ Додано", rows[0][0]["text"])
        self.assertIn("переліт до Анталії", rows[1][0]["text"])
        self.assertEqual(rows[1][0]["callback_data"], f"add:{second}")

    def test_declined_row_is_marked_not_removed(self):
        self.state.remember_digest_events([self.event_id])
        self.state.save()
        sent_markup = {}
        callback_run(self.update(data="skip:"), state=self.state, owner_id=777,
                     answer=self.answer, creator=self.creator,
                     edit=lambda mid, markup: (sent_markup.update(markup),
                                               {"edited": True})[1])
        row = sent_markup["inline_keyboard"][0]
        self.assertIn("Пропущено", row[0]["text"])

    def test_skip_declines_without_creating(self):
        result = callback_run(self.update(data="skip:"), state=self.state,
                              owner_id=777, answer=self.answer,
                              creator=self.creator,
                              edit=lambda mid, markup: {"edited": True})
        self.assertEqual(result["action"], "skip")
        self.assertNotIn("create", self.order)
        self.assertEqual(self.state.snapshot()["pending_events"][self.event_id]["status"],
                         "declined")

    def test_failed_creation_keeps_draft(self):
        """Токен помер — чернетку не втрачаємо, кнопка має спрацювати пізніше."""
        sent: list[str] = []

        def failing(event_id, *, state, **kwargs):
            raise ToolError("invalid_grant", status=401)

        result = callback_run(
            self.update(), state=self.state, owner_id=777, answer=self.answer,
            creator=failing,
            sender=lambda text, **kw: sent.append(text) or {"sent": True,
                                                            "message_id": 1},
            edit=lambda mid, markup: {"edited": True})
        self.assertFalse(result["ok"])
        self.assertEqual(self.state.pending_event(self.event_id)["status"], "pending")
        self.assertTrue(sent and "Не вдалося" in sent[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

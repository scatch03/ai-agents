"""
Тести інструментального шару. Мережі немає: IMAP і Telegram підмінені фейками.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailagent.config import Config, Mailbox                      # noqa: E402
from mailagent.errors import ToolError                            # noqa: E402
from mailagent.state import State                                 # noqa: E402
from mailagent import tools                                       # noqa: E402
from mailagent.tools import calendar as cal                       # noqa: E402
from mailagent.tools import mail, telegram                        # noqa: E402
from tests.fakes import FakeIMAP, FakeTelegram, build_email       # noqa: E402

BOX = Mailbox(id="work", host="imap.test", user="me@test")
CONFIG = Config(mailboxes=(BOX,), _by_id={"work": BOX})


def conns_with(fake: FakeIMAP) -> mail.Connections:
    return mail.Connections(CONFIG, opener=lambda box: fake)


def fresh_state() -> State:
    return State(tempfile.mktemp(suffix=".json"))


class TestListNewEmails(unittest.TestCase):
    def make(self, uids, uidvalidity=42):
        headers = {u: f"From: a@b.com\r\nSubject: лист {u}\r\n"
                      f"Authentication-Results: dkim=pass\r\n\r\n" for u in uids}
        return FakeIMAP(uidvalidity=uidvalidity, uids=uids, headers=headers)

    def test_readonly_always(self):
        """Агент не має права позначати листи прочитаними."""
        fake = self.make([101])
        with conns_with(fake) as c:
            mail.list_new_emails("work", 100, conns=c)
        self.assertTrue(fake.selected_readonly)

    def test_filters_imap_range_quirk(self):
        """Діапазон N:* віддає останній лист, навіть якщо він старіший за курсор."""
        fake = self.make([50])          # єдиний лист старіший за курсор
        with conns_with(fake) as c:
            result = mail.list_new_emails("work", 100, conns=c)
        self.assertEqual(result["messages"], [])

    def test_empty_is_not_an_error(self):
        fake = FakeIMAP(uids=[], headers={})
        with conns_with(fake) as c:
            result = mail.list_new_emails("work", 100, conns=c)
        self.assertEqual(result["messages"], [])
        self.assertFalse(result["truncated"])

    def test_truncation_keeps_oldest(self):
        """Найновіші віддавати не можна: курсор стане max(uid) і хвіст зникне."""
        fake = self.make(list(range(101, 111)))
        with conns_with(fake) as c:
            result = mail.list_new_emails("work", 100, conns=c, limit=3)
        self.assertEqual([m["uid"] for m in result["messages"]], [101, 102, 103])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["remaining"], 7)

    def test_uidvalidity_change_resets(self):
        fake = self.make([1, 2], uidvalidity=99)
        with conns_with(fake) as c:
            result = mail.list_new_emails("work", 100, conns=c, uidvalidity=42)
        self.assertTrue(result["uidvalidity_changed"])
        self.assertEqual(result["uidvalidity"], 99)
        self.assertEqual([m["uid"] for m in result["messages"]], [1, 2])

    def test_auth_results_parsed(self):
        fake = self.make([101])
        with conns_with(fake) as c:
            result = mail.list_new_emails("work", 100, conns=c)
        self.assertIs(result["messages"][0]["auth_passed"], True)

    def test_unknown_mailbox_rejected(self):
        with conns_with(self.make([101])) as c:
            with self.assertRaises(ToolError) as ctx:
                mail.list_new_emails("чужа_скринька", 0, conns=c)
        self.assertIn("немає в конфізі", str(ctx.exception))


class TestFetchBody(unittest.TestCase):
    def test_html_to_text_and_link_pairs(self):
        """Пари (текст, href) — саме на їхньому розходженні ловиться фішинг."""
        html = ('<p>Вітаємо!</p><a href="http://evil.example/x">ваш банк</a>'
                '<script>alert(1)</script>')
        fake = FakeIMAP(bodies={7: build_email(subject="s", sender="a@b", html=html)})
        with conns_with(fake) as c:
            body = mail.fetch_email_body("work", 7, conns=c)
        self.assertIn("Вітаємо", body["text"])
        self.assertNotIn("alert(1)", body["text"])
        self.assertEqual(body["links"][0], {"text": "ваш банк",
                                            "href": "http://evil.example/x"})

    def test_quotes_and_signature_stripped(self):
        plain = ("Коротка суть.\n\n-- \nІван, CTO\n\n"
                 "On Wed, 2 Sep 2026, someone wrote:\n> стара розмова\n")
        fake = FakeIMAP(bodies={7: build_email(subject="s", sender="a@b", plain=plain)})
        with conns_with(fake) as c:
            body = mail.fetch_email_body("work", 7, conns=c)
        self.assertEqual(body["text"], "Коротка суть.")

    def test_attachments_listed_not_read(self):
        fake = FakeIMAP(bodies={7: build_email(subject="s", sender="a@b",
                                               plain="текст", attachment="payload.zip")})
        with conns_with(fake) as c:
            body = mail.fetch_email_body("work", 7, conns=c)
        self.assertEqual(body["attachments"][0]["name"], "payload.zip")

    def test_missing_uid_is_404_not_crash(self):
        """Лист прибрали між опитуванням і читанням — гонка, а не збій системи."""
        with conns_with(FakeIMAP(bodies={})) as c:
            with self.assertRaises(ToolError) as ctx:
                mail.fetch_email_body("work", 999, conns=c)
        self.assertEqual(ctx.exception.status, 404)

    def test_truncation_flag(self):
        fake = FakeIMAP(bodies={7: build_email(subject="s", sender="a@b",
                                               plain="я" * 5000)})
        with conns_with(fake) as c:
            body = mail.fetch_email_body("work", 7, conns=c, max_chars=100)
        self.assertTrue(body["truncated"])
        self.assertEqual(len(body["text"]), 100)


class TestTelegram(unittest.TestCase):
    def setUp(self):
        os.environ["TELEGRAM_BOT_TOKEN"] = "test-token"
        os.environ["TELEGRAM_CHAT_ID"] = "555"

    def test_idempotency_key_blocks_second_send(self):
        state, fake = fresh_state(), FakeTelegram()
        first = telegram.send_message("текст", state=state,
                                      idempotency_key="digest-2026-09-08", caller=fake)
        second = telegram.send_message("текст", state=state,
                                       idempotency_key="digest-2026-09-08", caller=fake)
        self.assertTrue(first["sent"])
        self.assertTrue(second["already_sent"])
        self.assertEqual(len(fake.calls), 1, "друге повідомлення не мало піти")

    def test_never_sends_parse_mode(self):
        """Розмітка з листа не повинна стати клікабельним посиланням."""
        fake = FakeTelegram()
        telegram.send_message("[банк](http://evil.example)", state=fresh_state(),
                              idempotency_key="k", caller=fake)
        payload = fake.calls[0][1]
        self.assertNotIn("parse_mode", payload)
        self.assertEqual(payload["chat_id"], "555")

    def test_long_text_truncated_not_rejected(self):
        fake = FakeTelegram()
        telegram.send_message("я" * 5000, state=fresh_state(),
                              idempotency_key="k", caller=fake)
        self.assertLessEqual(len(fake.calls[0][1]["text"]), telegram.MAX_TEXT)

    def test_edit_failure_is_reported_not_raised(self):
        """Напис на кнопці — косметика; подія в календарі важливіша."""
        fake = FakeTelegram(errors={"editMessageReplyMarkup":
                                    ToolError("message to edit not found", status=400)})
        result = telegram.edit_message_buttons(8871, {"inline_keyboard": []}, caller=fake)
        self.assertFalse(result["edited"])
        self.assertIn("not found", result["reason"])


class TestCalendar(unittest.TestCase):
    def setUp(self):
        os.environ["GOOGLE_CALENDAR_ID"] = "cal@group.calendar.google.com"
        cal._token_cache.update({"value": None, "expires_at": 0})

    def draft(self, state: State, *, hours: int = 3) -> str:
        start = datetime.now(timezone.utc) + timedelta(hours=hours)
        return state.put_pending_event(
            title="зустріч з підрядником", start=start.isoformat(),
            end=(start + timedelta(hours=1)).isoformat(), source="work/88425")

    def client_returning(self, status: int, payload: dict):
        class FakeResponse:
            status_code = status
            text = str(payload)

            def json(self):
                return payload

        class FakeClient:
            def __init__(self):
                self.posted = []

            def post(self, url, **kwargs):
                self.posted.append((url, kwargs))
                return FakeResponse()

            def close(self):
                pass

        return FakeClient()

    def test_body_never_contains_attendees(self):
        """Найважливіший тест модуля: подія не має ставати каналом розсилки."""
        state = fresh_state()
        event_id = self.draft(state)
        client = self.client_returning(200, {"id": "abc", "htmlLink": "http://x"})
        cal.create_calendar_event(event_id, state=state, client=client,
                                  token_provider=lambda **kw: "tok")
        body = client.posted[0][1]["json"]
        self.assertNotIn("attendees", body)
        self.assertEqual(client.posted[0][1]["params"]["sendUpdates"], "none")

    def test_second_press_creates_nothing(self):
        state = fresh_state()
        event_id = self.draft(state)
        client = self.client_returning(200, {"id": "abc", "htmlLink": "http://x"})
        cal.create_calendar_event(event_id, state=state, client=client,
                                  token_provider=lambda **kw: "tok")
        again = cal.create_calendar_event(event_id, state=state, client=client,
                                          token_provider=lambda **kw: "tok")
        self.assertTrue(again["already_created"])
        self.assertEqual(len(client.posted), 1)

    def test_google_409_counts_as_success(self):
        state = fresh_state()
        event_id = self.draft(state)
        client = self.client_returning(409, {"error": "duplicate"})
        result = cal.create_calendar_event(event_id, state=state, client=client,
                                           token_provider=lambda **kw: "tok")
        self.assertTrue(result["already_created"])

    def test_past_event_rejected(self):
        state = fresh_state()
        event_id = self.draft(state, hours=-5)
        with self.assertRaises(ToolError):
            cal.create_calendar_event(event_id, state=state,
                                      client=self.client_returning(200, {}),
                                      token_provider=lambda **kw: "tok")

    def test_expired_draft_rejected(self):
        state = fresh_state()
        start = datetime.now(timezone.utc) + timedelta(days=30)
        event_id = state.put_pending_event(
            title="давня", start=start.isoformat(),
            end=start.isoformat(), source="work/1", ttl_days=-1)
        with self.assertRaises(ToolError) as ctx:
            cal.create_calendar_event(event_id, state=state,
                                      client=self.client_returning(200, {}),
                                      token_provider=lambda **kw: "tok")
        self.assertEqual(ctx.exception.status, 410)

    def test_declined_draft_not_created(self):
        state = fresh_state()
        event_id = self.draft(state)
        cal.decline_event(event_id, state=state)
        with self.assertRaises(ToolError):
            cal.create_calendar_event(event_id, state=state,
                                      client=self.client_returning(200, {}),
                                      token_provider=lambda **kw: "tok")


class TestStateGuards(unittest.TestCase):
    def test_cursor_never_moves_backwards(self):
        """Курсор, продиктований листом, назавжди сховав би пошту."""
        state = fresh_state()
        state.set_cursor("work", 100, 42)
        with self.assertRaises(ToolError):
            state.set_cursor("work", 50, 42)

    def test_cursor_resets_on_uidvalidity_change(self):
        state = fresh_state()
        state.set_cursor("work", 100, 42)
        state.set_cursor("work", 5, 99)
        self.assertEqual(state.cursor("work").uid, 5)




class TestRetryWiring(unittest.TestCase):
    """Політика повторів має бути не окремим модулем, а реальним шляхом викликів."""

    def setUp(self):
        os.environ["LLM_RETRY_BASE_DELAY"] = "0"   # тести не сплять

    def test_transient_failure_is_retried(self):
        attempts = {"n": 0}

        def flaky(**kwargs):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ToolError("503 temporarily unavailable", status=503)
            return {"ok": True}

        result = tools.call(flaky, label="flaky")
        self.assertEqual(attempts["n"], 3)
        self.assertEqual(result["_attempts"], 3)

    def test_auth_failure_fails_fast(self):
        attempts = {"n": 0}

        def revoked(**kwargs):
            attempts["n"] += 1
            raise ToolError("IMAP authentication failed", status=401)

        with self.assertRaises(Exception):
            tools.call(revoked, label="revoked")
        self.assertEqual(attempts["n"], 1, "401 не має повторюватись")


if __name__ == "__main__":
    unittest.main(verbosity=2)

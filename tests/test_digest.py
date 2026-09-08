"""
Тести рендерингу дайджесту.

Головне, що перевіряється: зсуви entities рахуються в UTF-16 (інакше жирний
шрифт з'їжджає на кожному емодзі), позначені листи не зникають ні за яких
обставин, і повідомлення не перевищує ліміт Telegram.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailagent.classify import Classified                          # noqa: E402
from mailagent.digest import (                                     # noqa: E402
    MAX_TEXT, MailboxReport, render_digest, utf16_len,
)
from mailagent.threats import NONE, Threat                         # noqa: E402

DAY = datetime(2026, 9, 3, 8, 0, tzinfo=timezone.utc)


def rec(uid=1, category="work", summary="переказ листа", *, threat=NONE,
        needs_action=False, deadline=None, mailbox="work_gmail",
        sender="a@b.com") -> Classified:
    return Classified(uid=uid, mailbox_id=mailbox, sender=sender,
                      subject="тема", category=category, summary=summary,
                      needs_action=needs_action, deadline=deadline, threat=threat)


def boxes(**kwargs) -> list[MailboxReport]:
    return [MailboxReport(mailbox_id="work_gmail", count=1, uid_from=1, uid_to=1,
                          **kwargs)]


class TestEntities(unittest.TestCase):
    def test_offsets_are_utf16_not_python_chars(self):
        """Емодзі поза BMP важить дві одиниці — інакше жирний з'їжджає."""
        result = render_digest([rec()], mailboxes=boxes(), day=DAY)
        encoded = result.text.encode("utf-16-le")
        for entity in result.entities:
            start = entity["offset"] * 2
            end = start + entity["length"] * 2
            fragment = encoded[start:end].decode("utf-16-le")
            self.assertNotIn("\n", fragment,
                             f"жирний фрагмент {fragment!r} з'їхав")
            self.assertTrue(fragment.strip(), "жирний фрагмент порожній")

    def test_headers_are_bold(self):
        result = render_digest([rec()], mailboxes=boxes(), day=DAY)
        encoded = result.text.encode("utf-16-le")
        bolds = [encoded[e["offset"] * 2:(e["offset"] + e["length"]) * 2]
                 .decode("utf-16-le") for e in result.entities]
        self.assertIn("Дайджест 3 вересня", bolds)
        self.assertIn("work (1)", bolds)
        self.assertIn("📮 Джерела", bolds)

    def test_headers_use_entities_not_markdown(self):
        """Жирний робиться зсувами, а не зірочками: parse_mode вимкнено."""
        result = render_digest([rec(summary="звичайний текст")],
                               mailboxes=boxes(), day=DAY)
        self.assertNotIn("*", result.text)
        self.assertNotIn("](", result.text)
        self.assertTrue(result.entities, "без entities заголовки будуть сірими")


class TestThreatVisibility(unittest.TestCase):
    def test_flagged_letter_visible_in_collapsed_category(self):
        """marketing показується лічильником — але не для позначених листів."""
        records = [rec(uid=i, category="marketing", summary=f"розсилка {i}")
                   for i in range(1, 6)]
        records.append(rec(uid=99, category="marketing", summary="виграш мільйона",
                           threat=Threat("scam", "класична схема")))
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        self.assertIn("виграш мільйона", result.text)
        self.assertNotIn("розсилка 1", result.text)

    def test_threat_counter_in_header(self):
        records = [rec(uid=1, category="finance"),
                   rec(uid=2, category="finance", summary="підтвердіть платіж",
                       threat=Threat("phishing", "домен не збігається"))]
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        self.assertIn("finance (2) 🚨 1 фішинг", result.text)

    def test_reason_line_under_flagged_item(self):
        records = [rec(threat=Threat("phishing", "DKIM не пройдено"),
                       sender="Ощадбанк <no-reply@0schadbank.net>")]
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        self.assertIn("схоже на фішинг: DKIM не пройдено", result.text)
        self.assertIn("0schadbank.net", result.text)

    def test_flagged_survives_budget_pressure(self):
        """Під тиском ліміту знімаються звичайні пункти, позначені — ніколи."""
        records = [rec(uid=i, category="work", summary=f"робочий лист {i} " + "х" * 60)
                   for i in range(1, 120)]
        records.append(rec(uid=999, category="work", summary="лист із загрозою",
                           threat=Threat("phishing", "домен-двійник")))
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        self.assertIn("лист із загрозою", result.text)
        self.assertLessEqual(result.utf16_length, MAX_TEXT)
        self.assertGreater(result.dropped, 0)


class TestHonestNotes(unittest.TestCase):
    def test_collapsed_by_design_is_not_reported_as_budget_cut(self):
        """
        marketing згорнуто задумом, а не лімітом. Примітка «згорнуто через
        ліміт Telegram» на повідомленні в 1 КБ із 4 — неправда, яка змусить
        шукати неіснуючу проблему.
        """
        records = [rec(uid=i, category="marketing", summary=f"розсилка {i}")
                   for i in range(1, 7)]
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        self.assertLess(result.utf16_length, 2000)
        self.assertEqual(result.dropped, 0)
        self.assertNotIn("ліміт Telegram", result.text)

    def test_injection_reason_reads_as_ukrainian(self):
        result = render_digest(
            [rec(threat=Threat("injection", "вказівки, адресовані асистенту"))],
            mailboxes=boxes(), day=DAY)
        self.assertIn("спроба інструктувати асистента:", result.text)
        self.assertNotIn("схоже на спроба", result.text)

    def test_plurals(self):
        for count, word in ((1, "1 лист"), (3, "3 листи"), (11, "11 листів")):
            records = [rec(uid=i) for i in range(count)]
            result = render_digest(records, mailboxes=boxes(), day=DAY)
            self.assertIn(f"— {word}", result.text)


class TestBudget(unittest.TestCase):
    def test_never_exceeds_telegram_limit(self):
        records = [rec(uid=i, category="work", summary="довгий переказ " + "я" * 150)
                   for i in range(1, 200)]
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        self.assertLessEqual(result.utf16_length, MAX_TEXT)

    def test_counts_stay_truthful_when_items_dropped(self):
        """Пункти зникають, лічильник — ні: (120) має лишитися (120)."""
        records = [rec(uid=i, category="work", summary="лист " + "я" * 120)
                   for i in range(1, 121)]
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        self.assertIn("work (120)", result.text)
        self.assertIn("згорнуто через ліміт", result.text)


class TestStructure(unittest.TestCase):
    def test_action_block_gathers_across_categories(self):
        records = [rec(uid=1, category="finance", summary="рахунок Hetzner",
                       needs_action=True, deadline="2026-09-06"),
                   rec(uid=2, category="work", summary="дедлайн інтеграції",
                       needs_action=True)]
        result = render_digest(records, mailboxes=boxes(), day=DAY)
        head = result.text.split("\nfinance (")[0]
        self.assertIn("Потребує дії", head)
        self.assertIn("рахунок Hetzner", head)
        self.assertIn("до 2026-09-06", head)

    def test_empty_categories_collapse_into_one_line(self):
        result = render_digest([rec()], mailboxes=boxes(), day=DAY)
        self.assertIn("порожньо: security, finance", result.text)
        self.assertNotIn("worldnews (0)", result.text)

    def test_sources_block_distinguishes_empty_from_broken(self):
        """«Нічого не прийшло» і «не змогли прочитати» — протилежні речі."""
        reports = [
            MailboxReport(mailbox_id="work_gmail", count=2, uid_from=10, uid_to=11),
            MailboxReport(mailbox_id="news_gmail", count=0, status="empty"),
            MailboxReport(mailbox_id="personal_imap", status="error",
                          error="відкликано app password"),
        ]
        result = render_digest([rec()], mailboxes=reports, day=DAY)
        self.assertIn("work_gmail 2 листи, uid 10–11", result.text)
        self.assertIn("news_gmail 0 — порожньо", result.text)
        self.assertIn("personal_imap — недоступна (відкликано app password)",
                      result.text)

    def test_notes_are_rendered(self):
        result = render_digest([rec()], mailboxes=boxes(), day=DAY,
                               notes=["скринька X недоступна"])
        self.assertIn("⚠️ скринька X недоступна", result.text)


class TestButtons(unittest.TestCase):
    def draft(self, title="зустріч з підрядником"):
        start = datetime(2026, 9, 3, 15, 0, tzinfo=timezone.utc)
        return {"title": title, "start": start.isoformat(),
                "end": (start + timedelta(hours=1)).isoformat(),
                "location": "Zoom", "confidence": 0.9}

    def test_button_label_explains_itself(self):
        """Клавіатура кріпиться до повідомлення, не до рядка — підпис має пояснювати."""
        result = render_digest([rec()], mailboxes=boxes(), day=DAY,
                               event_drafts={1: ("ev_7f3a", self.draft())})
        button = result.reply_markup["inline_keyboard"][0][0]
        self.assertIn("зустріч з підрядником", button["text"])
        self.assertIn("03.09 15:00", button["text"])

    def test_callback_data_is_opaque_id_only(self):
        result = render_digest([rec()], mailboxes=boxes(), day=DAY,
                               event_drafts={1: ("ev_7f3a", self.draft())})
        row = result.reply_markup["inline_keyboard"][0]
        self.assertEqual(row[0]["callback_data"], "add:ev_7f3a")
        self.assertEqual(row[1]["callback_data"], "skip:ev_7f3a")
        for button in row:
            self.assertLessEqual(len(button["callback_data"].encode()), 64,
                                 "Telegram обмежує callback_data 64 байтами")

    def test_no_buttons_without_drafts(self):
        result = render_digest([rec()], mailboxes=boxes(), day=DAY)
        self.assertIsNone(result.reply_markup)

    def test_button_count_capped(self):
        drafts = {i: (f"ev_{i:04x}", self.draft(f"подія {i}")) for i in range(20)}
        result = render_digest([rec()], mailboxes=boxes(), day=DAY,
                               event_drafts=drafts)
        self.assertLessEqual(len(result.reply_markup["inline_keyboard"]), 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)

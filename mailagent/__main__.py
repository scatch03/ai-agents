"""
CLI агента.

    python -m mailagent digest --dry-run   показати дайджест, нічого не надсилаючи
    python -m mailagent digest             зібрати і надіслати
    python -m mailagent listen             слухати натискання кнопок
    python -m mailagent state              показати стан між запусками
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx

from .config import load_config, telegram_owner_id, telegram_token
from .errors import ConfigError, ToolError
from .run import Limits, callback_run, digest_run
from .state import State

POLL_TIMEOUT = 25


def cmd_digest(args) -> int:
    result = digest_run(dry_run=args.dry_run,
                        limits=Limits(max_cost_usd=args.max_cost))
    if args.dry_run:
        print(result["text"])
        print("─" * 60)
    summary = (f"листів: {result['letters']}, ітерацій: {result['iterations']}, "
               f"${result['cost_usd']:.5f}, {result['seconds']} c")
    print(summary)
    if result["mailboxes_failed"]:
        print("недоступні скриньки:", ", ".join(result["mailboxes_failed"]))
    if result["stopped_by"]:
        print("зупинено:", result["stopped_by"])
    if not args.dry_run:
        sent = result["sent"] or {}
        print("надіслано" if sent.get("sent") else
              "вже надсилалося сьогодні" if sent.get("already_sent") else "не надіслано")
        print("курсори зсунуто:", ", ".join(result["cursors_moved"]) or "жодного")
    return 0


def cmd_listen(args) -> int:
    """
    Довгий опит getUpdates. Простіший за вебхук і не потребує білої адреси;
    для одного власника цього досить.
    """
    state = State()
    owner = telegram_owner_id()
    url = f"https://api.telegram.org/bot{telegram_token()}/getUpdates"
    print(f"слухаю натискання (власник {owner}), Ctrl+C щоб зупинити")
    with httpx.Client(timeout=POLL_TIMEOUT + 10) as client:
        while True:
            try:
                response = client.get(url, params={
                    "offset": state.last_update_id + 1,
                    "timeout": POLL_TIMEOUT,
                    "allowed_updates": '["callback_query"]',
                })
                updates = response.json().get("result", [])
            except (httpx.HTTPError, ValueError) as exc:
                print(f"опит не вдався: {exc}; чекаю 5 c", file=sys.stderr)
                time.sleep(5)
                continue

            for update in updates:
                state.set_last_update_id(update["update_id"])
                state.save()
                if "callback_query" not in update:
                    continue
                try:
                    result = callback_run(update, state=state, owner_id=owner)
                    print(f"  {result}")
                except (ToolError, ConfigError) as exc:
                    print(f"  збій обробки: {exc}", file=sys.stderr)


def cmd_state(args) -> int:
    state = State()
    data = state.snapshot()
    print(f"файл: {state.path}")
    print(f"останній дайджест: {data.get('last_digest_date')} "
          f"(message_id {data.get('last_digest_message_id')})")
    print("курсори:")
    for mailbox_id, cursor in (data.get("cursors") or {}).items():
        print(f"  {mailbox_id}: uid {cursor['uid']}, uidvalidity {cursor['uidvalidity']}")
    pending = {k: v for k, v in (data.get("pending_events") or {}).items()
               if v["status"] == "pending"}
    print(f"чернеток подій у черзі: {len(pending)}")
    for event_id, event in pending.items():
        print(f"  {event_id}: {event['title']} @ {event['start']} (з {event['source']})")
    print(f"відомих доменів-відправників: {len(data.get('known_senders') or {})}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mailagent", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    digest = sub.add_parser("digest", help="зібрати і надіслати ранковий дайджест")
    digest.add_argument("--dry-run", action="store_true",
                        help="показати текст і нічого не надсилати; "
                             "курсори при цьому не рухаються")
    digest.add_argument("--max-cost", type=float, default=0.10,
                        help="стеля витрат на запуск, доларів")
    digest.set_defaults(func=cmd_digest)

    listen = sub.add_parser("listen", help="слухати натискання кнопок у Telegram")
    listen.set_defaults(func=cmd_listen)

    show = sub.add_parser("state", help="показати стан між запусками")
    show.set_defaults(func=cmd_state)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nзупинено")
        return 130
    except ConfigError as exc:
        print(f"конфіг: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

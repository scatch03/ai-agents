"""
Одноразовий OAuth-обмін для Google Calendar.

    python scripts/google_oauth.py                 отримати refresh token
    python scripts/google_oauth.py --create-calendar   ще й завести календар
    python scripts/google_oauth.py --full-scope    якщо вузький доступ відхилено

Що робить: піднімає локальний сервер на 127.0.0.1, відкриває браузер із
згодою Google, ловить код і міняє його на refresh token. Токен друкується
в консоль — вписати його в .env маєш ти сам, скрипт у твій .env не лізе.

Два рішення про безпеку:

1. Доступ береться найвужчий — calendar.app.created: це дозволяє працювати
   ЛИШЕ з календарями, які створив цей застосунок. Навіть повністю зламаний
   агент не дотягнеться до особистого календаря. Якщо Google відхилить цей
   доступ, --full-scope дасть звичайний calendar, але це помітно ширше.

2. PKCE обов'язковий. Для встановлених застосунків client_secret не є
   таємницею (він лежить у .env на твоїй машині), тож перехоплений код
   без code_verifier нічого не дає.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import os
import secrets
import socket
import sys
import threading
import urllib.parse
import webbrowser

import httpx
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
CALENDAR_API = "https://www.googleapis.com/calendar/v3"

NARROW_SCOPE = "https://www.googleapis.com/auth/calendar.app.created"
FULL_SCOPE = "https://www.googleapis.com/auth/calendar"
CALENDAR_NAME = "Пошта (агент)"


def pkce_pair() -> tuple[str, str]:
    """(verifier, challenge) за S256, як вимагає RFC 7636."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def build_auth_url(client_id: str, redirect_uri: str, *, scope: str,
                   challenge: str, state: str) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        # offline + consent — інакше Google віддасть лише access token,
        # а refresh token видається тільки при явній згоді.
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Catcher(http.server.BaseHTTPRequestHandler):
    """Ловить один редирект від Google і показує людині, що можна закрити вкладку."""

    result: dict[str, str] = {}
    done = threading.Event()

    def do_GET(self):  # noqa: N802 — ім'я диктує BaseHTTPRequestHandler
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        _Catcher.result = {k: v[0] for k, v in query.items()}
        ok = "code" in _Catcher.result
        body = ("<h2>Готово. Повертайся в термінал.</h2>" if ok else
                f"<h2>Не вийшло: {_Catcher.result.get('error', 'невідома помилка')}</h2>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())
        _Catcher.done.set()

    def log_message(self, *args):
        pass  # не засмічуємо консоль


def obtain_code(client_id: str, scope: str) -> tuple[str, str, str]:
    """Повертає (code, verifier, redirect_uri)."""
    port = free_port()
    redirect_uri = f"http://127.0.0.1:{port}/"
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)

    server = http.server.HTTPServer(("127.0.0.1", port), _Catcher)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    url = build_auth_url(client_id, redirect_uri, scope=scope,
                         challenge=challenge, state=state)
    print("Відкриваю браузер. Якщо не відкрився — перейди сам:\n")
    print(url, "\n")
    webbrowser.open(url)

    if not _Catcher.done.wait(timeout=300):
        server.shutdown()
        raise SystemExit("минуло 5 хвилин без відповіді — спробуй ще раз")
    server.shutdown()

    result = _Catcher.result
    if result.get("state") != state:
        # Чужий state означає, що редирект прийшов не з нашого запиту.
        raise SystemExit("state не збігається — обмін перервано")
    if "code" not in result:
        raise SystemExit(f"Google відмовив: {result.get('error')}")
    return result["code"], verifier, redirect_uri


def exchange(code: str, verifier: str, redirect_uri: str, *, client_id: str,
             client_secret: str) -> dict:
    response = httpx.post(TOKEN_URL, data={
        "code": code, "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        "code_verifier": verifier,
    }, timeout=30)
    body = response.json()
    if response.status_code != 200:
        raise SystemExit(f"обмін коду не вдався: {body}")
    if "refresh_token" not in body:
        raise SystemExit(
            "Google не віддав refresh_token. Таке буває, якщо доступ уже було "
            "надано раніше: відкликай його на myaccount.google.com/permissions "
            "і запусти скрипт ще раз")
    return body


def create_calendar(access_token: str) -> str:
    response = httpx.post(f"{CALENDAR_API}/calendars",
                          headers={"Authorization": f"Bearer {access_token}"},
                          json={"summary": CALENDAR_NAME,
                                "description": "Події, зібрані агентом із пошти"},
                          timeout=30)
    if response.status_code >= 300:
        raise SystemExit(f"не вдалося створити календар: {response.text[:300]}")
    return response.json()["id"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full-scope", action="store_true",
                        help="звичайний доступ до календаря замість вузького")
    parser.add_argument("--create-calendar", action="store_true",
                        help=f"створити календар «{CALENDAR_NAME}» і показати його id")
    args = parser.parse_args(argv)

    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        print("Спершу створи OAuth-клієнт типу «Desktop app» у Google Cloud Console\n"
              "(APIs & Services → Credentials), увімкни Google Calendar API\n"
              "і впиши GOOGLE_OAUTH_CLIENT_ID та GOOGLE_OAUTH_CLIENT_SECRET у .env",
              file=sys.stderr)
        return 2

    scope = FULL_SCOPE if args.full_scope else NARROW_SCOPE
    print(f"доступ: {scope}")
    code, verifier, redirect_uri = obtain_code(client_id, scope)
    tokens = exchange(code, verifier, redirect_uri,
                      client_id=client_id, client_secret=client_secret)

    print("\nВпиши в .env:\n")
    print(f"GOOGLE_OAUTH_REFRESH_TOKEN={tokens['refresh_token']}")
    if args.create_calendar:
        calendar_id = create_calendar(tokens["access_token"])
        print(f"GOOGLE_CALENDAR_ID={calendar_id}")
    else:
        print("\nІд календаря візьми в налаштуваннях Google Calendar або запусти\n"
              "скрипт ще раз із --create-calendar")
    print("\nТокен більше ніде не збережено — цей вивід єдиний.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

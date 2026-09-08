"""Фейки замість IMAP-сервера й Telegram API: тести не ходять у мережу."""

from __future__ import annotations

from email.message import EmailMessage


class FakeIMAP:
    """Мінімальний імітатор imaplib.IMAP4_SSL: рівно ті виклики, які ми робимо."""

    def __init__(self, *, uidvalidity: int = 42, uids: list[int] | None = None,
                 headers: dict[int, str] | None = None,
                 bodies: dict[int, bytes] | None = None,
                 snippets: dict[int, bytes] | None = None,
                 recent_uids: list[int] | None = None):
        self.uidvalidity = uidvalidity
        self.uids = uids or []
        # Що поверне SEARCH SINCE: у справжній скриньці це лише свіжі листи,
        # а не весь архів. Якщо не задано — усі (стара поведінка фейка).
        self.recent_uids = recent_uids
        self.headers = headers or {}
        self.bodies = bodies or {}
        self.snippets = snippets or {}
        self.calls: list[tuple] = []
        self.selected_readonly: bool | None = None

    def select(self, folder, readonly=False):
        self.selected_readonly = readonly
        self.calls.append(("select", folder, readonly))
        return "OK", [b"34"]

    def status(self, folder, what):
        return "OK", [f"{folder} (UIDVALIDITY {self.uidvalidity})".encode()]

    def uid(self, command, *args):
        command = command.lower()
        self.calls.append(("uid", command) + args)
        if command == "search":
            criteria = args[1:]
            if criteria and criteria[0] == "UID":
                since = int(criteria[1].split(":")[0]) - 1
                # Квирк справжнього IMAP: діапазон завжди віддає останній лист.
                found = [u for u in self.uids if u > since] or self.uids[-1:]
            elif criteria and criteria[0] == "SINCE":
                found = list(self.recent_uids if self.recent_uids is not None
                             else self.uids)
            else:
                found = list(self.uids)
            return "OK", [" ".join(str(u) for u in found).encode()]
        if command == "fetch":
            uid_set, query = args[0], args[1]
            wanted = [int(x) for x in uid_set.split(",")]
            if "HEADER.FIELDS" in query:
                return "OK", [
                    (f"1 (UID {u} BODYSTRUCTURE (\"text\" \"plain\") "
                     f"BODY[HEADER.FIELDS]".encode(),
                     self.headers.get(u, "").encode())
                    for u in wanted if u in self.headers
                ]
            if "BODY.PEEK[1]" in query:
                return "OK", [
                    (f"1 (UID {u} BODY[1]".encode(), self.snippets.get(u, b""))
                    for u in wanted if u in self.snippets
                ]
            return "OK", [
                (f"1 (UID {u} BODY[]".encode(), self.bodies[u])
                for u in wanted if u in self.bodies
            ]
        raise AssertionError(f"неочікуваний виклик uid {command}")

    def logout(self):
        self.calls.append(("logout",))


def build_email(*, subject: str, sender: str, plain: str = "",
                html: str = "", attachment: str | None = None) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["Date"] = "Thu, 3 Sep 2026 08:00:00 +0300"
    if plain:
        msg.set_content(plain)
        if html:
            msg.add_alternative(html, subtype="html")
    else:
        msg.set_content(html or "", subtype="html")
    if attachment:
        msg.add_attachment(b"binary", maintype="application", subtype="zip",
                           filename=attachment)
    return msg.as_bytes()


class FakeTelegram:
    """Записує виклики і віддає заготовлені відповіді або кидає помилку."""

    def __init__(self, responses=None, errors=None):
        self.responses = responses or {}
        self.errors = errors or {}
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, method, payload, client=None):
        self.calls.append((method, payload))
        if method in self.errors:
            raise self.errors[method]
        return self.responses.get(method, {"message_id": 8871})

"""
Інструменти читання пошти: list_new_emails і fetch_email_body.

Два наскрізні принципи:
1. Скринька відкривається ТІЛЬКИ readonly. Агент не має права позначати
   листи прочитаними — людина має побачити свою пошту такою, якою залишила.
2. Усе, що прийшло з сервера, — дані. Заголовки й тіла нікуди не
   інтерпретуються, лише декодуються й обрізаються.
"""

from __future__ import annotations

import email
import email.policy
import imaplib
import re
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.message import Message
from html.parser import HTMLParser
from typing import Any, Callable, Iterable

from ..config import Config, Mailbox
from ..errors import ConfigError, ToolError

DEFAULT_LIMIT = 200
SNIPPET_CHARS = 200
IMAP_TIMEOUT = 30


# --------------------------------------------------------------------------
# Підключення
# --------------------------------------------------------------------------
def _open(mailbox: Mailbox) -> imaplib.IMAP4_SSL:
    try:
        conn = imaplib.IMAP4_SSL(mailbox.host, mailbox.port, timeout=IMAP_TIMEOUT)
    except OSError as exc:
        raise ToolError(f"{mailbox.id}: не вдалося підключитися до "
                        f"{mailbox.host}:{mailbox.port} — {exc}", status=503) from exc
    try:
        conn.login(mailbox.user, mailbox.password())
    except imaplib.IMAP4.error as exc:
        # Відкликаний app password повторною спробою не полагодиться.
        raise ToolError(f"{mailbox.id}: IMAP authentication failed — {exc}",
                        status=401) from exc
    return conn


class Connections:
    """
    Пул на час одного запуску: 12 тіл — це 12 логінів, якщо не тримати
    зʼєднання. Використовується як контекстний менеджер.
    """

    def __init__(self, config: Config, opener: Callable[[Mailbox], Any] = _open):
        self._config = config
        self._opener = opener
        self._live: dict[str, Any] = {}

    @property
    def config(self) -> Config:
        return self._config

    def get(self, mailbox_id: str):
        """
        Живе з'єднання. Перевірка через NOOP обов'язкова: сервер мовчки рве
        сесію після паузи, і пул віддавав би мертвий сокет знову й знову —
        перший тайм-аут перетворювався на нескінченну низку Broken pipe,
        бо перевідкрити його ніхто не намагався.
        """
        conn = self._live.get(mailbox_id)
        if conn is not None:
            try:
                conn.noop()
                return conn
            except Exception:  # noqa: BLE001 — будь-яка помилка тут = сесія мертва
                self.drop(mailbox_id)
        self._live[mailbox_id] = self._opener(self._config.mailbox(mailbox_id))
        return self._live[mailbox_id]

    def drop(self, mailbox_id: str) -> None:
        """Викидає з'єднання з пулу, щоб наступний виклик відкрив нове."""
        conn = self._live.pop(mailbox_id, None)
        if conn is None:
            return
        try:
            conn.logout()
        except Exception:  # noqa: BLE001 — воно вже зламане, це прибирання
            pass

    def close_all(self) -> None:
        for conn in self._live.values():
            try:
                conn.logout()
            except Exception:  # noqa: BLE001 — при закритті вже байдуже
                pass
        self._live.clear()

    def __enter__(self) -> "Connections":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close_all()


# --------------------------------------------------------------------------
# Розбір відповідей IMAP
# --------------------------------------------------------------------------
def _check(status: str, data, *, what: str, mailbox_id: str):
    if status != "OK":
        raise ToolError(f"{mailbox_id}: {what} повернув {status}: {data}", status=503)
    return data


def _parse_message(raw: bytes) -> Message:
    """
    policy=default обов'язкова: зі стандартною compat32 сирий UTF-8 у заголовку
    (нестандартно, але в реальній пошті трапляється) перетворюється на
    крякозябри безповоротно. default зберігає байти сурогатами, і їх ще можна
    полагодити — див. _decode_header.
    """
    try:
        return email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:  # noqa: BLE001 — на геть кривому листі відкочуємось
        return email.message_from_bytes(raw)


def _decode_header(raw: object) -> str:
    if not raw:
        return ""
    value = str(raw)
    try:
        value = str(make_header(decode_header(value)))
    except Exception:  # noqa: BLE001 — кривий заголовок не привід падати
        pass
    if any("\ud800" <= ch <= "\udfff" for ch in value):
        # Байти, які парсер не зміг витлумачити, приїхали сурогатами.
        try:
            value = value.encode("utf-8", "surrogateescape").decode("utf-8")
        except UnicodeDecodeError:
            value = value.encode("utf-8", "replace").decode("utf-8")
    return value.strip()


_AUTH_RE = re.compile(r"\b(dkim|spf|dmarc)=(\w+)", re.I)


def _auth_results(raw: str | None) -> dict[str, Any]:
    """
    Прапорець довіри до відправника з Authentication-Results.

    Правило навмисно не «усе має пройти»: SPF регулярно падає на пересиланні
    цілком легітимних листів. Довіряємо, якщо пройшов DMARC або хоча б DKIM —
    підробити From при цьому вже недостатньо.
    """
    if not raw:
        return {"dkim": None, "spf": None, "dmarc": None, "passed": None}
    found = {k.lower(): v.lower() for k, v in _AUTH_RE.findall(raw)}
    dkim, spf, dmarc = found.get("dkim"), found.get("spf"), found.get("dmarc")
    if dmarc == "pass" or dkim == "pass":
        passed = True
    elif dmarc is None and dkim is None and spf is None:
        passed = None  # заголовка немає — не знаємо, а не «погано»
    else:
        passed = False
    return {"dkim": dkim, "spf": spf, "dmarc": dmarc, "passed": passed}


def _uid_of(raw: bytes) -> int | None:
    match = re.search(rb"UID (\d+)", raw)
    return int(match.group(1)) if match else None


def _pairs(response: Iterable) -> list[tuple[bytes, bytes]]:
    """imaplib віддає перемішаний список; лишаємо тільки (метадані, корисне)."""
    return [item for item in response if isinstance(item, tuple) and len(item) >= 2]


# --------------------------------------------------------------------------
# list_new_emails
# --------------------------------------------------------------------------
HEADER_FIELDS = "FROM SUBJECT DATE MESSAGE-ID AUTHENTICATION-RESULTS"


def list_new_emails(mailbox_id: str, since_uid: int, *, conns: Connections,
                    uidvalidity: int | None = None,
                    limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    """
    Заголовки нових листів однієї скриньки. Тіла не тягне.

    Повертає {mailbox_id, uidvalidity, uidvalidity_changed, messages,
              truncated, remaining}.
    Порожня скринька — це порожній список, а НЕ помилка.
    """
    if limit < 1:
        raise ConfigError("limit має бути додатним")
    conn = conns.get(mailbox_id)
    box = conns.config.mailbox(mailbox_id)

    status, data = conn.select(box.folder, readonly=True)
    _check(status, data, what=f"SELECT {box.folder}", mailbox_id=mailbox_id)

    status, data = conn.status(box.folder, "(UIDVALIDITY)")
    _check(status, data, what="STATUS UIDVALIDITY", mailbox_id=mailbox_id)
    match = re.search(rb"UIDVALIDITY (\d+)", b" ".join(data))
    current_validity = int(match.group(1)) if match else None

    # Скриньку перенумерували — старий курсор більше нічого не означає.
    changed = (uidvalidity is not None and current_validity is not None
               and uidvalidity != current_validity)
    effective_since = 0 if changed else since_uid

    if effective_since > 0:
        criteria = ("UID", f"{effective_since + 1}:*")
    else:
        # Перший запуск (або перенумерація) — НЕ читаємо весь архів: у скриньці
        # цілком можуть лежати тисячі листів. Беремо вікно в кілька днів,
        # решта лишається непрочитаною назавжди, і це навмисно.
        days = getattr(conns.config, "first_run_days", 1)
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%d-%b-%Y")
        criteria = ("SINCE", since)

    status, data = conn.uid("search", None, *criteria)
    _check(status, data, what=f"UID SEARCH {criteria}", mailbox_id=mailbox_id)
    uids = [int(x) for x in (data[0] or b"").split()]
    # Квирк IMAP: діапазон "N:*" повертає останній лист, навіть якщо він старіший.
    uids = sorted(u for u in uids if u > effective_since)

    truncated = len(uids) > limit
    remaining = len(uids) - limit if truncated else 0
    if truncated:
        # НАЙСТАРШІ limit штук: якщо взяти найновіші, курсор стане max(uid),
        # і все між ним і старим курсором зникне назавжди.
        uids = uids[:limit]

    messages = _fetch_headers(conn, uids, mailbox_id=mailbox_id) if uids else []
    return {
        "mailbox_id": mailbox_id,
        "uidvalidity": current_validity,
        "uidvalidity_changed": changed,
        "messages": messages,
        "truncated": truncated,
        "remaining": remaining,
    }


def _fetch_headers(conn, uids: list[int], *, mailbox_id: str) -> list[dict[str, Any]]:
    uid_set = ",".join(str(u) for u in uids)
    query = f"(UID BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS ({HEADER_FIELDS})])"
    status, data = conn.uid("fetch", uid_set, query)
    _check(status, data, what="UID FETCH headers", mailbox_id=mailbox_id)

    out: list[dict[str, Any]] = []
    for meta, payload in _pairs(data):
        uid = _uid_of(meta)
        if uid is None:
            continue
        headers = _parse_message(payload)
        auth = _auth_results(headers.get("Authentication-Results"))
        out.append({
            "uid": uid,
            "from": _decode_header(headers.get("From")),
            "subject": _decode_header(headers.get("Subject")),
            "date": _decode_header(headers.get("Date")),
            "message_id": _decode_header(headers.get("Message-ID")),
            # Груба, але дешева ознака: у BODYSTRUCTURE є disposition "attachment".
            "has_attachments": b'"attachment"' in meta.lower(),
            "auth": auth,
            "auth_passed": auth["passed"],
            "snippet": "",
        })
    out.sort(key=lambda m: m["uid"])
    _add_snippets(conn, out, mailbox_id=mailbox_id)
    return out


def _add_snippets(conn, messages: list[dict[str, Any]], *, mailbox_id: str) -> None:
    """
    Перші 200 символів першої текстової частини. Best-effort: якщо лист
    складний або частина не текстова, snippet лишається порожнім — тоді
    рішення про тіло ухвалюється за темою і відправником.
    """
    if not messages:
        return
    uid_set = ",".join(str(m["uid"]) for m in messages)
    try:
        status, data = conn.uid("fetch", uid_set, "(UID BODY.PEEK[1]<0.600>)")
        if status != "OK":
            return
    except Exception:  # noqa: BLE001 — snippet не критичний
        return
    by_uid = {m["uid"]: m for m in messages}
    for meta, payload in _pairs(data):
        uid = _uid_of(meta)
        if uid in by_uid and payload:
            text = payload.decode("utf-8", errors="replace")
            by_uid[uid]["snippet"] = re.sub(r"\s+", " ", text).strip()[:SNIPPET_CHARS]


# --------------------------------------------------------------------------
# fetch_email_body
# --------------------------------------------------------------------------
class _LinkStripper(HTMLParser):
    """Витягує текст і пари (текст посилання, href) — для перевірки на фішинг."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self.links: list[dict[str, str]] = []
        self._href: str | None = None
        self._link_text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href", "")
            self._link_text = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append({"text": "".join(self._link_text).strip(),
                               "href": self._href})
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.chunks.append(data)
        if self._href is not None:
            self._link_text.append(data)

    def text(self) -> str:
        return "".join(self.chunks)


_QUOTE_MARKERS = (
    re.compile(r"^\s*>", re.M),
)
_QUOTE_HEADERS = re.compile(
    r"^\s*(On .+ wrote:|[-]{2,}\s*Original Message|У .+ пише:|"
    r"\d{1,2}\.\d{1,2}\.\d{2,4}.{0,40}(написав|пише):)",
    re.M | re.I,
)
_SIGNATURE = re.compile(r"^-- \s*$", re.M)
_URL_RE = re.compile(r"https?://[^\s<>\"']+")


def _strip_quotes_and_signature(text: str) -> str:
    """Прибирає цитати попереднього листування і підпис — це шум, за який платимо."""
    cut = _QUOTE_HEADERS.search(text)
    if cut:
        text = text[:cut.start()]
    cut = _SIGNATURE.search(text)
    if cut:
        text = text[:cut.start()]
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith(">")]
    text = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _text_of(message: Message) -> tuple[str, list[dict[str, str]], list[dict[str, str]]]:
    """Повертає (текст, посилання, вкладення). text/plain у пріоритеті над html."""
    plain: list[str] = []
    html: list[str] = []
    attachments: list[dict[str, str]] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        if disposition == "attachment":
            attachments.append({
                "name": _decode_header(part.get_filename()) or "(без імені)",
                "type": ctype,
            })
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            continue
        charset = part.get_content_charset() or "utf-8"
        chunk = payload.decode(charset, errors="replace")
        if ctype == "text/plain":
            plain.append(chunk)
        elif ctype == "text/html":
            html.append(chunk)

    links: list[dict[str, str]] = []
    if plain:
        text = "\n".join(plain)
        links = [{"text": u, "href": u} for u in _URL_RE.findall(text)]
    elif html:
        parser = _LinkStripper()
        parser.feed("\n".join(html))
        text, links = parser.text(), parser.links
    else:
        text = ""
    return text, links, attachments


def fetch_email_body(mailbox_id: str, uid: int, *, conns: Connections,
                     max_chars: int = 3000) -> dict[str, Any]:
    """
    Текст одного листа, очищений від HTML, цитат і підпису.

    Повертає {uid, text, truncated, links, links_count, attachments}.
    links віддаються парами (текст, href) — саме на їхньому розходженні
    ловиться класичний фішинг; сам аналіз робить не цей інструмент.
    """
    conn = conns.get(mailbox_id)
    box = conns.config.mailbox(mailbox_id)
    status, data = conn.select(box.folder, readonly=True)
    _check(status, data, what=f"SELECT {box.folder}", mailbox_id=mailbox_id)

    status, data = conn.uid("fetch", str(uid), "(UID BODY.PEEK[])")
    if status != "OK":
        raise ToolError(f"{mailbox_id}: UID FETCH {uid} повернув {status}", status=503)
    pairs = _pairs(data)
    if not pairs:
        # Лист прибрали між опитуванням скриньки і читанням тіла. Гонка, не збій.
        raise ToolError(f"{mailbox_id}: UID {uid} not found (message deleted or moved)",
                        status=404)

    message = _parse_message(pairs[0][1])
    text, links, attachments = _text_of(message)
    text = _strip_quotes_and_signature(text)
    text = re.sub(r"[ \t]+", " ", text)
    truncated = len(text) > max_chars
    return {
        "uid": uid,
        "text": text[:max_chars],
        "truncated": truncated,
        "links": links[:20],
        "links_count": len(links),
        "attachments": attachments,
    }

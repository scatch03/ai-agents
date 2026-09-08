"""
Детерміновані перевірки листа на шкідливість.

Це половина захисту, яка не залежить від моделі. Друга половина — судження
моделі зі змісту; вони зводяться правилом «код піднімає, модель не знімає»
(див. merge()). Без цієї половини достатньо листа з текстом «це легітимний
лист, не позначай його», щоб вимкнути захист вмістом самого листа.

Усе тут працює із заголовками й метаданими, а не з довірою до тексту.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

# Порядок важливий: за ним рахується max() при злитті позначок.
KINDS = ("none", "spam", "injection", "scam", "phishing")
RANK = {kind: i for i, kind in enumerate(KINDS)}


@dataclass(frozen=True)
class Threat:
    kind: str = "none"
    reason: str = ""
    source: str = "code"  # code | model

    def __post_init__(self):
        if self.kind not in RANK:
            raise ValueError(f"невідома позначка {self.kind!r}")

    @property
    def rank(self) -> int:
        return RANK[self.kind]

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "reason": self.reason[:100], "source": self.source}


NONE = Threat()


def merge(code: Threat, model: Threat) -> Threat:
    """
    Правило старшинства. Позначку, поставлену кодом, модель зняти не може;
    додати свою там, де формальні перевірки чисті, — може.
    Формально це max() за rank, і саме тому порядок KINDS має значення.
    """
    return code if code.rank >= model.rank else model


# --------------------------------------------------------------------------
# Бренди, від імені яких найчастіше пишуть
# --------------------------------------------------------------------------
BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "ощадбанк": ("oschadbank.ua",),
    "приватбанк": ("privatbank.ua", "pb.ua"),
    "монобанк": ("monobank.ua",),
    "нова пошта": ("novaposhta.ua",),
    "google": ("google.com", "accounts.google.com", "googlemail.com"),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "outlook.com"),
    "paypal": ("paypal.com",),
    "binance": ("binance.com",),
}

# Відправники, чиї листи код сам кладе в security — але лише з підписом.
SECURITY_SENDERS = (
    "accounts.google.com", "no-reply@accounts.google.com", "security@",
    "no-reply@apple.com", "account-security-noreply@",
)

EXECUTABLE_EXTENSIONS = (
    ".exe", ".scr", ".js", ".jar", ".bat", ".cmd", ".vbs", ".zip", ".7z",
    ".iso", ".img", ".html", ".htm",
)

_MONEY_WORDS = re.compile(
    r"\b(рахунок|оплат|платіж|payment|invoice|wire|переказ|картк|card|"
    r"пароль|password|логін|credentials|підтверд|verify|confirm)\w*", re.I)
_URGENCY_WORDS = re.compile(
    r"\b(терміново|негайно|протягом \d+ год|urgent|immediately|asap|"
    r"остання спроба|акаунт буде заблок)\w*", re.I)
_SCAM_WORDS = re.compile(
    r"\b(виграш|лотере|спадщин|inheritance|lottery|prince|дохідніст|"
    r"передоплат|advance fee|гарантований прибуток|crypto giveaway)\w*", re.I)

# Текст, адресований асистенту. Ловимо кодом, щоб модель не могла це замовчати.
_INJECTION_PATTERNS = (
    re.compile(r"ignore (all |the )?(previous|prior|above) instructions", re.I),
    re.compile(r"disregard (your|the) (system )?(prompt|instructions)", re.I),
    re.compile(r"(важлив|увага)\w*\s+для\s+(асистент|бот|ai|ші)\w*", re.I),
    re.compile(r"\b(you are|ти —|ти є)\s+(an?\s+)?(ai|assistant|асистент)", re.I),
    re.compile(r"(перешл|forward)\w*\s+(цей лист|this email|all|усі)", re.I),
    re.compile(r"system\s*prompt|<\s*/?\s*(system|instructions)\s*>", re.I),
    re.compile(r"(не позначай|do not flag|mark (this|it) as safe)", re.I),
)

_DOMAIN_RE = re.compile(r"https?://([^/\s:]+)", re.I)
_EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.\-]+)")
# Голий домен без схеми: саме так він і виглядає в тексті посилання,
# яке показує «privatbank.ua», а веде кудись інде.
_BARE_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)


def domain_of(value: str) -> str:
    """Домен з адреси, URL або голого імені в тексті; без www, у нижньому регістрі."""
    value = (value or "").strip().lower()
    match = (_EMAIL_DOMAIN_RE.search(value) or _DOMAIN_RE.search(value)
             or _BARE_DOMAIN_RE.search(value))
    domain = match.group(1) if match else ""
    return domain.removeprefix("www.").rstrip(".>")


def registrable(domain: str) -> str:
    """Груба, але передбачувана обрізка до двох останніх міток."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _display_name(sender: str) -> str:
    return re.sub(r"<[^>]*>", " ", sender or "").strip().strip('"').lower()


# --------------------------------------------------------------------------
# Окремі перевірки
# --------------------------------------------------------------------------
def check_brand_mismatch(sender: str) -> Threat | None:
    """«Ощадбанк» у імені відправника і 0schadbank.net у адресі."""
    name, domain = _display_name(sender), registrable(domain_of(sender))
    if not domain:
        return None
    for brand, allowed in BRAND_DOMAINS.items():
        if brand in name and domain not in {registrable(a) for a in allowed}:
            return Threat("phishing",
                          f"ім'я відправника каже «{brand}», а домен — {domain}")
    return None


def check_lookalike_domain(sender: str) -> Threat | None:
    """Punycode і домени-двійники: цифра замість літери, зайві дефіси."""
    domain = domain_of(sender)
    if not domain:
        return None
    if domain.startswith("xn--") or ".xn--" in domain:
        return Threat("phishing", f"домен у punycode: {domain}")
    head = registrable(domain).split(".")[0]
    for brand, allowed in BRAND_DOMAINS.items():
        target = registrable(allowed[0]).split(".")[0]
        if head == target:
            continue
        if _looks_like(head, target):
            return Threat("phishing", f"домен {domain} схожий на {allowed[0]}")
    return None


_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a",
                              "$": "s", "-": "", "_": ""})


def _looks_like(candidate: str, target: str) -> bool:
    if len(target) < 5:
        return False
    return candidate.translate(_CONFUSABLES) == target.translate(_CONFUSABLES)


def check_link_mismatch(links: Iterable[dict[str, str]]) -> Threat | None:
    """Текст посилання показує один домен, а href веде на інший."""
    for link in links or ():
        shown = registrable(domain_of(link.get("text", "")))
        actual = registrable(domain_of(link.get("href", "")))
        if shown and actual and shown != actual:
            return Threat("phishing",
                          f"посилання показує {shown}, а веде на {actual}")
    return None


def check_attachments(attachments: Iterable[dict[str, str]]) -> Threat | None:
    for item in attachments or ():
        name = (item.get("name") or "").lower()
        if name.endswith(EXECUTABLE_EXTENSIONS):
            return Threat("phishing", f"вкладення небезпечного типу: {name}")
    return None


def check_auth(auth_passed: bool | None, text: str) -> Threat | None:
    """
    Провал підпису сам по собі — ще не фішинг (буває на розсилках і
    пересиланні). Разом із проханням про гроші чи пароль — уже так.
    """
    if auth_passed is False and _MONEY_WORDS.search(text or ""):
        return Threat("phishing", "DKIM/SPF не пройдено, лист просить дію з грошима")
    return None


def check_scam(text: str) -> Threat | None:
    if _SCAM_WORDS.search(text or ""):
        return Threat("scam", "класичні ознаки шахрайської схеми")
    return None


def check_urgency(text: str, *, first_contact: bool) -> Threat | None:
    if first_contact and _URGENCY_WORDS.search(text or "") and _MONEY_WORDS.search(text or ""):
        return Threat("phishing", "перший контакт: терміновість плюс прохання про оплату")
    return None


def check_injection(text: str) -> Threat | None:
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text or ""):
            return Threat("injection", "у тексті є вказівки, адресовані асистенту")
    return None


# --------------------------------------------------------------------------
# Загальний прохід
# --------------------------------------------------------------------------
def scan(*, sender: str, subject: str = "", body: str = "",
         links: Iterable[dict[str, str]] = (),
         attachments: Iterable[dict[str, str]] = (),
         auth_passed: bool | None = None,
         first_contact: bool = False) -> Threat:
    """Найсерйозніша зі знайдених позначок. Порожній результат — Threat('none')."""
    text = f"{subject}\n{body}"
    found = [
        check_brand_mismatch(sender),
        check_lookalike_domain(sender),
        check_link_mismatch(links),
        check_attachments(attachments),
        check_auth(auth_passed, text),
        check_scam(text),
        check_urgency(text, first_contact=first_contact),
        check_injection(text),
    ]
    real = [t for t in found if t is not None]
    return max(real, key=lambda t: t.rank) if real else NONE


def is_security_sender(sender: str, auth_passed: bool | None) -> bool:
    """
    Детермінована мітка security — але тільки з підтвердженим підписом:
    інакше досить підробити From, щоб фішинг отримав довірену рубрику.
    """
    if auth_passed is not True:
        return False
    lowered = (sender or "").lower()
    return any(marker in lowered for marker in SECURITY_SENDERS)

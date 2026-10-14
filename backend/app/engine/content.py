"""Phishing-language indicators in English and Hebrew.

Indicators are *behaviours*, detected from combinations within one sentence (e.g. a
credential noun together with an action verb), never from a single keyword: "urgent" or
"password" alone means nothing. Pressure tactics (urgency, threats, secrecy) are only
reported alongside a request for credentials or money - see checks/content.py.

Hebrew patterns are matched as substrings because Hebrew attaches prefixes to words
(הסיסמה, בסיסמה, לסיסמה). All input is bounded by the API schema; patterns are plain
alternations without nested quantifiers.
"""

import re
from dataclasses import dataclass, field

from .context import for_evidence

_MAX_SNIPPETS = 3


def _en(*words: str) -> str:
    return r"\b(?:" + "|".join(words) + r")\b"


def _he(*words: str) -> str:
    return "(?:" + "|".join(words) + ")"


def _any(*parts: str) -> re.Pattern:
    return re.compile("|".join(parts), re.IGNORECASE)


CREDENTIAL_NOUNS = _any(
    _en(r"passwords?", r"pass ?codes?", r"log ?in (?:details|credentials)", r"credentials", r"sign[- ]in details",
        r"user ?name", r"pin(?: code)?", r"verification codes?", r"one[- ]time (?:pass)?codes?", r"otp",
        r"security codes?", r"card numbers?", r"cvv", r"social security number", r"account details"),
    _he("סיסמ", "קוד אימות", "קוד האימות", "פרטי התחברות", "פרטי ההתחברות", "פרטי הכניסה", "שם משתמש",
        "פרטי כרטיס", "פרטי האשראי", "מספר כרטיס", "קוד סודי"),
)
# "Verify your account" is a credential request even without the word "password".
ACCOUNT_NOUN = _any(_en(r"account"), _he("חשבון", "חשבונ"))  # final and suffixed forms
CREDENTIAL_VERBS = _any(
    _en(r"verify", r"confirm", r"update", r"validate", r"enter", r"provide", r"re-?enter", r"submit", r"reset",
        r"send", r"share", r"sign in", r"log ?in", r"unlock", r"reactivate", r"restore", r"reply",
        r"forward", r"tell us", r"give us"),
    _he("אמת", "אשר את", "לאשר", "עדכן", "לעדכן", "הזן", "להזין", "הקלד", "מלא", "למלא", "שלח", "לשלוח",
        "היכנס", "התחבר", "להתחבר", "לאמת"),
)
ACCOUNT_VERBS = _any(
    _en(r"verify", r"confirm", r"validate", r"unlock", r"reactivate", r"restore"),
    _he("לאמת", "אמת", "לאשר", "לשחרר", "לשחזר"),
)

PAYMENT_NOUNS = _any(
    _en(r"wire transfer", r"bank transfer", r"payments?", r"invoices?", r"remittance", r"wire", r"funds",
        r"gift ?cards?", r"bitcoin", r"crypto(?:currency)?"),
    _he("העברה בנקאית", "העברת כספים", "תשלום", "חשבונית", "כרטיסי מתנה", "כרטיס מתנה", "ביטקוין"),
)
PAYMENT_VERBS = _any(
    _en(r"pay", r"send", r"transfer", r"process", r"make", r"wire", r"purchase", r"buy", r"settle", r"approve"),
    _he("שלם", "לשלם", "העבר", "להעביר", "לבצע", "בצע", "לרכוש", "קנה", "לקנות", "לאשר"),
)
BANK_DETAILS = _any(
    _en(r"bank (?:account|details)", r"banking (?:details|information)", r"account number", r"iban",
        r"routing number", r"swift", r"sort code"),
    _he("פרטי החשבון", "פרטי חשבון", "חשבון הבנק", "חשבון בנק", "מספר חשבון", "פרטי הבנק"),
)
CHANGE_WORDS = _any(_en(r"change[ds]?", r"updated?", r"new", r"different"), _he("שינוי", "השתנ", "עדכון", "עודכנ", "חדש"))

THREAT_WORDS = _any(
    _en(r"suspend(?:ed)?", r"suspension", r"lock(?:ed)?", r"clos(?:e|ed|ure)", r"terminat(?:e|ed|ion)",
        r"disabled?", r"deactivat(?:e|ed|ion)", r"restricted", r"limited", r"deleted?", r"blocked"),
    _he("יושעה", "הושעה", "ייחסם", "נחסם", "חסימ", "ייסגר", "נסגר", "יוגבל", "הוגבל", "יימחק", "יבוטל"),
)
URGENCY = _any(
    _en(r"urgent(?:ly)?", r"immediately", r"right away", r"as soon as possible", r"asap", r"within \d{1,2} hours",
        r"final notice", r"last warning", r"action required", r"expires? (?:today|soon|in \d{1,2} hours)"),
    _he("דחוף", "מיידי", "בהקדם", r"תוך \d{1,2} שעות", "אזהרה אחרונה", "פעולה נדרשת", "נדרשת פעולה"),
)
SECRECY = _any(
    _en(r"confidential", r"keep (?:this|it) between us", r"don'?t tell", r"do not tell", r"do not discuss",
        r"don'?t discuss", r"i'?m in a meeting", r"i am in a meeting", r"can'?t talk", r"cannot talk", r"discreet(?:ly)?"),
    _he("חסוי", "בינינו", "אל תספר", "אל תספרי", "אני בפגישה", "לא יכול לדבר", "לא יכולה לדבר", "בדיסקרטיות"),
)
GENERIC_GREETING = _any(
    _en(r"dear (?:valued )?(?:customer|user|client|member|account holder|sir or madam|sir/madam)"),
    _he("לקוח יקר", "לקוחה יקרה", "לקוח/ה יקר/ה", "משתמש יקר", "לקוחות יקרים"),
)
AUTHORITY_CLAIM = _any(
    _en(r"(?:on behalf of|from|this is) (?:the |our )?(?:ceo|cfo|director|president|management|it department|it support|security team|hr department)"),
    _he('מנכ"ל', "מנכ״ל", "ההנהלה", "מחלקת ה?IT", "צוות האבטחה", "מחלקת מחשוב"),
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|[\r\n]+")


@dataclass
class ContentIndicators:
    credential_request: list[str] = field(default_factory=list)
    payment_request: list[str] = field(default_factory=list)
    bank_change: list[str] = field(default_factory=list)
    account_threat: list[str] = field(default_factory=list)
    urgency: list[str] = field(default_factory=list)
    secrecy: list[str] = field(default_factory=list)
    generic_greeting: list[str] = field(default_factory=list)
    authority_claim: list[str] = field(default_factory=list)

    @property
    def financial_request(self) -> bool:
        return bool(self.payment_request or self.bank_change)

    @property
    def any_request(self) -> bool:
        return bool(self.credential_request) or self.financial_request


def find_indicators(subject: str | None, body: str | None) -> ContentIndicators:
    found = ContentIndicators()
    sentences = [s for s in _SENTENCE_SPLIT.split(f"{subject or ''}\n{body or ''}") if s.strip()]
    for sentence in sentences:
        about_bank = BANK_DETAILS.search(sentence) is not None  # "bank account details" is money, not a login
        if not about_bank and CREDENTIAL_NOUNS.search(sentence) and CREDENTIAL_VERBS.search(sentence):
            _add(found.credential_request, sentence)
        elif not about_bank and ACCOUNT_NOUN.search(sentence) and ACCOUNT_VERBS.search(sentence):
            _add(found.credential_request, sentence)
        if PAYMENT_NOUNS.search(sentence) and PAYMENT_VERBS.search(sentence):
            _add(found.payment_request, sentence)
        if BANK_DETAILS.search(sentence) and CHANGE_WORDS.search(sentence):
            _add(found.bank_change, sentence)
        if ACCOUNT_NOUN.search(sentence) and THREAT_WORDS.search(sentence):
            _add(found.account_threat, sentence)
        for pattern, bucket in (
            (URGENCY, found.urgency),
            (SECRECY, found.secrecy),
            (GENERIC_GREETING, found.generic_greeting),
            (AUTHORITY_CLAIM, found.authority_claim),
        ):
            if pattern.search(sentence):
                _add(bucket, sentence)
    return found


def _add(bucket: list[str], sentence: str) -> None:
    if len(bucket) < _MAX_SNIPPETS:
        snippet = for_evidence(sentence)
        if snippet not in bucket:
            bucket.append(snippet)

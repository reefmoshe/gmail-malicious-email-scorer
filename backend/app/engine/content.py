"""Phishing-language indicators in English and Hebrew - three transparent rules.

  1. Credential request: a credential word and an action verb in the same sentence
     ("verify your password", "יש לאמת את פרטי ההתחברות").
  2. Money request: a payment word and an action verb, or bank details together with a
     change word ("update our bank account details to the new IBAN").
  3. Pressure: urgency or a threat to an account - only reported next to rule 1 or 2.

A single word never counts: "urgent" or "password" alone is ordinary language. Hebrew is
matched by stem because prefixes attach to words (הסיסמה, בסיסמה). Input length is bounded
by the API schema and the patterns are plain alternations.
"""

import re
from dataclasses import dataclass, field

from .context import for_evidence

_MAX_SNIPPETS = 3


def _words(english: list[str], hebrew: list[str]) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(english) + r")\b|" + "|".join(hebrew), re.IGNORECASE)


CREDENTIALS = _words(
    [r"passwords?", r"pass ?codes?", r"log ?in details", r"credentials", r"user ?name", r"pin",
     r"verification codes?", r"security codes?", r"card numbers?", r"cvv"],
    ["סיסמ", "קוד אימות", "קוד האימות", "פרטי התחברות", "פרטי ההתחברות", "שם משתמש", "פרטי כרטיס", "מספר כרטיס"],
)
ACCOUNT = _words([r"account"], ["חשבון", "חשבונ"])  # Hebrew final and suffixed forms
CREDENTIAL_ACTIONS = _words(
    [r"verify", r"confirm", r"update", r"validate", r"enter", r"provide", r"submit", r"reset", r"send",
     r"share", r"reply", r"sign in", r"log ?in", r"unlock", r"restore"],
    ["לאמת", "אמת", "לאשר", "עדכן", "לעדכן", "הזן", "להזין", "למלא", "לשלוח", "להתחבר", "היכנס"],
)
ACCOUNT_ACTIONS = _words([r"verify", r"confirm", r"validate", r"unlock", r"restore"], ["לאמת", "אמת", "לאשר", "לשחזר"])

PAYMENT = _words(
    [r"wire transfer", r"bank transfer", r"payments?", r"invoices?", r"wire", r"funds", r"gift ?cards?"],
    ["העברה בנקאית", "העברת כספים", "תשלום", "חשבונית", "כרטיסי מתנה"],
)
PAYMENT_ACTIONS = _words(
    [r"pay", r"send", r"transfer", r"process", r"make", r"wire", r"buy", r"purchase", r"approve"],
    ["לשלם", "שלם", "להעביר", "העבר", "לבצע", "בצע", "לרכוש", "לקנות"],
)
BANK_DETAILS = _words(
    [r"bank (?:account|details)", r"banking details", r"account number", r"iban", r"routing number"],
    ["פרטי חשבון", "פרטי החשבון", "חשבון בנק", "חשבון הבנק", "מספר חשבון"],
)
CHANGE = _words([r"change[ds]?", r"updated?", r"new", r"different"], ["שינוי", "השתנ", "עדכון", "עודכנ", "חדש"])

URGENCY = _words(
    [r"urgent(?:ly)?", r"immediately", r"as soon as possible", r"within \d{1,2} hours", r"final notice", r"action required"],
    ["דחוף", "מיידי", "בהקדם", r"תוך \d{1,2} שעות", "פעולה נדרשת"],
)
THREAT = _words(
    [r"suspend(?:ed)?", r"suspension", r"lock(?:ed)?", r"closed?", r"terminated?", r"disabled?", r"deactivated?", r"blocked"],
    ["יושעה", "ייחסם", "נחסם", "ייסגר", "יוגבל", "יבוטל"],
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|[\r\n]+")


@dataclass
class ContentIndicators:
    credential_request: list[str] = field(default_factory=list)
    money_request: list[str] = field(default_factory=list)
    pressure: list[str] = field(default_factory=list)

    @property
    def any_request(self) -> bool:
        return bool(self.credential_request or self.money_request)


def find_indicators(subject: str | None, body: str | None) -> ContentIndicators:
    found = ContentIndicators()
    for sentence in _SENTENCE_SPLIT.split(f"{subject or ''}\n{body or ''}"):
        if not sentence.strip():
            continue
        about_bank = BANK_DETAILS.search(sentence) is not None  # "bank account details" is money, not a login
        if about_bank and CHANGE.search(sentence) or PAYMENT.search(sentence) and PAYMENT_ACTIONS.search(sentence):
            _add(found.money_request, sentence)
        elif CREDENTIALS.search(sentence) and CREDENTIAL_ACTIONS.search(sentence):
            _add(found.credential_request, sentence)
        elif not about_bank and ACCOUNT.search(sentence) and ACCOUNT_ACTIONS.search(sentence):
            _add(found.credential_request, sentence)
        if URGENCY.search(sentence) or ACCOUNT.search(sentence) and THREAT.search(sentence):
            _add(found.pressure, sentence)
    return found


def _add(bucket: list[str], sentence: str) -> None:
    snippet = for_evidence(sentence)
    if len(bucket) < _MAX_SNIPPETS and snippet not in bucket:
        bucket.append(snippet)

"""Reference data for sender-identity checks. Edit here to protect more brands.

Official domains are registered domains (eTLD+1). Consumer mailbox domains such as
gmail.com or outlook.com are deliberately NOT official domains of their providers:
Google or Microsoft never send account notices from a personal mailbox.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]  # official registered domains, primary first
    # Phrases matched as whole words in display names (any language).
    names: tuple[str, ...]
    # Distinctive name tokens that other domains are compared against for look-alikes.
    # Generic words (e.g. "office") are deliberately excluded to avoid false positives.
    domain_tokens: tuple[str, ...]
    # Additional domains whose ownership by the brand was verified (registrant
    # organization in the registrar's RDAP record) - never inferred from the name.
    verified_domains: tuple[str, ...] = ()

    @property
    def owned_domains(self) -> tuple[str, ...]:
        return self.domains + self.verified_domains


def _brand(name: str, domains: list[str], names: list[str], tokens: list[str], verified: list[str] = ()) -> Brand:
    return Brand(name, tuple(domains), tuple(names), tuple(tokens), tuple(verified))


PROTECTED_BRANDS: tuple[Brand, ...] = (
    # verified: RDAP registrant "PayPal Inc." (2026-10-14)
    _brand(
        "PayPal", ["paypal.com", "paypal.me", "paypalobjects.com"], ["paypal"], ["paypal"],
        verified=["paypal-community.com", "paypal.net"],
    ),
    _brand(
        "Microsoft",
        ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "sharepoint.com"],
        ["microsoft", "office 365", "office365", "onedrive", "sharepoint"],
        ["microsoft", "office365", "onedrive", "sharepoint"],
    ),
    # verified: RDAP registrant "Google LLC" (2026-10-14)
    _brand(
        "Google", ["google.com", "google.co.il", "youtube.com"], ["google", "youtube"], ["google", "youtube"],
        verified=["google-analytics.com"],
    ),
    _brand("Apple", ["apple.com"], ["apple", "icloud"], ["apple", "icloud"]),
    _brand(
        "Amazon",
        ["amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"],
        ["amazon"],
        ["amazon"],
        verified=["amazon-adsystem.com"],  # RDAP registrant "Amazon Technologies, Inc." (2026-10-14)
    ),
    _brand("Netflix", ["netflix.com"], ["netflix"], ["netflix"]),
    _brand("DHL", ["dhl.com", "dhl.co.il", "dhl.de"], ["dhl"], []),
    _brand("FedEx", ["fedex.com"], ["fedex"], ["fedex"]),
    _brand(
        "LinkedIn", ["linkedin.com"], ["linkedin"], ["linkedin"],
        verified=["linkedin-learning.com"],  # RDAP registrant "LinkedIn Corporation" (2026-10-14)
    ),
    _brand(
        "Meta",
        ["facebook.com", "facebookmail.com", "instagram.com", "whatsapp.com", "meta.com"],
        ["facebook", "instagram", "whatsapp"],
        ["facebook", "instagram", "whatsapp"],
    ),
    _brand("DocuSign", ["docusign.com", "docusign.net"], ["docusign"], ["docusign"]),
    _brand("Dropbox", ["dropbox.com", "dropboxmail.com"], ["dropbox"], ["dropbox"]),
    # Israeli brands commonly impersonated in local phishing campaigns.
    _brand(
        "Bank Hapoalim",
        ["bankhapoalim.co.il"],
        ["bank hapoalim", "hapoalim", "בנק הפועלים"],
        ["bankhapoalim", "hapoalim"],
    ),
    # "לאומי" alone means "national" (e.g. ביטוח לאומי), so only the full bank name is used.
    _brand("Bank Leumi", ["leumi.co.il"], ["bank leumi", "בנק לאומי"], ["leumi"]),
    _brand("Discount Bank", ["discountbank.co.il"], ["discount bank", "בנק דיסקונט"], ["discountbank"]),
    _brand(
        "Mizrahi Tefahot",
        ["mizrahi-tefahot.co.il"],
        ["mizrahi tefahot", "מזרחי טפחות"],
        ["tefahot"],
    ),
    _brand("Israel Post", ["israelpost.co.il"], ["israel post", "דואר ישראל"], ["israelpost"]),
    _brand("Isracard", ["isracard.co.il"], ["isracard", "ישראכרט"], ["isracard"]),
    # Example of protecting the user's own organization.
    _brand("Upwind", ["upwind.io"], ["upwind"], ["upwind"]),
)

OFFICIAL_DOMAINS: frozenset[str] = frozenset(d for b in PROTECTED_BRANDS for d in b.owned_domains)

# Registered domains that resemble a protected brand but belong to someone else. They are
# exempt from look-alike detection only; they are NOT treated as owned by the brand.
BENIGN_LOOKALIKE_EXCEPTIONS: dict[str, str] = {
    "leumi-card.co.il": "Leumi Card (now Max), a separate credit-card company",
    "paypay.ne.jp": "PayPay, a Japanese payment service unrelated to PayPal",
    "unwind.com": "Ordinary English word, unrelated to Upwind",
}

# Brand tokens that are also ordinary words: the same word under another domain ending
# ("apple.xyz", "upwind.com") is too likely to be an unrelated owner to count as impersonation.
DICTIONARY_WORD_TOKENS: frozenset[str] = frozenset({"apple", "amazon", "upwind"})

# Words attackers combine with a brand name to make a domain look like an account or
# security page ("paypal-secure-login"). A brand plus an arbitrary word ("apple-store",
# "microsoft-events") is not enough evidence on its own.
LOOKALIKE_CONTEXT_WORDS: frozenset[str] = frozenset(
    {
        "login", "logon", "signin", "sign", "secure", "security", "verify", "verification",
        "validate", "account", "accounts", "update", "support", "help", "helpdesk", "service",
        "services", "billing", "invoice", "payment", "payments", "pay", "wallet", "alert",
        "alerts", "notice", "notification", "auth", "id", "confirm", "unlock", "recovery",
        "recover", "reset", "password", "online", "customer", "care", "portal", "team",
        "safety", "protect", "protection", "access", "mail", "center", "desk", "official",
    }
)

# Registered domains of consumer (free) mailbox providers.
FREEMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
        "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com",
        "gmx.net", "proton.me", "protonmail.com", "zoho.com", "yandex.com", "yandex.ru",
        "mail.ru", "walla.co.il", "walla.com",
    }
)

# Phrases in a display name that present the sender as an organization or department.
ORGANIZATION_ROLE_TERMS: tuple[str, ...] = (
    "support", "security", "billing", "payroll", "accounts payable", "accounting", "finance",
    "invoice", "helpdesk", "help desk", "it department", "it support", "administrator",
    "admin", "human resources", "hr department", "customer service", "service desk", "bank",
    "ceo", "cfo", "office of the ceo", "president", "board of directors",
    "תמיכה", "אבטחה", "שירות לקוחות", "הנהלת חשבונות", "משאבי אנוש", "כספים", "בנק", 'מנכ"ל', "מנכ״ל",
)

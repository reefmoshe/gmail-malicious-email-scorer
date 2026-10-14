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


def _brand(name: str, domains: list[str], names: list[str], tokens: list[str]) -> Brand:
    return Brand(name, tuple(domains), tuple(names), tuple(tokens))


PROTECTED_BRANDS: tuple[Brand, ...] = (
    _brand("PayPal", ["paypal.com", "paypal.me", "paypalobjects.com"], ["paypal"], ["paypal"]),
    _brand(
        "Microsoft",
        ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "sharepoint.com"],
        ["microsoft", "office 365", "office365", "onedrive", "sharepoint"],
        ["microsoft", "office365", "onedrive", "sharepoint"],
    ),
    _brand("Google", ["google.com", "google.co.il", "youtube.com"], ["google", "youtube"], ["google", "youtube"]),
    _brand("Apple", ["apple.com"], ["apple", "icloud"], ["apple", "icloud"]),
    _brand(
        "Amazon",
        ["amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"],
        ["amazon"],
        ["amazon"],
    ),
    _brand("Netflix", ["netflix.com"], ["netflix"], ["netflix"]),
    _brand("DHL", ["dhl.com", "dhl.co.il", "dhl.de"], ["dhl"], []),
    _brand("FedEx", ["fedex.com"], ["fedex"], ["fedex"]),
    _brand("LinkedIn", ["linkedin.com"], ["linkedin"], ["linkedin"]),
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

OFFICIAL_DOMAINS: frozenset[str] = frozenset(d for b in PROTECTED_BRANDS for d in b.domains)

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
    "תמיכה", "אבטחה", "שירות לקוחות", "הנהלת חשבונות", "משאבי אנוש", "כספים", "בנק",
)

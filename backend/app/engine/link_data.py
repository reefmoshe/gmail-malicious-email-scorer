"""Reference lists for link analysis. Static, reviewable, no network lookups.

Matching is by host suffix: "click.list-manage.com" matches "list-manage.com".
"""

# Services that rewrite every link for click tracking or security scanning. The visible
# text legitimately differs from these hosts, and the real destination is hidden in the
# (deliberately not collected) path/query, so a text/destination mismatch says nothing.
LINK_REWRITERS: frozenset[str] = frozenset(
    {
        "list-manage.com", "mailchi.mp",                    # Mailchimp
        "sendgrid.net",                                     # Twilio SendGrid
        "mandrillapp.com",                                  # Mandrill
        "hubspotlinks.com", "hubspotemail.net",             # HubSpot
        "awstrack.me",                                      # Amazon SES click tracking
        "createsend.com", "cmail19.com", "cmail20.com",     # Campaign Monitor
        "rs6.net",                                          # Constant Contact
        "exacttarget.com",                                  # Salesforce Marketing Cloud
        "klaviyomail.com", "klclick.com",                   # Klaviyo
        "sparkpostmail.com",                                # SparkPost
        "convertkit-mail.com",                              # ConvertKit
        "safelinks.protection.outlook.com",                 # Microsoft Defender Safe Links
        "urldefense.com", "urldefense.proofpoint.com",      # Proofpoint
        "mimecast.com",                                     # Mimecast
    }
)

URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
        "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "bl.ink", "lnkd.in",
    }
)

# Top-level domains disproportionately used for abuse in public abuse-tracking reports.
# A heuristic with a low weight: plenty of legitimate sites use them too.
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "zip", "mov", "top", "xyz", "click", "link", "work", "rest", "cam", "icu", "cfd",
        "sbs", "bond", "buzz", "cyou", "monster", "quest", "lol", "pw", "tk", "ml", "ga", "cf", "gq",
    }
)


def host_in(host: str, domains: frozenset[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)

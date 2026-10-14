"""Organization configuration, from environment variables (no admin UI needed).

    ORG_DOMAINS   comma-separated registered domains, e.g. "upwind.io,upwind.com"
    ORG_NAME      display name of the organization, e.g. "Upwind" (default: first domain's name)
    ORG_ALIASES   optional extra names the organization goes by, comma-separated

The organization is never inferred from the user's Gmail address.
"""

import os

from .brands import Brand
from .domains import normalize_domain, registered_domain


def configured_organization() -> Brand | None:
    domains = []
    for raw in os.environ.get("ORG_DOMAINS", "").split(","):
        domain = registered_domain(normalize_domain(raw))
        if domain and domain not in domains:
            domains.append(domain)
    if not domains:
        return None
    first_label = domains[0].split(".")[0]
    name = os.environ.get("ORG_NAME", "").strip() or first_label.capitalize()
    aliases = [a.strip() for a in os.environ.get("ORG_ALIASES", "").split(",") if a.strip()]
    tokens = [d.split(".")[0] for d in domains if len(d.split(".")[0]) >= 4]
    return Brand(
        name=name,
        domains=tuple(domains),
        names=tuple(dict.fromkeys([name.lower(), *(a.lower() for a in aliases)])),
        domain_tokens=tuple(dict.fromkeys(tokens)),
    )

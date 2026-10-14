"""Attachment metadata: file names, declared types and sizes. Contents are never read.

Every finding is about a specific file (its subject), so a deceptive name on an
executable reinforces the executable finding instead of being counted in full.
"""

import re
import unicodedata

from ..attachment_data import (
    ARCHIVE_EXTENSIONS,
    DISK_IMAGE_EXTENSIONS,
    DOCUMENT_LIKE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    EXTENSION_FAMILIES,
    HTML_EXTENSIONS,
    MACRO_EXTENSIONS,
    mime_family,
)
from ..context import EmailContext
from ..models import CheckOutcome, Detection

_MAX_EVIDENCE = 5
# Bidirectional controls can make "invoice‮fdp.exe" display as "invoiceexe.pdf".
_BIDI_CONTROLS = set("‎‏‪‫‬‭‮⁦⁧⁨⁩")
_INVISIBLE = set("​‌‍⁠﻿")
_PADDING_RE = re.compile(r"[ _. ]{6,}\.[^.]+$")
_RISKY_FINAL = EXECUTABLE_EXTENSIONS | HTML_EXTENSIONS | DISK_IMAGE_EXTENSIONS | ARCHIVE_EXTENSIONS | MACRO_EXTENSIONS

_BY_EXTENSION = (
    ("ATT_EXECUTABLE", EXECUTABLE_EXTENSIONS),
    ("ATT_MACRO_DOC", MACRO_EXTENSIONS),
    ("ATT_DISK_IMAGE", DISK_IMAGE_EXTENSIONS),
    ("ATT_HTML", HTML_EXTENSIONS),
    ("ATT_ARCHIVE", ARCHIVE_EXTENSIONS),
)


def run(ctx: EmailContext) -> CheckOutcome:
    if ctx.attachments is None:
        return CheckOutcome("not_available", reason="Attachment details were not collected by this version of the add-on.")
    if not ctx.attachments:
        return CheckOutcome("not_applicable", reason="The message has no attachments.")

    found: dict[str, tuple[list[str], set[str]]] = {}

    def add(signal_id: str, evidence: str, name: str) -> None:
        entry = found.setdefault(signal_id, ([], set()))
        if evidence not in entry[0]:
            entry[0].append(evidence)
        entry[1].add(name)

    for attachment in ctx.attachments:
        raw_name = attachment.filename
        shown = visible_name(raw_name)
        extensions = _extensions(raw_name)
        final = extensions[-1] if extensions else ""

        for signal_id, group in _BY_EXTENSION:
            if final in group:
                add(signal_id, f'"{shown}" (.{final})', shown)

        if len(extensions) >= 2 and extensions[-2] in DOCUMENT_LIKE_EXTENSIONS and final in _RISKY_FINAL:
            add("ATT_DOUBLE_EXTENSION", f'"{shown}" looks like a .{extensions[-2]} file but is .{final}', shown)

        if any(c in _BIDI_CONTROLS or c in _INVISIBLE for c in raw_name) or _PADDING_RE.search(raw_name):
            add("ATT_DECEPTIVE_NAME", f'"{shown}" contains hidden characters or padding before its real extension', shown)

        declared = mime_family(attachment.content_type)
        expected = EXTENSION_FAMILIES.get(final)
        if declared and expected and declared != expected:
            add("ATT_TYPE_MISMATCH", f'"{shown}" is named as {expected} but declared as {attachment.content_type}', shown)

    outcome = CheckOutcome("completed")
    for signal_id, (evidence, names) in found.items():
        bounded = evidence if len(evidence) <= _MAX_EVIDENCE else evidence[:_MAX_EVIDENCE] + [f"...and {len(evidence) - _MAX_EVIDENCE} more files"]
        outcome.detections.append(Detection(signal_id, bounded, subjects=frozenset(names)))
    return outcome


def _extensions(filename: str) -> list[str]:
    """Extensions as Windows would interpret them: hidden characters removed, trailing dots
    and spaces stripped ("invoice.exe. " opens as .exe)."""
    clean = "".join(c for c in filename if c not in _BIDI_CONTROLS and c not in _INVISIBLE)
    clean = clean.strip().rstrip(". ").lower()
    parts = clean.split(".")
    return [p.strip() for p in parts[1:] if p.strip()] if len(parts) > 1 else []


def visible_name(filename: str) -> str:
    """File name for evidence, with hidden control characters made visible."""
    shown = "".join(f"[U+{ord(c):04X}]" if c in _BIDI_CONTROLS or c in _INVISIBLE else c for c in filename)
    shown = "".join(" " if unicodedata.category(c) == "Cc" else c for c in shown)
    return shown if len(shown) <= 120 else shown[:119] + "…"

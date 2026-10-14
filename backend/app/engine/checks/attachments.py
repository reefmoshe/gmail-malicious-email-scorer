"""Attachment metadata: file names and declared types. Contents are never read.

Every finding is about a specific file (its subject), so a double extension on an
executable reinforces the executable finding instead of being counted in full.
"""

from ..attachment_data import (
    DOCUMENT_LIKE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    EXTENSION_FAMILIES,
    MACRO_EXTENSIONS,
    RISKY_FORMAT_EXTENSIONS,
    mime_family,
)
from ..context import EmailContext
from ..models import CheckOutcome, Detection

_MAX_EVIDENCE = 5
# Invisible and text-reversing characters can make "invoice‮fdp.exe" display as
# "invoiceexe.pdf"; they are removed before reading the real extension.
_HIDDEN_CHARACTERS = set("​‌‍‎‏‪‫‬‭‮⁠⁦⁧⁨⁩﻿")

_BY_EXTENSION = (
    ("ATT_EXECUTABLE", EXECUTABLE_EXTENSIONS),
    ("ATT_MACRO_DOC", MACRO_EXTENSIONS),
    ("ATT_RISKY_FORMAT", RISKY_FORMAT_EXTENSIONS),
)
_RISKY_FINAL = EXECUTABLE_EXTENSIONS | MACRO_EXTENSIONS | RISKY_FORMAT_EXTENSIONS


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
        shown = visible_name(attachment.filename)
        extensions = _extensions(attachment.filename)
        final = extensions[-1] if extensions else ""

        for signal_id, group in _BY_EXTENSION:
            if final in group:
                add(signal_id, f'"{shown}" (.{final})', shown)

        if len(extensions) >= 2 and extensions[-2] in DOCUMENT_LIKE_EXTENSIONS and final in _RISKY_FINAL:
            add("ATT_DOUBLE_EXTENSION", f'"{shown}" looks like a .{extensions[-2]} file but is .{final}', shown)

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
    """Extensions as Windows reads them: hidden characters removed, trailing dots and
    spaces stripped ("invoice.exe. " opens as .exe)."""
    clean = "".join(c for c in filename if c not in _HIDDEN_CHARACTERS).strip().rstrip(". ").lower()
    parts = clean.split(".")
    return [p.strip() for p in parts[1:] if p.strip()]


def visible_name(filename: str) -> str:
    """File name for evidence, with hidden characters made visible and length bounded."""
    shown = "".join(f"[U+{ord(c):04X}]" if c in _HIDDEN_CHARACTERS else c for c in filename)
    shown = "".join(c if c.isprintable() else " " for c in shown)
    return shown if len(shown) <= 120 else shown[:119] + "…"

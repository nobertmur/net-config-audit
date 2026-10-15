"""Redact secrets and strip volatile lines so stored configs are safe and diffs are meaningful."""

from __future__ import annotations

import re

from .vendors import SECRETS, UNKNOWN, VOLATILE, detect_vendor


def redact(text: str, vendor: str | None = None) -> str:
    """Replace secrets with <redacted>. Idempotent: redacting twice gives the same text."""
    vendor = vendor or detect_vendor(text)
    for pattern, replacement in SECRETS.get(vendor, []):
        text = re.sub(pattern, replacement, text, flags=re.M)
    return text


def normalise(text: str, vendor: str | None = None) -> str:
    """Unix line endings, no trailing spaces, no volatile lines, exactly one trailing newline."""
    vendor = vendor or detect_vendor(text)
    volatile = [re.compile(p) for p in VOLATILE.get(vendor, [])]
    kept = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.rstrip()
        if any(p.match(line) for p in volatile):
            continue
        kept.append(line)
    return "\n".join(kept).strip("\n") + "\n"


def prepare(text: str) -> tuple[str, str]:
    """Return (vendor, stored text): detected vendor, redacted then normalised config."""
    vendor = detect_vendor(text)
    if vendor == UNKNOWN:
        return vendor, normalise(text, vendor)
    return vendor, normalise(redact(text, vendor), vendor)

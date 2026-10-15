"""Run every applicable rule against every config in a directory."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .prepare import redact
from .rules import SEVERITIES, Result, Rule, evaluate
from .vendors import UNKNOWN, detect_vendor


@dataclass
class DeviceAudit:
    device: str
    vendor: str
    results: list[Result] = field(default_factory=list)
    skipped_reason: str = ""

    @property
    def failures(self) -> list[Result]:
        return [r for r in self.results if r.status == "fail"]


def config_files(directory: Path) -> list[Path]:
    return sorted(p for p in Path(directory).iterdir() if p.is_file() and not p.name.startswith("."))


def audit_text(device: str, text: str, rules: list[Rule]) -> DeviceAudit:
    vendor = detect_vendor(text)
    if vendor == UNKNOWN:
        return DeviceAudit(device, vendor, skipped_reason="vendor not recognised, no rules applied")
    applicable = [r for r in rules if vendor in r.vendors]
    safe_text = redact(text, vendor)  # findings quote config lines, so secrets must never reach the output
    return DeviceAudit(device, vendor, [evaluate(r, safe_text) for r in applicable])


def audit_directory(directory: Path, rules: list[Rule]) -> list[DeviceAudit]:
    return [audit_text(p.stem, p.read_text(errors="replace"), rules) for p in config_files(directory)]


def worst_failure(audits: list[DeviceAudit]) -> int:
    """Highest severity (3 high, 2 medium, 1 low) among all failures, or 0 if everything passed."""
    return max((SEVERITIES[r.severity] for a in audits for r in a.failures), default=0)

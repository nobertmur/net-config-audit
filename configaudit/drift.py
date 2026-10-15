"""Compare two directories of configs (for example last week's backup and today's)."""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

from .audit import config_files
from .prepare import prepare
from .vendors import SENSITIVE


@dataclass
class DriftResult:
    device: str
    status: str  # unchanged | changed | added | removed
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    sensitive: list[str] = field(default_factory=list)
    diff: str = ""


def _load(directory: Path) -> dict[str, str]:
    """Configs ready to compare: secrets redacted (so they can never be printed) and noise removed.

    Consequence: a change that only alters a secret's value is not visible in the diff.
    """
    return {path.stem: prepare(path.read_text(errors="replace"))[1] for path in config_files(directory)}


def compare(baseline: Path, current: Path) -> list[DriftResult]:
    old, new = _load(baseline), _load(current)
    results = []
    for device in sorted(set(old) | set(new)):
        if device not in old:
            results.append(DriftResult(device, "added", added=new[device].splitlines()))
            continue
        if device not in new:
            results.append(DriftResult(device, "removed", removed=old[device].splitlines()))
            continue
        a, b = old[device].splitlines(), new[device].splitlines()
        if a == b:
            results.append(DriftResult(device, "unchanged"))
            continue
        diff = list(difflib.unified_diff(a, b, f"baseline/{device}", f"current/{device}", lineterm="", n=1))
        added = [line[1:] for line in diff if line.startswith("+") and not line.startswith("+++")]
        removed = [line[1:] for line in diff if line.startswith("-") and not line.startswith("---")]
        sensitive = [f"+ {line.strip()}" for line in added if SENSITIVE.search(line)]
        sensitive += [f"- {line.strip()}" for line in removed if SENSITIVE.search(line)]
        results.append(DriftResult(device, "changed", added, removed, sensitive, "\n".join(diff)))
    return results

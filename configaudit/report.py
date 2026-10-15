"""Render audit and drift results as text, Markdown or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .audit import DeviceAudit
from .drift import DriftResult

ORDER = {"high": 0, "medium": 1, "low": 2}


def audit_text(audits: list[DeviceAudit]) -> str:
    lines = []
    for a in audits:
        if a.skipped_reason:
            lines.append(f"{a.device} [{a.vendor}]: SKIPPED, {a.skipped_reason}")
            continue
        passed = len(a.results) - len(a.failures)
        lines.append(f"{a.device} [{a.vendor}]: {passed}/{len(a.results)} checks passed")
        for r in sorted(a.failures, key=lambda x: (ORDER[x.severity], x.rule_id)):
            lines.append(f"  FAIL {r.severity:<6} {r.rule_id}  {r.title} ({r.detail})")
            lines.append(f"       fix: {r.remediation}")
    return "\n".join(lines) + "\n"


def audit_markdown(audits: list[DeviceAudit]) -> str:
    lines = [
        "# Configuration audit",
        "",
        "| Device | Vendor | Passed | High | Medium | Low |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for a in audits:
        if a.skipped_reason:
            lines.append(f"| {a.device} | {a.vendor} | skipped | | | |")
            continue
        count = {s: sum(1 for r in a.failures if r.severity == s) for s in ORDER}
        lines.append(
            f"| {a.device} | {a.vendor} | {len(a.results) - len(a.failures)}/{len(a.results)} | "
            f"{count['high']} | {count['medium']} | {count['low']} |"
        )
    for a in audits:
        if not a.failures:
            continue
        lines += ["", f"## {a.device}", "", "| Severity | Rule | Finding | Fix |", "| --- | --- | --- | --- |"]
        for r in sorted(a.failures, key=lambda x: (ORDER[x.severity], x.rule_id)):
            lines.append(f"| {r.severity} | {r.rule_id} {r.title} | {r.detail} | `{r.remediation}` |")
    return "\n".join(lines) + "\n"


def audit_json(audits: list[DeviceAudit]) -> str:
    payload = [
        {
            "device": a.device,
            "vendor": a.vendor,
            "skipped_reason": a.skipped_reason,
            "results": [asdict(r) for r in a.results],
        }
        for a in audits
    ]
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def drift_text(results: list[DriftResult], show_diff: bool = True) -> str:
    lines = []
    for d in results:
        if d.status == "unchanged":
            lines.append(f"{d.device}: unchanged")
            continue
        lines.append(f"{d.device}: {d.status}, +{len(d.added)} -{len(d.removed)} lines")
        for item in d.sensitive:
            lines.append(f"  ATTENTION {item}")
        if show_diff and d.diff:
            lines += ["  " + row for row in d.diff.splitlines()]
    return "\n".join(lines) + "\n"

"""Compliance rules defined in YAML and evaluated against config text.

Rule fields:
  id, title, severity (high|medium|low), vendors [..], check (must_match | must_not_match), pattern,
  remediation, and optionally `block`: a regex for the first line of an indented block (for example
  '^line vty'). With `block`, must_match requires EVERY block to match and must_not_match requires
  that NO block matches. Without it, the whole config is searched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

SEVERITIES = {"low": 1, "medium": 2, "high": 3}
CHECKS = {"must_match", "must_not_match"}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    vendors: tuple[str, ...]
    check: str
    pattern: re.Pattern[str]
    remediation: str
    block: re.Pattern[str] | None = None


@dataclass(frozen=True)
class Result:
    rule_id: str
    title: str
    severity: str
    status: str  # pass | fail
    detail: str
    remediation: str


def parse_rule(raw: dict) -> Rule:
    for key in ("id", "title", "severity", "vendors", "check", "pattern", "remediation"):
        if key not in raw:
            raise ValueError(f"rule {raw.get('id', '?')}: missing field '{key}'")
    if raw["severity"] not in SEVERITIES:
        raise ValueError(f"rule {raw['id']}: severity must be one of {sorted(SEVERITIES)}")
    if raw["check"] not in CHECKS:
        raise ValueError(f"rule {raw['id']}: check must be one of {sorted(CHECKS)}")
    try:
        pattern = re.compile(raw["pattern"], re.M)
        block = re.compile(raw["block"], re.M) if raw.get("block") else None
    except re.error as exc:
        raise ValueError(f"rule {raw['id']}: bad regular expression: {exc}") from exc
    return Rule(
        raw["id"],
        raw["title"],
        raw["severity"],
        tuple(raw["vendors"]),
        raw["check"],
        pattern,
        raw["remediation"],
        block,
    )


def load_rules(directory: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(Path(directory).glob("*.yml")):
        for raw in yaml.safe_load(path.read_text()) or []:
            rules.append(parse_rule(raw))
    ids = [r.id for r in rules]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate rule ids: {duplicates}")
    return rules


def extract_blocks(text: str, start: re.Pattern[str]) -> list[str]:
    """Blocks that begin at a matching line and continue while following lines are indented."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.split("\n"):
        if start.match(line):
            current = [line]
            blocks.append(current)
        elif current is not None and line[:1] in (" ", "\t"):
            current.append(line)
        else:
            current = None
    return ["\n".join(b) for b in blocks]


def evaluate(rule: Rule, text: str) -> Result:
    def result(ok: bool, detail: str) -> Result:
        return Result(rule.id, rule.title, rule.severity, "pass" if ok else "fail", detail, rule.remediation)

    if rule.block is not None:
        blocks = extract_blocks(text, rule.block)
        if not blocks:
            return result(False, "no matching configuration section found")
        hits = [bool(rule.pattern.search(b)) for b in blocks]
        if rule.check == "must_match":
            missing = hits.count(False)
            return result(missing == 0, f"{missing} of {len(blocks)} section(s) lack the setting" if missing else "ok")
        found = hits.count(True)
        return result(
            found == 0, f"{found} of {len(blocks)} section(s) contain the forbidden setting" if found else "ok"
        )

    match = rule.pattern.search(text)
    if rule.check == "must_match":
        return result(bool(match), "ok" if match else "required setting not found")
    return result(not match, "ok" if not match else f"forbidden setting present: {match.group(0).strip()[:80]}")

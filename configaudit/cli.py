"""Command line: audit | drift | collect | redact."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report
from .audit import audit_directory, worst_failure
from .collect import collect, commit, load_inventory
from .drift import compare
from .prepare import prepare
from .rules import SEVERITIES, load_rules

FORMATS = {"text": report.audit_text, "markdown": report.audit_markdown, "json": report.audit_json}


def cmd_audit(args: argparse.Namespace) -> int:
    audits = audit_directory(args.configs, load_rules(args.rules))
    if not audits:
        print(f"no config files found in {args.configs}", file=sys.stderr)
        return 2
    print(FORMATS[args.format](audits), end="")
    return 1 if worst_failure(audits) >= SEVERITIES[args.fail_on] else 0


def cmd_drift(args: argparse.Namespace) -> int:
    results = compare(args.baseline, args.current)
    print(report.drift_text(results, show_diff=not args.summary), end="")
    changed = any(r.status != "unchanged" for r in results)
    sensitive = any(r.sensitive for r in results)
    if args.fail_on == "any" and changed:
        return 1
    return 1 if args.fail_on == "sensitive" and sensitive else 0


def cmd_collect(args: argparse.Namespace) -> int:
    inventory = load_inventory(args.inventory)
    written, failed = collect(inventory, args.out)
    for name, status in sorted(written.items()):
        print(f"{name}: {status}")
    for name, error in sorted(failed.items()):
        print(f"{name}: FAILED {error}", file=sys.stderr)
    if args.commit and written:
        made = commit(args.out, f"Config change: {', '.join(sorted(written))}")
        print("committed" if made else "nothing to commit")
    return 1 if failed else 0


def cmd_redact(args: argparse.Namespace) -> int:
    _, stored = prepare(args.file.read_text(errors="replace"))
    print(stored, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="configaudit", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="check configs against the rules")
    audit.add_argument("--configs", type=Path, required=True)
    audit.add_argument("--rules", type=Path, default=Path("rules"))
    audit.add_argument("--format", choices=sorted(FORMATS), default="text")
    audit.add_argument("--fail-on", choices=sorted(SEVERITIES), default="high", help="exit 1 at or above this severity")
    audit.set_defaults(func=cmd_audit)

    drift = sub.add_parser("drift", help="compare two directories of configs")
    drift.add_argument("--baseline", type=Path, required=True)
    drift.add_argument("--current", type=Path, required=True)
    drift.add_argument("--summary", action="store_true", help="omit the line-by-line diff")
    drift.add_argument("--fail-on", choices=["never", "sensitive", "any"], default="never")
    drift.set_defaults(func=cmd_drift)

    coll = sub.add_parser(
        "collect", help="pull configs from devices (needs netmiko and credentials in the environment)"
    )
    coll.add_argument("--inventory", type=Path, required=True)
    coll.add_argument("--out", type=Path, default=Path("backups"))
    coll.add_argument("--commit", action="store_true", help="commit changes to a Git repository in --out")
    coll.set_defaults(func=cmd_collect)

    red = sub.add_parser("redact", help="print a config with secrets removed and volatile lines stripped")
    red.add_argument("file", type=Path)
    red.set_defaults(func=cmd_redact)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

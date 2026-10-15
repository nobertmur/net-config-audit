import re

import pytest
from rule_cases import CASES

from configaudit.rules import evaluate, extract_blocks, load_rules, parse_rule


def base(**changes):
    raw = {
        "id": "T-1",
        "title": "t",
        "severity": "high",
        "vendors": ["cisco_ios"],
        "check": "must_match",
        "pattern": "^x$",
        "remediation": "fix",
    }
    raw.update(changes)
    return raw


def test_every_rule_has_a_pass_and_a_fail_case(rules):
    assert {r.id for r in rules} == set(CASES)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_passes_and_fails_where_it_should(rules, rule_id):
    rule = next(r for r in rules if r.id == rule_id)
    good, bad = CASES[rule_id]
    assert evaluate(rule, good).status == "pass", f"{rule_id} should pass on its good snippet"
    assert evaluate(rule, bad).status == "fail", f"{rule_id} should fail on its bad snippet"


@pytest.mark.parametrize(
    "change,message",
    [
        ({"severity": "urgent"}, "severity"),
        ({"check": "maybe"}, "check"),
        ({"pattern": "("}, "bad regular expression"),
        ({"block": "["}, "bad regular expression"),
    ],
)
def test_bad_rules_are_rejected(change, message):
    with pytest.raises(ValueError, match=message):
        parse_rule(base(**change))


def test_missing_field_is_rejected():
    raw = base()
    del raw["remediation"]
    with pytest.raises(ValueError, match="remediation"):
        parse_rule(raw)


def test_duplicate_rule_ids_are_rejected(tmp_path):
    (tmp_path / "a.yml").write_text(
        "- {id: X-1, title: t, severity: low, vendors: [fortinet], check: must_match, pattern: a, remediation: r}\n"
    )
    (tmp_path / "b.yml").write_text(
        "- {id: X-1, title: t, severity: low, vendors: [fortinet], check: must_match, pattern: b, remediation: r}\n"
    )
    with pytest.raises(ValueError, match="duplicate rule ids"):
        load_rules(tmp_path)


def test_shipped_rules_load_with_unique_ids_and_known_vendors(rules):
    assert len({r.id for r in rules}) == len(rules)
    assert {v for r in rules for v in r.vendors} == {"cisco_ios", "mikrotik_routeros", "fortinet"}


def test_blocks_run_until_indentation_stops():
    text = "line con 0\nline vty 0 4\n transport input ssh\n login local\nline vty 5 15\n transport input all\n!\n"
    blocks = extract_blocks(text, re.compile(r"^line vty"))
    assert blocks == ["line vty 0 4\n transport input ssh\n login local", "line vty 5 15\n transport input all"]


def test_block_rule_with_no_blocks_fails_with_a_clear_reason(rules):
    rule = next(r for r in rules if r.id == "CISCO-002")
    result = evaluate(rule, "hostname r1\n")
    assert result.status == "fail" and "no matching configuration section" in result.detail


def test_block_rule_reports_how_many_sections_are_wrong(rules):
    rule = next(r for r in rules if r.id == "CISCO-002")
    assert "1 of 2 section(s)" in evaluate(rule, CASES["CISCO-002"][1]).detail

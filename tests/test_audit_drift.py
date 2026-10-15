from configaudit.audit import audit_directory, audit_text, worst_failure
from configaudit.drift import compare
from configaudit.report import audit_json, audit_markdown, drift_text
from configaudit.report import audit_text as render_text


def failing_ids(audits, device):
    return sorted(r.rule_id for a in audits if a.device == device for r in a.failures)


def test_audit_of_the_current_samples_finds_exactly_the_planted_problems(current, rules):
    audits = audit_directory(current, rules)
    assert failing_ids(audits, "edge-sw01") == ["CISCO-002", "CISCO-003", "CISCO-004", "CISCO-005", "CISCO-008"]
    assert failing_ids(audits, "edge-rtr02") == ["MT-001"]
    assert failing_ids(audits, "fw-01") == []


def test_the_baseline_is_clean_where_the_current_state_regressed(baseline, rules):
    audits = audit_directory(baseline, rules)
    assert failing_ids(audits, "edge-sw01") == []
    assert failing_ids(audits, "edge-rtr02") == []


def test_rules_only_apply_to_their_own_vendor(current, rules):
    audits = audit_directory(current, rules)
    ids = {a.device: {r.rule_id[:2] for r in a.results} for a in audits}
    assert ids == {"edge-rtr02": {"MT"}, "edge-sw01": {"CI"}, "fw-01": {"FG"}}


def test_unknown_vendor_is_skipped_not_failed(rules):
    audit = audit_text("mystery", "this is not a router config\n", rules)
    assert audit.skipped_reason and audit.results == []
    assert worst_failure([audit]) == 0


def test_worst_failure_reports_the_highest_severity(current, baseline, rules):
    assert worst_failure(audit_directory(current, rules)) == 3
    assert worst_failure(audit_directory(baseline, rules)) == 0


def test_audit_output_never_contains_a_secret(current, rules):
    audits = audit_directory(current, rules)
    for text in (render_text(audits), audit_markdown(audits), audit_json(audits)):
        for secret in ("EXAMPLEPLAINTEXTxxxx", "EXAMPLETEMPPASSxxxx", "EXAMPLEPASSWORD1", "EXAMPLE-RO-STRING"):
            assert secret not in text


def test_drift_finds_the_planted_regressions_and_ignores_volatile_changes(baseline, current):
    by_device = {d.device: d for d in compare(baseline, current)}
    assert by_device["fw-01"].status == "unchanged"  # only #conf_file_ver differs
    assert by_device["edge-rtr02"].status == "changed"
    assert "- set telnet disabled=yes" in by_device["edge-rtr02"].sensitive
    switch = by_device["edge-sw01"].sensitive
    assert "+ snmp-server community public RO" in switch
    assert "+ transport input all" in switch
    assert "- service password-encryption" in switch


def test_drift_output_never_contains_a_secret(baseline, current):
    text = drift_text(compare(baseline, current))
    for secret in ("EXAMPLEPLAINTEXTxxxx", "EXAMPLETEMPPASSxxxx", "EXAMPLEPASSWORD2", "EXAMPLE-RO-STRING"):
        assert secret not in text
    assert "password=<redacted>" in text


def test_a_secret_only_change_is_invisible_by_design(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "r1.cfg").write_text("hostname r1\ninterface Loopback0\nenable password one\n")
    (tmp_path / "b" / "r1.cfg").write_text("hostname r1\ninterface Loopback0\nenable password two\n")
    assert compare(tmp_path / "a", tmp_path / "b")[0].status == "unchanged"


def test_added_and_removed_devices_are_reported(tmp_path):
    (tmp_path / "old").mkdir()
    (tmp_path / "new").mkdir()
    (tmp_path / "old" / "gone.cfg").write_text("hostname gone\ninterface Loopback0\n")
    (tmp_path / "new" / "fresh.cfg").write_text("hostname fresh\ninterface Loopback0\n")
    statuses = {d.device: d.status for d in compare(tmp_path / "old", tmp_path / "new")}
    assert statuses == {"fresh": "added", "gone": "removed"}


def test_a_finding_that_quotes_a_secret_bearing_line_shows_it_redacted(rules):
    from configaudit.rules import parse_rule

    quoting_rule = parse_rule(
        {
            "id": "T-QUOTE",
            "title": "no local users with passwords",
            "severity": "high",
            "vendors": ["cisco_ios"],
            "check": "must_not_match",
            "pattern": r"^username .*password.*$",
            "remediation": "use AAA",
        }
    )
    text = "hostname r1\nservice timestamps log datetime msec\nusername bob privilege 15 password 0 HUNTER2SECRET\n"
    audit = audit_text("r1", text, [quoting_rule])
    detail = audit.failures[0].detail
    assert "HUNTER2SECRET" not in detail and "<redacted>" in detail

import pytest

from configaudit.prepare import normalise, prepare, redact
from configaudit.vendors import CISCO, FORTINET, MIKROTIK, UNKNOWN, detect_vendor

SECRETS = [
    "EXAMPLEPLAINTEXTxxxx",
    "EXAMPLETEMPPASSxxxx",
    "EXAMPLEPASSWORD1",
    "EXAMPLEPASSWORD2",
    "EXAMPLEHASHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "SH2EXAMPLEENCRYPTEDVALUExxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==",
    "EXAMPLE-RO-STRING",
]


@pytest.mark.parametrize(
    "path,vendor",
    [("edge-sw01.cfg", CISCO), ("edge-rtr02.rsc", MIKROTIK), ("fw-01.conf", FORTINET)],
)
def test_vendor_detection_on_samples(current, path, vendor):
    assert detect_vendor((current / path).read_text()) == vendor


def test_unrecognised_text_is_unknown():
    assert detect_vendor("hello world\nnothing to see\n") == UNKNOWN


@pytest.mark.parametrize("path", ["edge-sw01.cfg", "edge-rtr02.rsc", "fw-01.conf"])
def test_no_secret_survives_redaction(baseline, current, path):
    for directory in (baseline, current):
        _, stored = prepare((directory / path).read_text())
        for secret in SECRETS:
            assert secret not in stored, f"{secret} leaked in {directory.name}/{path}"


@pytest.mark.parametrize("path", ["edge-sw01.cfg", "edge-rtr02.rsc", "fw-01.conf"])
def test_redaction_is_idempotent(current, path):
    once = redact((current / path).read_text())
    assert redact(once) == once


def test_default_snmp_communities_stay_visible_because_they_are_findings():
    text = "hostname r1\nsnmp-server community public RO\nsnmp-server community S3cret RW\n"
    out = redact(text, CISCO)
    assert "snmp-server community public RO" in out
    assert "S3cret" not in out and "snmp-server community <redacted> RW" in out


def test_redaction_keeps_the_structure_around_the_secret():
    out = redact("hostname r1\nenable password abc123\nusername bob privilege 15 secret 9 HASH\n", CISCO)
    assert "enable password <redacted>" in out
    assert "username bob privilege 15 secret 9 <redacted>" in out


def test_normalise_drops_volatile_lines_per_vendor(baseline, current):
    for name in ("fw-01.conf",):  # differs only by #conf_file_ver
        assert prepare((baseline / name).read_text())[1] == prepare((current / name).read_text())[1]
    cisco = prepare((current / "edge-sw01.cfg").read_text())[1]
    assert "Building configuration" not in cisco and "Last configuration change" not in cisco
    mikrotik = prepare((current / "edge-rtr02.rsc").read_text())[1]
    assert "by RouterOS" not in mikrotik and "serial number" not in mikrotik


def test_normalise_cleans_line_endings_and_whitespace():
    assert normalise("a  \r\nb\t\r\n\r\n\r\n", UNKNOWN) == "a\nb\n"
    assert normalise("", UNKNOWN) == "\n"

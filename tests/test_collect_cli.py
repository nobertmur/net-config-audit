import subprocess
import sys

import pytest

import configaudit.cli as cli_module
from configaudit.cli import main
from configaudit.collect import collect, commit, load_inventory, netmiko_connect

INVENTORY = """\
devices:
  - {name: sw1, host: 192.0.2.10, device_type: cisco_ios, username_env: U, password_env: P}
  - {name: rt1, host: 192.0.2.11, device_type: mikrotik_routeros, username_env: U, password_env: P}
"""

CISCO_TEXT = "hostname sw1\nenable password SECRET123\n! Last configuration change at 1\n"
MT_TEXT = "# 2026-10-14 00:00:00 by RouterOS 7.14\n/ip service\nset telnet disabled=yes\n"


class Fake:
    def __init__(self, output):
        self.output, self.commands, self.closed = output, [], False

    def send_command(self, command):
        self.commands.append(command)
        return self.output

    def disconnect(self):
        self.closed = True


def make_connect(outputs, fakes=None):
    def connect(device):
        out = outputs[device["name"]]
        if isinstance(out, Exception):
            raise out
        fake = Fake(out)
        if fakes is not None:
            fakes.append(fake)
        return fake

    return connect


@pytest.fixture()
def inventory(tmp_path):
    path = tmp_path / "inv.yml"
    path.write_text(INVENTORY)
    return load_inventory(path)


def test_collect_stores_redacted_normalised_files_and_closes_connections(inventory, tmp_path):
    fakes = []
    written, failed = collect(inventory, tmp_path / "out", make_connect({"sw1": CISCO_TEXT, "rt1": MT_TEXT}, fakes))
    assert written == {"sw1": "new", "rt1": "new"} and failed == {}
    stored = (tmp_path / "out" / "sw1.cfg").read_text()
    assert "SECRET123" not in stored and "enable password <redacted>" in stored
    assert "Last configuration change" not in stored
    assert sorted(f.commands[0] for f in fakes) == ["/export", "show running-config"]
    assert all(f.closed for f in fakes)


def test_second_run_with_no_change_writes_nothing_and_a_change_is_reported(inventory, tmp_path):
    out = tmp_path / "out"
    connect = make_connect({"sw1": CISCO_TEXT, "rt1": MT_TEXT})
    collect(inventory, out, connect)
    assert collect(inventory, out, connect)[0] == {}
    changed = make_connect({"sw1": CISCO_TEXT + "ntp server 10.0.9.20\n", "rt1": MT_TEXT})
    assert collect(inventory, out, changed)[0] == {"sw1": "changed"}


def test_one_unreachable_device_does_not_stop_the_others(inventory, tmp_path):
    connect = make_connect({"sw1": TimeoutError("no route"), "rt1": MT_TEXT})
    written, failed = collect(inventory, tmp_path / "out", connect)
    assert written == {"rt1": "new"} and "TimeoutError" in failed["sw1"]


@pytest.mark.parametrize(
    "line,message",
    [
        ("{name: 'a b', host: 1.2.3.4, device_type: cisco_ios, username_env: U, password_env: P}", "bad or duplicate"),
        ("{name: a, host: '1.2.3.4; rm', device_type: cisco_ios, username_env: U, password_env: P}", "unsafe host"),
        ("{name: a, host: 1.2.3.4, device_type: juniper, username_env: U, password_env: P}", "unsupported"),
        ("{name: a, host: 1.2.3.4, device_type: cisco_ios, username_env: u, password_env: P}", "environment variable"),
        ("{name: a, host: 1.2.3.4, device_type: cisco_ios, username_env: U}", "missing 'password_env'"),
    ],
)
def test_bad_inventory_entries_are_rejected(tmp_path, line, message):
    path = tmp_path / "inv.yml"
    path.write_text(f"devices:\n  - {line}\n")
    with pytest.raises(ValueError, match=message):
        load_inventory(path)


def test_inventory_has_no_place_for_credentials(root):
    text = (root / "inventory.example.yml").read_text().lower()
    assert "password:" not in text and "secret:" not in text


def test_live_connection_without_netmiko_gives_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "netmiko", None)  # makes `import netmiko` raise ImportError
    with pytest.raises(RuntimeError, match="netmiko is not installed"):
        netmiko_connect({"username_env": "U", "password_env": "P"})


def test_commit_only_when_something_changed(tmp_path):
    (tmp_path / "a.cfg").write_text("hostname a\n")
    assert commit(tmp_path, "first") is True
    assert commit(tmp_path, "nothing new") is False
    (tmp_path / "a.cfg").write_text("hostname a\nntp server 1.1.1.1\n")
    assert commit(tmp_path, "second") is True
    log = subprocess.run(["git", "-C", str(tmp_path), "log", "--format=%s"], capture_output=True, text=True).stdout
    assert log.split() == ["second", "first"]


def test_cli_audit_exit_codes(current, baseline, root):
    rules = str(root / "rules")
    assert main(["audit", "--configs", str(current), "--rules", rules]) == 1
    assert main(["audit", "--configs", str(baseline), "--rules", rules]) == 0
    only_low = ["audit", "--configs", str(current), "--rules", rules, "--fail-on"]
    assert main([*only_low, "high"]) == 1


def test_cli_audit_with_no_configs_is_an_error(tmp_path, root, capsys):
    assert main(["audit", "--configs", str(tmp_path), "--rules", str(root / "rules")]) == 2
    assert "no config files" in capsys.readouterr().err


def test_cli_drift_fail_modes(baseline, current):
    args = ["drift", "--baseline", str(baseline), "--current", str(current), "--summary"]
    assert main(args) == 0
    assert main([*args, "--fail-on", "sensitive"]) == 1
    assert main([*args, "--fail-on", "any"]) == 1
    assert main(["drift", "--baseline", str(baseline), "--current", str(baseline), "--fail-on", "any"]) == 0


def test_cli_redact_prints_a_safe_config(current, capsys):
    assert main(["redact", str(current / "edge-sw01.cfg")]) == 0
    out = capsys.readouterr().out
    assert "EXAMPLEPLAINTEXTxxxx" not in out and "enable password <redacted>" in out


def test_cli_collect_commits_when_asked(monkeypatch, tmp_path, capsys):
    inv = tmp_path / "inv.yml"
    inv.write_text(INVENTORY)
    calls = []
    monkeypatch.setattr(cli_module, "collect", lambda inventory, out: ({"sw1": "new"}, {}))
    monkeypatch.setattr(cli_module, "commit", lambda out, message: calls.append(message) or True)
    assert main(["collect", "--inventory", str(inv), "--out", str(tmp_path / "o"), "--commit"]) == 0
    assert calls == ["Config change: sw1"]


def test_cli_collect_failures_give_a_nonzero_exit(monkeypatch, tmp_path):
    inv = tmp_path / "inv.yml"
    inv.write_text(INVENTORY)
    monkeypatch.setattr(cli_module, "collect", lambda inventory, out: ({}, {"sw1": "TimeoutError: x"}))
    assert main(["collect", "--inventory", str(inv), "--out", str(tmp_path / "o")]) == 1

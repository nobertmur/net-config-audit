"""Per-vendor knowledge: how to recognise a config, which lines are noise, and which are secrets."""

from __future__ import annotations

import re
from collections.abc import Callable
from re import Match

CISCO = "cisco_ios"
MIKROTIK = "mikrotik_routeros"
FORTINET = "fortinet"
UNKNOWN = "unknown"
VENDORS = (CISCO, MIKROTIK, FORTINET)

# Netmiko device types and the command that prints the full configuration.
COLLECT_COMMANDS = {
    CISCO: "show running-config",
    MIKROTIK: "/export",
    FORTINET: "show full-configuration",
}

_SIGNATURES = {
    FORTINET: re.compile(r"^(#config-version=|config system global\b|config system interface\b)", re.M),
    MIKROTIK: re.compile(r"^(# .*RouterOS|/(ip|system|interface) [a-z]|/(ip|system|interface)\s*$)", re.M),
    CISCO: re.compile(r"^(version \d|hostname \S+|interface (Gigabit|FastEthernet|Ethernet|Vlan|Loopback))", re.M),
}


def detect_vendor(text: str) -> str:
    """Best-effort vendor guess from content. The first signature that matches wins."""
    for vendor in (FORTINET, MIKROTIK, CISCO):
        if _SIGNATURES[vendor].search(text):
            return vendor
    return UNKNOWN


# Lines that change on every export without any real change. They are removed before storing or diffing.
VOLATILE = {
    CISCO: [
        r"^Building configuration\.\.\.$",
        r"^Current configuration\s*:.*$",
        r"^! Last configuration change at .*$",
        r"^! NVRAM config last updated at .*$",
        r"^! No configuration change since last restart.*$",
        r"^ntp clock-period \d+$",
        r"^! Time: .*$",
    ],
    MIKROTIK: [
        r"^# \d{4}-\d{2}-\d{2}.* by RouterOS .*$",
        r"^# software id = .*$",
        r"^# model = .*$",
        r"^# serial number = .*$",
    ],
    FORTINET: [
        r"^#config-version=.*$",
        r"^#conf_file_ver=.*$",
        r"^#buildno=.*$",
        r"^#global_vdom=.*$",
    ],
}

# A replacement is either a string or a function so some values (default SNMP communities) can stay visible.
Replacement = str | Callable[[Match[str]], str]

REDACTED = "<redacted>"
WEAK_COMMUNITIES = {"public", "private"}  # not secrets; they are findings, so the audit must still see them


def _keep_weak(match: Match[str]) -> str:
    value = match.group("value").strip('"')
    return match.group(0) if value.lower() in WEAK_COMMUNITIES else f"{match.group('head')}{REDACTED}"


SECRETS: dict[str, list[tuple[str, Replacement]]] = {
    CISCO: [
        (r"^(?P<head>\s*enable (?:secret|password)(?: \d)? )\S+", rf"\g<head>{REDACTED}"),
        (r"^(?P<head>\s*username \S+ (?:privilege \d+ )?(?:secret|password)(?: \d)? )\S+", rf"\g<head>{REDACTED}"),
        (r"^(?P<head>\s*snmp-server community )(?P<value>\S+)", _keep_weak),
        (r"^(?P<head>\s*(?:tacacs-server |radius-server )?key(?: \d)? )\S+", rf"\g<head>{REDACTED}"),
        (r"^(?P<head>\s*ntp authentication-key \d+ md5 )\S+", rf"\g<head>{REDACTED}"),
        (r"^(?P<head>\s*(?:neighbor \S+ )?password(?: \d)? )\S+", rf"\g<head>{REDACTED}"),
    ],
    MIKROTIK: [
        (
            r"(?P<head>\b(?:password|secret|passphrase|psk|private-key|authentication-password|encryption-password|"
            r"wpa-pre-shared-key|wpa2-pre-shared-key)=)(\"[^\"]*\"|\S+)",
            rf"\g<head>{REDACTED}",
        ),
    ],
    FORTINET: [
        (r"\bENC\s+\S+", f"ENC {REDACTED}"),
    ],
}

# Changed lines matching these deserve attention in a drift report.
SENSITIVE = re.compile(
    r"\b(user|username|password|secret|snmp|community|telnet|ssh|allowaccess|admin\w*|acl|access-list|"
    r"firewall|chain=input|nat|enable|aaa|tacacs|radius|transport|http\w*)\b",
    re.I,
)

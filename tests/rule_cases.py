"""For every rule: a snippet that must pass and one that must fail.

Keeping this table complete is enforced by test_every_rule_has_a_pass_and_a_fail_case.
"""

VTY_GOOD = "line vty 0 4\n transport input ssh\n login local\nline vty 5 15\n transport input ssh\n"
VTY_BAD = "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input all\n"

CASES: dict[str, tuple[str, str]] = {
    # id: (passing text, failing text)
    "CISCO-001": ("ip ssh version 2\n", "ip ssh version 1\n"),
    "CISCO-002": (VTY_GOOD, VTY_BAD),
    "CISCO-003": ("snmp-server community S3cretLongString RO\n", "snmp-server community public RO\n"),
    "CISCO-004": ("service password-encryption\n", "hostname r1\n"),
    "CISCO-005": ("enable secret 9 abc\n", "enable password abc\n"),
    "CISCO-006": ("ntp server 10.0.9.20\n", "hostname r1\n"),
    "CISCO-007": ("logging host 10.0.9.10\n", "logging buffered 8192\n"),
    "CISCO-008": ("no ip http server\n", "ip http server\n"),
    "CISCO-009": ("banner login ^C\nhi\n^C\n", "hostname r1\n"),
    "CISCO-010": ("service timestamps log datetime msec\n", "service timestamps debug uptime\n"),
    "MT-001": ("/ip service\nset telnet disabled=yes\n", "/ip service\nset ssh port=22\n"),
    "MT-002": ("set ftp disabled=yes\n", "set ftp port=21\n"),
    "MT-003": ("set www disabled=yes\n", "set www port=80\n"),
    "MT-004": ("set api disabled=yes\n", "set api port=8728\n"),
    "MT-005": (
        'add action=drop chain=input comment="drop all else"\n',
        "add action=accept chain=input protocol=icmp\nadd action=drop chain=forward\n",
    ),
    "MT-006": ("/system ntp client\nset enabled=yes\n", "/system ntp client\nset enabled=no\n"),
    "FG-001": ("config system global\n    set strong-crypto enable\nend\n", "config system global\nend\n"),
    "FG-002": ("    set admin-lockout-threshold 3\n", "    set admin-lockout-threshold 10\n"),
    "FG-003": ("config system global\n    set admin-telnet disable\nend\n", "    set admin-telnet enable\n"),
    "FG-004": ("    set admintimeout 10\n", "    set admintimeout 60\n"),
    "FG-005": ("    set ntpsync enable\n", "    set ntpsync disable\n"),
    "FG-006": ("        set allowaccess ping https ssh\n", "        set allowaccess ping https telnet\n"),
    "FG-007": ("        set allowaccess ping https ssh\n", "        set allowaccess ping http ssh\n"),
    "FG-008": ("    set pre-login-banner enable\n", "config system global\nend\n"),
}

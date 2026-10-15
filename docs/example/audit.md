# Configuration audit

| Device | Vendor | Passed | High | Medium | Low |
| --- | --- | ---: | ---: | ---: | ---: |
| edge-rtr02 | mikrotik_routeros | 5/6 | 1 | 0 | 0 |
| edge-sw01 | cisco_ios | 5/10 | 2 | 3 | 0 |
| fw-01 | fortinet | 8/8 | 0 | 0 | 0 |

## edge-rtr02

| Severity | Rule | Finding | Fix |
| --- | --- | --- | --- |
| high | MT-001 Telnet service disabled | required setting not found | `/ip service set telnet disabled=yes` |

## edge-sw01

| Severity | Rule | Finding | Fix |
| --- | --- | --- | --- |
| high | CISCO-002 VTY lines accept SSH only | 1 of 2 section(s) lack the setting | `line vty 0 15 / transport input ssh` |
| high | CISCO-003 No default SNMP community strings | forbidden setting present: snmp-server community public | `no snmp-server community public ; use SNMPv3 or a long random community` |
| medium | CISCO-004 Password encryption service enabled | required setting not found | `service password-encryption` |
| medium | CISCO-005 No cleartext enable password | forbidden setting present: enable password | `no enable password ; enable secret 9 <hash>` |
| medium | CISCO-008 HTTP server disabled | required setting not found | `no ip http server` |

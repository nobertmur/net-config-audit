# net-config-audit

Collect network device configurations, strip the secrets, check them against written rules, and report what
changed since a known-good baseline. Covers Cisco IOS, MikroTik RouterOS and Fortinet FortiOS.

It is the config-backup-and-compliance loop most network teams run by hand or with a pile of scripts, built so
that it is safe to run in CI: **secrets are redacted before anything is stored, diffed or printed.**

> Status: reference project. The rules, redaction, drift and report logic are tested (76 tests) against
> synthetic configurations. The Netmiko collector is tested with a fake connection only and has **not** been run
> against live devices. See [docs/design.md](docs/design.md) for limits.

## What it does

| Command | Purpose |
| --- | --- |
| `collect` | Log in to each device in an inventory (credentials from env vars), pull the config, store the redacted and normalised copy, optionally commit it to Git |
| `audit` | Evaluate YAML rules against a directory of configs; text, markdown or JSON output; non-zero exit at a chosen severity (CI gate) |
| `drift` | Compare a baseline directory with the current one; flags changes to sensitive lines (auth, SNMP, management services) as ATTENTION |
| `redact` | Print one config with secrets removed, for pasting into a ticket |

## Try it (no devices, no dependencies beyond PyYAML)

```bash
python3 -m configaudit audit --configs samples/current --rules rules --fail-on high   # exit 1
python3 -m configaudit drift --baseline samples/baseline --current samples/current
python3 -m configaudit redact samples/current/edge-sw01.cfg
```

Output from the included samples is committed in [docs/example/](docs/example/): `edge-sw01` fails 5 of 10
checks (telnet-capable VTY, default SNMP community, cleartext enable password, HTTP server back on, password
encryption removed), `edge-rtr02` fails the telnet check, `fw-01` passes, and drift highlights each of those regressions.
Passwords in the output show as `<redacted>`.

## Using it for real

```bash
pip install -e '.[collect]'            # adds netmiko
export NETAUDIT_USER=backup NETAUDIT_PASS=...   # names are set per device in the inventory
cp inventory.example.yml inventory.yml  # git-ignored; devices, device_type, env var names
python3 -m configaudit collect --inventory inventory.yml --out backups --commit
python3 -m configaudit audit --configs backups --rules rules --format markdown > audit.md
```

The inventory holds env var *names*, never credentials. `backups/` is its own Git repository, so
`git log -p` is your change history and `drift` compares any two checkouts. Do not run this against configs you
are not permitted to copy, and keep the backup repository private.

## Rules

24 starter rules (10 Cisco IOS, 6 RouterOS, 8 FortiOS) in [rules/](rules/), as data:

```yaml
- id: CISCO-003
  title: No default SNMP community strings
  severity: high
  vendors: [cisco_ios]
  check: must_not_match
  pattern: 'snmp-server community (public|private)\b'
  remediation: no snmp-server community public ; use SNMPv3 or a long random community
```

Adding a rule means a YAML entry and a pass/fail case in `tests/rule_cases.py`; a test fails if you forget.
See [docs/rule-authoring.md](docs/rule-authoring.md). These are a hardening starter set, not a CIS benchmark or
a compliance attestation. Tune them to your own standard.

## Layout

```
configaudit/   vendors, prepare (redact + normalise), rules, audit, drift, collect, report, cli
rules/         one YAML file per vendor
samples/       synthetic baseline and current configs (placeholder secrets)
tests/         76 tests incl. no-secret-leak checks and a fake-connection collector
docs/          design and limits, rule authoring, example output
```

## Development

```bash
pip install -r requirements-dev.txt
make lint test
```

MIT licensed.

# Design and limits

## Flow

```
device ──(collect, Netmiko)──> redact + normalise ──> backups/<device>.cfg (Git)
                                       │
          baseline dir ─┐              ├──> audit: rules/*.yml ──> report (text/markdown/json), exit code
          current dir  ─┴─> drift ─────┘
```

`prepare(text)` is the single choke point: detect vendor, redact secrets, normalise volatile lines.
Collect stores its output, `audit` and `drift` run it again on whatever they read (idempotent), and `redact`
exposes it on the command line. Nothing prints or stores raw configuration text.

## Decisions

- **Redact before compare, not after.** A diff of raw configs prints the secret on the `+`/`-` lines.
  The cost: a change to only a password value is invisible to drift. That is deliberate and tested; rotating
  credentials is tracked elsewhere (AAA/vault), and the alternative is leaking them into CI logs.
- **Weak SNMP communities (`public`, `private`) stay visible** because they are findings, not secrets.
- **Normalisation removes volatile lines** (timestamps, "Building configuration", RouterOS export header,
  FortiOS `#conf_file_ver`) so drift reports real changes only. It is per vendor and tested.
- **Credentials come from environment variables named in the inventory**, never from the file.
  Host and name fields are validated, so a hostile inventory cannot inject into the connection call.
- **Rules are data.** Adding a vendor check is a YAML change plus a test case. The engine is deliberately small.
- **Unknown vendor is skipped with a reason**, not failed, so a stray file cannot break a pipeline silently
  and cannot pass silently either: it shows in the report as skipped.

## Limits (read these)

- Regex over text. No config parser, so no cross-line semantics (ACL ordering, per-interface checks).
- The rules are a small starter set based on common hardening guidance, not a benchmark implementation
  (not CIS, not a compliance attestation). Review them against your own standard before relying on them.
- Redaction is pattern-based. It covers the syntax in the shipped samples and the patterns in `vendors.py`.
  Unusual syntax can slip through, so add a pattern and a test when you find one, and do not point this at
  configs you are not allowed to copy.
- The Netmiko collector is tested with a fake connection only. It has not been run against live devices.
- Samples are synthetic with placeholder secrets. No real device data is in this repository.

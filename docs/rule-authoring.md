# Writing rules

Rules live in `rules/<vendor>.yml` as a list. Example:

```yaml
- id: CISCO-002
  title: VTY lines accept SSH only
  severity: high            # high | medium | low
  vendors: [cisco_ios]
  check: must_not_match     # must_match | must_not_match
  block: '^line vty'        # optional: only look inside matching sections
  pattern: 'transport input (all|telnet)'
  remediation: "line vty 0 15 / transport input ssh"
```

- Patterns are Python regexes applied with `re.MULTILINE` to the **redacted, normalised** text.
- With `block`, a section starts at a line matching `block` and continues while following lines are indented
  (or blank). The rule is judged per section; the detail says how many sections failed.
  A `block` rule fails with "no matching configuration section" if none exist, because a missing VTY
  section is itself worth a look. If that is wrong for your rule, do not use `block`.
- `must_match` fails when the pattern is absent (a control is missing). `must_not_match` fails when present.
- Rules are checked at load time: unknown severity or check, bad regex, missing field, duplicate id all raise.

## Testing a rule

Add `"<ID>": (passing_text, failing_text)` to `tests/rule_cases.py`. Keep snippets as small as possible, but
realistic enough that the regex is tested against the syntax you see on a device, not a made-up form.

## Checks that depend on the whole config

A regex cannot say "every interface has X". Those checks (and anything needing parsing, such as ACL shadowing)
are out of scope; see `docs/design.md`. Use a parser library such as ciscoconfparse if you need them.

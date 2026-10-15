# Contributing

- Branch from `main`; keep pull requests small.
- A new rule is a YAML entry plus one passing and one failing snippet in `tests/rule_cases.py`;
  a test fails if a rule has no case. See `docs/rule-authoring.md`.
- Anything that stores or prints configuration text must go through `prepare()` so secrets are redacted first.
- Never commit real configs, even "sanitised" ones. Use the synthetic files in `samples/`.
- `make lint test` must pass before you open a pull request.

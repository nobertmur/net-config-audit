PY ?= python3

.PHONY: test lint fmt audit drift example
test:
	$(PY) -m pytest
lint:
	ruff check . && ruff format --check .
fmt:
	ruff format . && ruff check --fix .
audit:
	$(PY) -m configaudit audit --configs samples/current --rules rules --fail-on high
drift:
	$(PY) -m configaudit drift --baseline samples/baseline --current samples/current
example:
	mkdir -p docs/example
	-$(PY) -m configaudit audit --configs samples/current --rules rules --format markdown > docs/example/audit.md
	-$(PY) -m configaudit drift --baseline samples/baseline --current samples/current > docs/example/drift.txt

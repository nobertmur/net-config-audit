from pathlib import Path

import pytest

from configaudit.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def rules():
    return load_rules(ROOT / "rules")


@pytest.fixture()
def current(root) -> Path:
    return root / "samples" / "current"


@pytest.fixture()
def baseline(root) -> Path:
    return root / "samples" / "baseline"

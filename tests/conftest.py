from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def fixture_dex(repo_root: Path) -> Path:
    path = repo_root / "tests" / "fixtures" / "synthetic" / "Fixture.dex"
    assert path.exists()
    return path


@pytest.fixture(scope="session")
def test_apk() -> Path:
    value = os.environ.get("DEX2C_TEST_APK")
    if not value:
        pytest.skip("set DEX2C_TEST_APK to an authorized Dex2C-protected APK for integration tests")
    path = Path(value).expanduser()
    if not path.exists():
        pytest.skip(f"DEX2C_TEST_APK does not exist: {path}")
    return path

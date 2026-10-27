from __future__ import annotations

import subprocess
from pathlib import Path


def _run(repo_root: Path, *args: str):
    return subprocess.run(
        [str(repo_root / "dex2c-recover"), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=90,
    )


def test_cli_help(repo_root: Path) -> None:
    result = _run(repo_root, "--help")
    assert result.returncode == 0
    assert "analyze" in result.stdout
    assert "all" in result.stdout
    assert "validate" in result.stdout
    assert "filters.txt" not in result.stdout


def test_cli_version(repo_root: Path) -> None:
    result = _run(repo_root, "--version")
    assert result.returncode == 0
    assert "dex2c-recover 1.0.0" in result.stdout


def test_cli_devices_does_not_require_apk(repo_root: Path) -> None:
    result = _run(repo_root, "devices", "--json")
    assert result.returncode == 0
    assert result.stdout.strip().startswith("{")


def test_cli_rejects_missing_apk(repo_root: Path, tmp_path: Path) -> None:
    result = _run(repo_root, "analyze", "--apk", str(tmp_path / "missing.apk"), "--out", str(tmp_path / "out"))
    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_cli_rejects_non_zip_input(repo_root: Path, tmp_path: Path) -> None:
    apk = tmp_path / "not.apk"
    apk.write_text("not an apk", encoding="utf-8")
    result = _run(repo_root, "analyze", "--apk", str(apk), "--out", str(tmp_path / "out"))
    assert result.returncode == 2
    assert "ZIP/APK" in result.stderr

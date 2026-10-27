from __future__ import annotations

import hashlib
from pathlib import Path

from dex2c_recover.dexparse import load_dex, parse_header
from dex2c_recover.validation import validate_dex


def test_synthetic_dex_parses(fixture_dex: Path) -> None:
    data = fixture_dex.read_bytes()
    header = parse_header(data)
    assert header.version == 35
    assert header.checksum_ok is True
    assert header.signature_ok is True
    dex = load_dex(data)
    methods = {
        (cls.get_name(), method.get_name(), method.get_descriptor())
        for cls in dex.get_classes()
        for method in cls.get_methods()
    }
    assert ("Ldex2c_recover/Fixture;", "answer", "()I") in methods
    assert ("Ldex2c_recover/Fixture;", "add", "(I I)I") in methods
    assert ("Ldex2c_recover/Fixture;", "<init>", "()V") in methods


def test_synthetic_dex_validates(fixture_dex: Path) -> None:
    result = validate_dex(fixture_dex, run_external=False)
    assert result["valid"] is True
    assert result["errors"] == []
    assert result["classes"] == 1
    assert result["methods"] == 4
    assert result["checks"]["instruction_decode"] is True


def test_truncated_dex_is_rejected(fixture_dex: Path, tmp_path: Path) -> None:
    truncated = tmp_path / "truncated.dex"
    truncated.write_bytes(fixture_dex.read_bytes()[:64])
    result = validate_dex(truncated, run_external=False)
    assert result["valid"] is False
    assert result["errors"]


def test_tampered_dex_is_rejected(fixture_dex: Path, tmp_path: Path) -> None:
    tampered = tmp_path / "tampered.dex"
    data = bytearray(fixture_dex.read_bytes())
    data[120] ^= 0xFF
    tampered.write_bytes(data)
    result = validate_dex(tampered, run_external=False)
    assert result["valid"] is False
    assert any("checksum" in error or "signature" in error for error in result["errors"])


def test_fixture_identity(fixture_dex: Path) -> None:
    assert hashlib.sha256(fixture_dex.read_bytes()).hexdigest() == "b30683587f01623dd03865a77c7f4221250d57fe61b404482ac5ada5e4b397f6"

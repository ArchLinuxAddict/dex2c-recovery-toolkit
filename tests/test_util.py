from __future__ import annotations

import json
from pathlib import Path

from dex2c_recover.util import (
    read_json,
    read_jsonl,
    stable_json,
    write_json,
    write_jsonl,
)


def test_stable_json_is_sorted_and_roundtrips(tmp_path: Path) -> None:
    value = {"z": 1, "a": {"b": 2, "a": 3}, "ü": "é"}
    text = stable_json(value)
    assert text.index('"a"') < text.index('"z"')
    assert json.loads(text) == value
    path = tmp_path / "x.json"
    write_json(path, value)
    assert read_json(path) == value


def test_jsonl_is_sorted_by_input_order(tmp_path: Path) -> None:
    rows = [{"b": 1}, {"a": 2}]
    path = tmp_path / "x.jsonl"
    assert write_jsonl(path, rows) == 2
    assert read_jsonl(path) == rows
    assert path.read_text(encoding="utf-8").splitlines()[0].startswith('{"b"')


def test_missing_jsonl_is_empty(tmp_path: Path) -> None:
    assert read_jsonl(tmp_path / "missing.jsonl") == []

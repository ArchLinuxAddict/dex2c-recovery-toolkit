from __future__ import annotations

import hashlib
from pathlib import Path

from dex2c_recover.pipeline import Pipeline
from dex2c_recover.util import read_json


def test_static_pipeline_on_synthetic_apk(repo_root: Path, tmp_path: Path) -> None:
    apk = repo_root / "tests" / "fixtures" / "synthetic" / "Fixture.apk"
    before = hashlib.sha256(apk.read_bytes()).hexdigest()
    out = tmp_path / "workspace with spaces"
    result = Pipeline(apk, out, ghidra="off", runtime="none").run_static(command="pytest")
    stages = result["stages"]
    assert stages["ingest"]["package"] == "dev.dex2c.fixture"
    assert stages["dex"]["classes"] == 1
    assert stages["dex"]["methods"] == 3
    assert (out / "inventory" / "inputs.json").exists()
    assert (out / "native" / "method-mappings.jsonl").exists()
    assert (out / "recovery" / "exact" / "manifest.json").exists()
    assert (out / "recovery" / "unresolved.jsonl").exists()
    report = read_json(out / "reports" / "report.json", {})
    assert report["validation"]["dex"]["valid"] == 1
    assert report["validation"]["dex"]["invalid"] == 0
    assert (out / "provenance" / "SHA256SUMS").exists()
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == before

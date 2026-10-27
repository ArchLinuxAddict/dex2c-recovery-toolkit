from __future__ import annotations

from pathlib import Path

import pytest

from dex2c_recover.pipeline import Pipeline


@pytest.mark.integration
def test_static_pipeline_end_to_end(test_apk: Path, tmp_path: Path) -> None:
    out = tmp_path / "workspace"
    result = Pipeline(test_apk, out, ghidra="off", runtime="none").run_static(command="pytest")
    assert result["ingest"]["input_sha256"]
    assert (out / "inventory" / "inputs.json").exists()
    assert (out / "inventory" / "methods.jsonl").exists()
    assert (out / "native" / "method-mappings.jsonl").exists()
    assert (out / "inventory" / "protected-method-candidates.jsonl").exists()
    assert (out / "reports" / "report.json").exists()
    assert (out / "provenance" / "SHA256SUMS").exists()

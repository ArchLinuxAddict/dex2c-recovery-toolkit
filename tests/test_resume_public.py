from __future__ import annotations

from pathlib import Path

from dex2c_recover.util import read_json
from dex2c_recover.workspace import Workspace


def test_stage_resume_state_and_isolation(tmp_path: Path) -> None:
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"not-an-apk")
    ws = Workspace(tmp_path / "out", apk)
    assert ws.stage_done("ingest", "abc") is False
    ws.mark_stage("ingest", "completed", input_sha256="abc", details={"n": 1})
    assert ws.stage_done("ingest", "abc") is True
    assert ws.stage_done("ingest", "different") is False
    state = read_json(ws.state_path, {})
    assert state["stages"]["ingest"]["status"] == "completed"


def test_workspace_records_input_hash_only_in_state(tmp_path: Path) -> None:
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"data")
    ws = Workspace(tmp_path / "out", apk)
    ws.mark_stage("ingest", "running", input_sha256="x")
    state = ws.load_state()
    assert state["stages"]["ingest"]["input_sha256"] == "x"
    # No content from a previous output directory is embedded in a new workspace.
    assert not (tmp_path / "out" / "recovery" / "exact" / "manifest.json").exists()


def test_no_filters_or_reference_apk_dependency_in_source() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "dex2c_recover"
    lines = [
        line
        for path in root.glob("*.py")
        if True
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    forbidden = ["filters.txt", "original.apk", "pre-protection", "reference_dex"]
    for token in forbidden:
        for line in lines:
            if token not in line:
                continue
            # The only permitted mentions are explicit "no dependency" caveats.
            assert "not required" in line or "no reference apk" in line.lower() or "no " in line, line
    cli = (root / "cli.py").read_text(encoding="utf-8")
    assert "--filters" not in cli
    assert "--reference-apk" not in cli

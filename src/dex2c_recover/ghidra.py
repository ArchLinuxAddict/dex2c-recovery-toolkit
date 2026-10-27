"""Ghidra headless driver and pseudocode ingestion."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .environment import _candidate_paths, _first_existing
from .util import (
    ensure_dir,
    read_jsonl,
    run_command,
    safe_filename,
    sha256_file,
    write_json,
)


def ghidra_path() -> Path | None:
    return _first_existing(_candidate_paths()["ghidra"])


def run_ghidra(
    workspace_root: str | Path,
    library_path: str | Path,
    abi: str,
    *,
    timeout: int = 3600,
    prefixes: str = "Java_,JNI_OnLoad,d2c_",
) -> dict[str, Any]:
    root = Path(workspace_root)
    ghidra = ghidra_path()
    if not ghidra:
        return {"ok": False, "error": "Ghidra analyzeHeadless not available"}
    project_dir = root / "native" / "ghidra" / "projects"
    out_dir = root / "native" / "ghidra" / f"{safe_filename(abi)}__{safe_filename(Path(library_path).name)}"
    ensure_dir(project_dir)
    ensure_dir(out_dir)
    project_name = f"dex2c_{safe_filename(abi)}_{safe_filename(Path(library_path).stem)}"
    script_dir = Path(__file__).resolve().parents[2] / "tools" / "ghidra_scripts"
    result = run_command(
        [
            str(ghidra),
            str(project_dir),
            project_name,
            "-import",
            str(Path(library_path).resolve()),
            "-scriptPath",
            str(script_dir),
            "-postScript",
            "ExportDecomp.java",
            str(out_dir),
            prefixes,
            "-deleteProject",
            "-analysisTimeoutPerFile",
            str(timeout),
        ],
        timeout=timeout + 120,
    )
    index_path = out_dir / "ghidra-functions.jsonl"
    rows = read_jsonl(index_path)
    return {
        "ok": index_path.exists(),
        "abi": abi,
        "library": Path(library_path).name,
        "library_sha256": sha256_file(library_path),
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-4000:],
        "output_dir": str(out_dir),
        "functions": rows,
        "log": str(root / "logs" / f"ghidra-{safe_filename(abi)}-{safe_filename(Path(library_path).name)}.log"),
    }


def collect_pseudocode(workspace_root: str | Path, ghidra_result: dict[str, Any]) -> list[dict[str, Any]]:
    root = Path(workspace_root)
    out_root = root / "native" / "pseudocode" / safe_filename(ghidra_result.get("abi") or "unknown")
    ensure_dir(out_root)
    collected = []
    src_dir = Path(ghidra_result.get("output_dir") or "")
    for row in ghidra_result.get("functions") or []:
        if not row.get("decompiled"):
            continue
        src = src_dir / row.get("decompiled_file", "")
        if not src.exists():
            continue
        name = row.get("name") or "function"
        dst = out_root / f"{safe_filename(name)}.c"
        shutil.copyfile(src, dst)
        collected.append({**row, "pseudocode_path": str(dst)})
    write_json(root / "native" / "ghidra-index.json", collected)
    return collected


def import_ghidra_output(
    workspace_root: str | Path,
    source_dir: str | Path,
    *,
    abi: str,
    library_name: str,
    library_sha256: str | None = None,
) -> dict[str, Any]:
    """Import Ghidra ExportDecomp output produced outside the pipeline.

    The C files are preserved verbatim; only a malformed quote emitted by an
    older copy of the export script is repaired in the index JSONL.
    """
    import re

    root = Path(workspace_root)
    src = Path(source_dir)
    dst = root / "native" / "ghidra" / f"{safe_filename(abi)}__{safe_filename(library_name)}"
    ensure_dir(dst)
    for path in src.glob("*.c"):
        shutil.copyfile(path, dst / path.name)
    index_src = src / "ghidra-functions.jsonl"
    index_dst = dst / "ghidra-functions.jsonl"
    lines = []
    if index_src.exists():
        for line in index_src.read_text(encoding="utf-8").splitlines():
            fixed = re.sub(r'("decompiled":(?:true|false))"', r'\1', line)
            lines.append(fixed)
        index_dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = read_jsonl(index_dst)
    result = {
        "ok": bool(rows),
        "abi": abi,
        "library": library_name,
        "library_sha256": library_sha256,
        "output_dir": str(dst),
        "functions": rows,
        "imported_from": str(src),
    }
    collected = collect_pseudocode(root, result)
    result["collected_pseudocode"] = len(collected)
    run_path = root / "native" / "ghidra-run.json"
    existing = []
    if run_path.exists():
        try:
            import json

            existing = json.loads(run_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = [existing]
        except Exception:
            existing = []
    existing = [x for x in existing if not (x.get("abi") == abi and x.get("library") == library_name)]
    existing.append({k: v for k, v in result.items() if k != "functions"})
    write_json(run_path, existing)
    return result

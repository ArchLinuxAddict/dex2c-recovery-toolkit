"""Reproducible workspace layout and resumable stage state."""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .util import SCHEMA_VERSION, now_utc, read_json, write_json

SUBDIRS = [
    "inventory",
    "inventory/dex",
    "inventory/embedded",
    "extracted",
    "native/elf-analysis",
    "native/disassembly",
    "native/ghidra",
    "native/pseudocode",
    "native/call-graphs",
    "runtime/raw",
    "runtime/validated",
    "recovery/exact",
    "recovery/reconstructed",
    "recovery/partial",
    "validation",
    "provenance",
    "reports",
    "logs",
]


@dataclass
class Workspace:
    root: Path
    apk: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.apk = Path(self.apk)
        for sub in SUBDIRS:
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    @property
    def state_path(self) -> Path:
        return self.root / ".state.json"

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def load_state(self) -> dict[str, Any]:
        state = read_json(self.state_path, None)
        if not isinstance(state, dict):
            state = {
                "schema_version": SCHEMA_VERSION,
                "tool_version": __version__,
                "created_at": now_utc(),
                "stages": {},
            }
        state.setdefault("stages", {})
        return state

    def save_state(self, state: dict[str, Any]) -> None:
        state["updated_at"] = now_utc()
        write_json(self.state_path, state)

    def stage_done(self, name: str, input_sha256: str | None = None) -> bool:
        state = self.load_state()
        stage = state.get("stages", {}).get(name)
        if not isinstance(stage, dict) or stage.get("status") != "completed":
            return False
        if input_sha256 and stage.get("input_sha256") != input_sha256:
            return False
        if stage.get("tool_version") != __version__:
            return False
        return True

    def mark_stage(
        self,
        name: str,
        status: str,
        *,
        input_sha256: str | None = None,
        details: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        state = self.load_state()
        previous = state["stages"].get(name, {}) if isinstance(state["stages"].get(name), dict) else {}
        now = now_utc()
        entry = {
            "status": status,
            "tool_version": __version__,
            "input_sha256": input_sha256,
            "started_at": previous.get("started_at") or now,
            "updated_at": now,
            "details": details or previous.get("details", {}),
        }
        if status == "completed":
            entry["completed_at"] = now
        if error:
            entry["error"] = error[:8000]
        state["stages"][name] = entry
        self.save_state(state)

    def clean_outputs(self) -> None:
        if self.root.exists():
            shutil.rmtree(self.root)
        self.__post_init__()

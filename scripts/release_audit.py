#!/usr/bin/env python3
"""Fail when a public release tree contains prohibited or sensitive content."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {".apk", ".apks", ".xapk", ".dex", ".odex", ".vdex", ".so", ".jar"}
ALLOWED_FIXTURES = {"tests/fixtures/synthetic/Fixture.dex", "tests/fixtures/synthetic/Fixture.apk"}
FORBIDDEN_NAMES = {"protected.apk", "original.apk"}
SECRET_PATTERNS = [
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
]
LOCAL_PATTERNS = [
    re.compile(r"/home/[A-Za-z0-9_.-]+/"),
    re.compile(r"/tmp/kilo/"),
    re.compile(r"\bRZ[0-9A-Z]{8,}\b"),
]


def main() -> int:
    errors: list[str] = []
    files = [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        if path.suffix.lower() in FORBIDDEN_SUFFIXES and rel not in ALLOWED_FIXTURES:
            errors.append(f"forbidden binary extension: {rel}")
        if path.name.lower() in FORBIDDEN_NAMES:
            errors.append(f"forbidden artifact name: {rel}")
        if rel.startswith("assets/"):
            errors.append(f"embedded asset path present: {rel}")
        if path.stat().st_size > 2 * 1024 * 1024:
            errors.append(f"oversized file (>2 MiB): {rel}")
        if rel in {".gitignore", ".gitattributes", "scripts/release_audit.py"} or path.suffix.lower() in {".pyc", ".pyo"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"possible secret pattern in {rel}")
        for pattern in LOCAL_PATTERNS:
            if pattern.search(text):
                errors.append(f"local path/device pattern in {rel}")
    if not (ROOT / "README.md").exists():
        errors.append("README.md missing")
    if not (ROOT / "LICENSE").exists():
        errors.append("LICENSE missing")
    if errors:
        print("release audit failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"release audit passed: {len(files)} files, no prohibited binaries or obvious sensitive patterns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Shared utilities: deterministic serialization, hashing, subprocess wrappers."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TOOL_NAME = "dex2c-recover"
SCHEMA_VERSION = "1.0"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_file(path: str | os.PathLike[str]) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_json(value: Any, *, indent: int | None = 2) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=indent,
        separators=(",", ": ") if indent else (",", ":"),
    )


def write_json(path: str | os.PathLike[str], value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(stable_json(value) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: str | os.PathLike[str], default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def write_jsonl(path: str | os.PathLike[str], rows: Iterable[dict[str, Any]]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(stable_json(row, indent=None))
            fh.write("\n")
            count += 1
    os.replace(tmp, path)
    return count


def read_jsonl(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
        pass
    return rows


def iter_jsonl(path: str | os.PathLike[str]) -> Iterator[dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
    except FileNotFoundError:
        return


def safe_filename(value: str, *, max_len: int = 180) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    if not value:
        value = "item"
    return value[:max_len]


def ensure_dir(path: str | os.PathLike[str]) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
        }

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_command(
    argv: Sequence[str | os.PathLike[str]],
    *,
    timeout: int = 120,
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = False,
) -> CommandResult:
    cmd = [str(x) for x in argv]
    started = time.monotonic()
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=full_env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            errors="replace",
        )
        elapsed = int((time.monotonic() - started) * 1000)
        result = CommandResult(cmd, proc.returncode, proc.stdout, proc.stderr, elapsed)
    except subprocess.TimeoutExpired as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        result = CommandResult(
            cmd,
            -1,
            _as_text(exc.stdout),
            _as_text(exc.stderr),
            elapsed,
            timed_out=True,
        )
    except FileNotFoundError as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        result = CommandResult(cmd, 127, "", str(exc), elapsed)
    if check and not result.ok:
        raise RuntimeError(
            f"command failed ({result.returncode}): {shlex.join(cmd)}\n{result.stderr[-4000:]}"
        )
    return result


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def tool_version(argv: Sequence[str], *, timeout: int = 20) -> dict[str, Any]:
    result = run_command(argv, timeout=timeout)
    text = (result.stdout or "").strip() or (result.stderr or "").strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return {
        "argv": list(argv),
        "available": result.returncode != 127 and not result.timed_out,
        "returncode": result.returncode,
        "version": lines[0][:500] if lines else "",
        "detail": text[-2000:] if not lines else "",
    }


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return str(num)


def relative_to(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(Path(path).resolve())


def clone_workspace_state(path: str | os.PathLike[str]) -> dict[str, Any]:
    return dict(read_json(path, {}) or {})


def atomic_copy(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as inf, open(dst, "wb") as outf:
        outf.writelines(iter(lambda: inf.read(1 << 20), b""))


def temp_dir(prefix: str = "dex2c-recover-") -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix=prefix)


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)

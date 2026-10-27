"""Standalone APK ingestion and nested-artifact inventory."""
from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path
from typing import Any

from .dexparse import parse_header
from .elfs import elf_quick
from .util import (
    md5_file,
    now_utc,
    relative_to,
    safe_filename,
    sha256_bytes,
    sha256_file,
    write_json,
    write_jsonl,
)

MAX_ENTRY_SIZE = 512 * 1024 * 1024
MAX_UNCOMPRESSED_TOTAL = 4 * 1024 * 1024 * 1024
MAX_NESTED_DEPTH = 2


def apk_structure(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    info: dict[str, Any] = {
        "is_zip": False,
        "is_apk_zip": False,
        "zip_test": None,
        "entry_count": 0,
        "has_manifest": False,
        "has_dex": False,
        "has_apk_signing_block": False,
    }
    try:
        info["zip_test"] = zipfile.ZipFile(path).testzip()
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            info["is_zip"] = True
            info["entry_count"] = len(names)
            info["has_manifest"] = "AndroidManifest.xml" in names
            info["has_dex"] = any(n.endswith(".dex") for n in names)
            info["is_apk_zip"] = bool(info["has_manifest"] and info["has_dex"])
    except Exception as exc:
        info["error"] = str(exc)
    try:
        data = path.read_bytes()
        info["has_apk_signing_block"] = b"APK Sig Block 42" in data[-1024 * 1024 :]
    except Exception:
        pass
    return info


def _apk_metadata(path: str | Path) -> dict[str, Any]:
    try:
        from androguard.core.apk import APK

        apk = APK(str(path))
        manifest = apk.get_android_manifest_xml()
        application = manifest.find("application") if manifest is not None else None
        ns = "{http://schemas.android.com/apk/res/android}"
        app_name = application.get(ns + "name", "") if application is not None else ""
        if app_name.startswith("."):
            app_name = apk.get_package() + app_name
        extract_native = application.get(ns + "extractNativeLibs", None) if application is not None else None
        return {
            "ok": True,
            "package": apk.get_package(),
            "version_code": apk.get_androidversion_code(),
            "version_name": apk.get_androidversion_name(),
            "main_activity": apk.get_main_activity(),
            "application_name": app_name,
            "permissions": sorted(apk.get_permissions() or []),
            "min_sdk": _safe_call(apk, "get_min_sdk_version"),
            "target_sdk": _safe_call(apk, "get_target_sdk_version"),
            "extract_native_libs": extract_native,
            "debuggable": _manifest_bool(application, ns + "debuggable") if application is not None else None,
            "allow_backup": _manifest_bool(application, ns + "allowBackup") if application is not None else None,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _safe_call(obj: Any, name: str) -> Any:
    try:
        value = getattr(obj, name)()
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)
    except Exception:
        return None


def _manifest_bool(application: Any, attr: str) -> bool | None:
    try:
        value = application.get(attr)
        if value is None:
            return None
        return value.lower() in ("true", "1")
    except Exception:
        return None


def _extract_zip(path: Path, out_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    total = 0
    with zipfile.ZipFile(path) as zf:
        for entry in zf.infolist():
            name = entry.filename
            if name.endswith("/"):
                continue
            if entry.file_size > MAX_ENTRY_SIZE:
                entries.append({"name": name, "skipped": "entry_too_large", "size": entry.file_size})
                continue
            total += entry.file_size
            if total > MAX_UNCOMPRESSED_TOTAL:
                entries.append({"name": name, "skipped": "archive_too_large", "size": entry.file_size})
                continue
            target = (out_dir / name).resolve()
            try:
                target.relative_to(out_dir.resolve())
            except ValueError:
                entries.append({"name": name, "skipped": "zip_slip"})
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with zf.open(entry) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                entries.append(
                    {
                        "name": name,
                        "size": entry.file_size,
                        "compressed_size": entry.compress_size,
                        "crc": f"0x{entry.CRC:08x}",
                        "method": entry.compress_type,
                        "sha256": sha256_file(target),
                        "extracted_to": str(target),
                    }
                )
            except Exception as exc:
                entries.append({"name": name, "error": str(exc)})
    return entries


def _looks_like_apk(data: bytes) -> bool:
    if not data.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            return "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names)
    except Exception:
        return False


def _nested_apk_metadata(path: Path) -> dict[str, Any]:
    meta = _apk_metadata(path)
    meta["structure"] = apk_structure(path)
    try:
        from androguard.core.apk import APK

        from .dexparse import load_dex

        apk = APK(str(path))
        dexes = []
        for index, raw in enumerate(apk.get_all_dex()):
            dx = load_dex(raw)
            dexes.append(
                {
                    "name": "classes.dex" if index == 0 else f"classes{index + 1}.dex",
                    "sha256": sha256_bytes(raw),
                    "size": len(raw),
                    "classes": len(dx.get_classes()),
                    "methods": sum(len(c.get_methods()) for c in dx.get_classes()),
                    "header": parse_header(raw).as_dict(),
                }
            )
        meta["dex"] = dexes
    except Exception as exc:
        meta["dex_error"] = str(exc)
    return meta


def ingest_apk(apk_path: str | Path, workspace_root: str | Path) -> dict[str, Any]:
    """Inventory a protected APK and extract its contents into the workspace.

    The input APK is never modified.  Extracted and nested artifacts are kept
    separate from any recovered artifact directories.
    """
    apk_path = Path(apk_path).resolve()
    root = Path(workspace_root).resolve()
    extracted = root / "extracted" / "apk"
    embedded_root = root / "inventory" / "embedded"
    if extracted.exists():
        shutil.rmtree(extracted)
    extracted.mkdir(parents=True, exist_ok=True)
    embedded_root.mkdir(parents=True, exist_ok=True)

    before = {
        "path": str(apk_path),
        "size": apk_path.stat().st_size,
        "mtime_ns": apk_path.stat().st_mtime_ns,
        "sha256": sha256_file(apk_path),
        "md5": md5_file(apk_path),
    }
    structure = apk_structure(apk_path)
    if not structure.get("is_zip"):
        raise ValueError(f"input is not a ZIP/APK: {structure.get('error')}")
    if not structure.get("has_dex"):
        raise ValueError("input contains no DEX files")
    if not structure.get("has_manifest"):
        raise ValueError("input contains no AndroidManifest.xml")

    extracted_entries = _extract_zip(apk_path, extracted)
    entries_by_name = {e["name"]: e for e in extracted_entries if "sha256" in e}

    dex_rows: list[dict[str, Any]] = []
    for name in sorted(entries_by_name):
        if not name.endswith(".dex"):
            continue
        path = extracted / name
        data = path.read_bytes()
        row: dict[str, Any] = {
            "name": name,
            "path": relative_to(path, root),
            "size": len(data),
            "sha256": sha256_bytes(data),
            "zip_entry": name,
            "valid": False,
        }
        try:
            header = parse_header(data)
            row["header"] = header.as_dict()
            row["valid"] = header.checksum_ok and header.signature_ok and header.file_size == len(data)
            row["version"] = header.version
            row["classes"] = header.class_defs_size
            row["methods"] = header.method_ids_size
            row["strings"] = header.string_ids_size
            row["parse_error"] = None
        except Exception as exc:
            row["parse_error"] = str(exc)
        dex_rows.append(row)

    native_rows: list[dict[str, Any]] = []
    for name in sorted(entries_by_name):
        if not name.startswith("lib/") or not name.endswith(".so"):
            continue
        parts = name.split("/")
        abi = parts[1] if len(parts) > 2 else ""
        path = extracted / name
        quick = elf_quick(path)
        row = {
            "name": Path(name).name,
            "zip_entry": name,
            "path": relative_to(path, root),
            "abi": abi,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
            "elf": quick,
        }
        native_rows.append(row)

    # Nested APKs and archives embedded in assets/unknown locations.
    embedded: list[dict[str, Any]] = []
    seen_hashes: dict[str, str] = {}
    for entry in sorted(extracted_entries, key=lambda x: x.get("name", "")):
        name = entry.get("name", "")
        if "sha256" not in entry:
            continue
        if name.endswith((".dex", ".so")) or name in ("AndroidManifest.xml", "resources.arsc"):
            continue
        path = extracted / name
        try:
            head = path.read_bytes()[:4]
        except Exception:
            continue
        if head != b"PK\x03\x04":
            continue
        data = path.read_bytes()
        if not _looks_like_apk(data):
            continue
        sha = entry["sha256"]
        if sha in seen_hashes:
            continue
        seen_hashes[sha] = name
        nested_dir = embedded_root / f"{sha[:16]}_{safe_filename(name)}"
        nested_dir.mkdir(parents=True, exist_ok=True)
        nested_apk_path = nested_dir / "artifact.apk"
        nested_apk_path.write_bytes(data)
        nested_extract = nested_dir / "extracted"
        nested_extract.mkdir(exist_ok=True)
        nested_entries = _extract_zip(nested_apk_path, nested_extract)
        meta = _nested_apk_metadata(nested_apk_path)
        embedded.append(
            {
                "origin_zip_entry": name,
                "sha256": sha,
                "size": len(data),
                "path": relative_to(nested_apk_path, root),
                "extracted_dir": relative_to(nested_extract, root),
                "role": "embedded_apk_artifact",
                "is_input": False,
                "device_install_candidate": False,
                "metadata": meta,
                "extracted_entries": nested_entries,
            }
        )

    assets = []
    for name in sorted(entries_by_name):
        if name.startswith(("assets/", "res/raw/", "unknown/")) or name.endswith((".bin", ".dat", ".prof", ".profm")):
            e = entries_by_name[name]
            assets.append(
                {
                    "name": name,
                    "size": e.get("size"),
                    "sha256": e.get("sha256"),
                    "path": relative_to(root / "extracted" / "apk" / name, root),
                }
            )
    resources = [
        {"name": name, "size": entries_by_name[name].get("size"), "sha256": entries_by_name[name].get("sha256")}
        for name in sorted(entries_by_name)
        if name.startswith("res/") and not name.startswith("res/raw/")
    ]

    after = {
        "size": apk_path.stat().st_size,
        "mtime_ns": apk_path.stat().st_mtime_ns,
        "sha256": sha256_file(apk_path),
        "unchanged": False,
    }
    after["unchanged"] = (
        before["size"] == after["size"]
        and before["mtime_ns"] == after["mtime_ns"]
        and before["sha256"] == after["sha256"]
    )

    manifest = _apk_metadata(apk_path)
    inputs = {
        "schema_version": "1.0",
        "generated_at": now_utc(),
        "input": {
            "provided_path": str(apk_path),
            "absolute_path": str(apk_path),
            "filename": apk_path.name,
            "size": before["size"],
            "sha256": before["sha256"],
            "md5": before["md5"],
            "mtime_ns": before["mtime_ns"],
            "immutability": before["sha256"] == after["sha256"] and before["mtime_ns"] == after["mtime_ns"],
        },
        "structure": structure,
        "manifest": manifest,
        "extracted_dir": relative_to(extracted, root),
        "dex": dex_rows,
        "native_libraries": native_rows,
        "embedded_apks": embedded,
        "assets": assets,
        "resources": resources,
        "zip_entries": extracted_entries,
        "extraction_limits": {
            "max_entry_size": MAX_ENTRY_SIZE,
            "max_uncompressed_total": MAX_UNCOMPRESSED_TOTAL,
            "max_nested_depth": MAX_NESTED_DEPTH,
        },
    }
    write_json(root / "inventory" / "inputs.json", inputs)
    write_jsonl(
        root / "inventory" / "dex.jsonl",
        [
            {
                "name": row["name"],
                "path": row["path"],
                "size": row["size"],
                "sha256": row["sha256"],
                "valid": row["valid"],
                "classes": row.get("classes"),
                "methods": row.get("methods"),
                "strings": row.get("strings"),
                "header": row.get("header"),
                "parse_error": row.get("parse_error"),
            }
            for row in dex_rows
        ],
    )
    write_json(root / "inventory" / "native-libraries.json", native_rows)
    write_json(root / "inventory" / "embedded-artifacts.json", embedded)
    write_jsonl(root / "inventory" / "zip-entries.jsonl", extracted_entries)
    return inputs


def find_dex_paths(workspace_root: str | Path) -> list[Path]:
    root = Path(workspace_root)
    out = []
    for path in sorted((root / "extracted" / "apk").glob("*.dex")):
        out.append(path)
    return out


def find_native_paths(workspace_root: str | Path) -> list[tuple[str, Path]]:
    root = Path(workspace_root)
    out = []
    base = root / "extracted" / "apk" / "lib"
    if not base.exists():
        return out
    for abi_dir in sorted(base.iterdir()):
        if not abi_dir.is_dir():
            continue
        for path in sorted(abi_dir.glob("*.so")):
            out.append((abi_dir.name, path))
    return out

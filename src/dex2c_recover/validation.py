"""Independent structural validation for DEX, ELF, and reconstructed artifacts."""
from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

from .dexparse import parse_header
from .elfs import elf_quick
from .environment import _candidate_paths, _first_existing
from .util import run_command, sha256_file, write_json, write_jsonl


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    start = offset
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
        if shift > 35:
            break
    raise ValueError(f"invalid uleb128 at 0x{start:x}")


def _checked_offset(off: int, size: int, file_size: int, label: str, errors: list[str]) -> bool:
    if off < 0 or off > file_size or size < 0 or off + size > file_size:
        errors.append(f"{label} out of bounds: off=0x{off:x} size=0x{size:x} file=0x{file_size:x}")
        return False
    return True


def validate_dex(path: str | Path, *, run_external: bool = False) -> dict[str, Any]:
    path = Path(path)
    result: dict[str, Any] = {
        "path": str(path),
        "sha256": sha256_file(path) if path.exists() else None,
        "size": path.stat().st_size if path.exists() else None,
        "valid": False,
        "errors": [],
        "warnings": [],
        "checks": {},
        "external": [],
    }
    try:
        data = path.read_bytes()
        header = parse_header(data)
        result["header"] = header.as_dict()
        result["checks"].update(
            {
                "magic": DEX_MAGIC_OK(header),
                "file_size": header.file_size == len(data),
                "checksum": header.checksum_ok,
                "signature": header.signature_ok,
                "header_size": header.header_size == 0x70,
                "endian_tag": header.endian_tag in (0x12345678, 0x78563412),
            }
        )
        if not result["checks"]["magic"]:
            result["errors"].append("unsupported DEX magic/version")
        if not result["checks"]["file_size"]:
            result["errors"].append(f"header file_size {header.file_size} != actual {len(data)}")
        if not result["checks"]["checksum"]:
            result["errors"].append("Adler-32 checksum mismatch")
        if not result["checks"]["signature"]:
            result["errors"].append("SHA-1 signature mismatch")
        if header.header_size != 0x70:
            result["errors"].append(f"header_size {header.header_size} != 0x70")
        # Table bounds.
        tables = [
            ("string_ids", header.string_ids_off, header.string_ids_size * 4),
            ("type_ids", header.type_ids_off, header.type_ids_size * 4),
            ("proto_ids", header.proto_ids_off, header.proto_ids_size * 12),
            ("field_ids", header.field_ids_off, header.field_ids_size * 8),
            ("method_ids", header.method_ids_off, header.method_ids_size * 8),
            ("class_defs", header.class_defs_off, header.class_defs_size * 32),
            ("data", header.data_off, header.data_size),
        ]
        for label, off, size in tables:
            if size == 0:
                continue
            if not _checked_offset(off, size, len(data), label, result["errors"]):
                result["checks"][label] = False
            else:
                result["checks"][label] = True
        # String data and type indexes.
        string_offsets: list[int] = []
        if _checked_offset(header.string_ids_off, header.string_ids_size * 4, len(data), "string_ids", result["errors"]):
            for i in range(header.string_ids_size):
                off = struct.unpack_from("<I", data, header.string_ids_off + i * 4)[0]
                string_offsets.append(off)
                if off >= len(data):
                    result["errors"].append(f"string_data_off[{i}] out of bounds")
                    break
        type_ids: list[int] = []
        if _checked_offset(header.type_ids_off, header.type_ids_size * 4, len(data), "type_ids", result["errors"]):
            for i in range(header.type_ids_size):
                idx = struct.unpack_from("<I", data, header.type_ids_off + i * 4)[0]
                type_ids.append(idx)
                if idx >= header.string_ids_size:
                    result["errors"].append(f"type_ids[{i}] -> string {idx} out of range")
                    break
        if _checked_offset(header.proto_ids_off, header.proto_ids_size * 12, len(data), "proto_ids", result["errors"]):
            for i in range(header.proto_ids_size):
                shorty, ret_type, params_off = struct.unpack_from("<III", data, header.proto_ids_off + i * 12)
                if shorty >= header.string_ids_size or (type_ids and ret_type >= len(type_ids)):
                    result["errors"].append(f"proto_ids[{i}] invalid indexes")
                    break
                if params_off and not _validate_type_list(data, params_off, header.type_ids_size, result["warnings"]):
                    result["errors"].append(f"proto_ids[{i}] invalid parameter type_list")
                    break
        field_ids: list[tuple[int, int, int]] = []
        if _checked_offset(header.field_ids_off, header.field_ids_size * 8, len(data), "field_ids", result["errors"]):
            for i in range(header.field_ids_size):
                class_idx, type_idx, name_idx = struct.unpack_from("<HHI", data, header.field_ids_off + i * 8)
                field_ids.append((class_idx, type_idx, name_idx))
                if class_idx >= len(type_ids) or type_idx >= len(type_ids) or name_idx >= header.string_ids_size:
                    result["errors"].append(f"field_ids[{i}] invalid indexes")
                    break
        method_ids: list[tuple[int, int, int]] = []
        if _checked_offset(header.method_ids_off, header.method_ids_size * 8, len(data), "method_ids", result["errors"]):
            for i in range(header.method_ids_size):
                class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, header.method_ids_off + i * 8)
                method_ids.append((class_idx, proto_idx, name_idx))
                if class_idx >= len(type_ids) or proto_idx >= header.proto_ids_size or name_idx >= header.string_ids_size:
                    result["errors"].append(f"method_ids[{i}] invalid indexes")
                    break
        classes: set[str] = set()
        methods: set[tuple[str, str, str]] = set()
        code_items = 0
        if _checked_offset(header.class_defs_off, header.class_defs_size * 32, len(data), "class_defs", result["errors"]):
            for i in range(header.class_defs_size):
                (
                    class_idx, access, super_idx, interfaces_off, source_idx, annotations_off,
                    class_data_off, static_values_off,
                ) = struct.unpack_from("<8I", data, header.class_defs_off + i * 32)
                if class_idx >= len(type_ids):
                    result["errors"].append(f"class_defs[{i}] class_idx out of range")
                    continue
                class_name = _string_at(data, string_offsets, type_ids[class_idx]) if type_ids else None
                if class_name:
                    if class_name in classes:
                        result["errors"].append(f"duplicate class {class_name}")
                    classes.add(class_name)
                if super_idx and super_idx >= len(type_ids):
                    result["errors"].append(f"class_defs[{i}] superclass_idx out of range")
                if interfaces_off and not _validate_type_list(data, interfaces_off, header.type_ids_size, result["warnings"]):
                    result["errors"].append(f"class_defs[{i}] invalid interfaces type_list")
                if class_data_off:
                    try:
                        class_data_info = _parse_class_data(data, class_data_off, header.method_ids_size, header.field_ids_size)
                        code_items += class_data_info["code_items"]
                        for mrec in class_data_info["methods"]:
                            mkey = (class_name or f"class{i}", str(mrec["method_idx"]), str(mrec["code_off"]))
                            if mkey in methods:
                                result["errors"].append(f"duplicate encoded method in {class_name}")
                            methods.add(mkey)
                    except Exception as exc:
                        result["errors"].append(f"class_defs[{i}] class_data error: {exc}")
        result["classes"] = len(classes)
        result["methods"] = header.method_ids_size
        result["code_items"] = code_items
        # Decode all instructions with androguard.  This is independent of the
        # structural parser above and catches malformed instruction streams.
        try:
            from androguard.core.dex import DEX

            dex = DEX(data)
            decoded = 0
            for cls in dex.get_classes():
                for method in cls.get_methods():
                    code = method.get_code()
                    if code is None:
                        continue
                    for ins in method.get_instructions():
                        decoded += 1
            result["decoded_instructions"] = decoded
            result["checks"]["instruction_decode"] = True
        except Exception as exc:
            result["checks"]["instruction_decode"] = False
            result["errors"].append(f"instruction decode failed: {exc}")
        if run_external:
            # dexdump is an independent Android tool when available.
            dexdump = _first_existing(_candidate_paths()["dexdump"])
            if dexdump:
                with tempfile.NamedTemporaryFile(prefix="dexdump-", suffix=".txt", delete=False) as tmp:
                    tmp_path = tmp.name
                try:
                    cmd = run_command([str(dexdump), "-d", "-o", tmp_path, str(path)], timeout=180)
                    result["external"].append(
                        {"tool": "dexdump", "path": str(dexdump), "returncode": cmd.returncode, "ok": cmd.ok, "stderr": cmd.stderr[-4000:]}
                    )
                    if not cmd.ok:
                        result["errors"].append(f"dexdump failed: {cmd.stderr[-1000:]}")
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
            baksmali = _first_existing(_candidate_paths()["baksmali"])
            if baksmali:
                with tempfile.TemporaryDirectory(prefix="baksmali-") as tmpdir:
                    cmd = run_command(["java", "-jar", str(baksmali), "d", str(path), "-o", tmpdir], timeout=180)
                    result["external"].append(
                        {"tool": "baksmali", "path": str(baksmali), "returncode": cmd.returncode, "ok": cmd.ok, "stderr": cmd.stderr[-4000:]}
                    )
                    if not cmd.ok:
                        result["errors"].append(f"baksmali failed: {cmd.stderr[-1000:]}")
        result["valid"] = not result["errors"] and result["checks"].get("instruction_decode", False)
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def DEX_MAGIC_OK(header: Any) -> bool:
    return header.magic.startswith("dex\n") and header.version in (35, 36, 37, 38, 39, 40, 41)


def _string_at(data: bytes, string_offsets: list[int], string_idx: int) -> str | None:
    if string_idx >= len(string_offsets):
        return None
    off = string_offsets[string_idx]
    try:
        _, pos = _uleb128(data, off)
        end = data.find(b"\x00", pos)
        if end < 0:
            return None
        return data[pos:end].decode("utf-8", "replace")
    except Exception:
        return None


def _validate_type_list(data: bytes, off: int, type_count: int, warnings: list[str]) -> bool:
    if off + 4 > len(data):
        return False
    size = struct.unpack_from("<I", data, off)[0]
    if size > 100000 or off + 4 + size * 2 > len(data):
        return False
    for i in range(size):
        idx = struct.unpack_from("<H", data, off + 4 + i * 2)[0]
        if idx >= type_count:
            return False
    if size > 65535:
        warnings.append("large type_list")
    return True


def _parse_class_data(data: bytes, off: int, method_count: int, field_count: int) -> dict[str, Any]:
    pos = off
    static_fields, pos = _uleb128(data, pos)
    instance_fields, pos = _uleb128(data, pos)
    direct_methods, pos = _uleb128(data, pos)
    virtual_methods, pos = _uleb128(data, pos)
    if static_fields + instance_fields > field_count + 100000 or direct_methods + virtual_methods > method_count + 100000:
        raise ValueError("implausible field/method counts")
    field_idx = 0
    for _ in range(static_fields):
        diff, pos = _uleb128(data, pos)
        _access, pos = _uleb128(data, pos)
        field_idx += diff
        if field_idx >= field_count:
            raise ValueError("static field index out of range")
    field_idx = 0
    for _ in range(instance_fields):
        diff, pos = _uleb128(data, pos)
        _access, pos = _uleb128(data, pos)
        field_idx += diff
        if field_idx >= field_count:
            raise ValueError("instance field index out of range")
    methods = []
    code_items = 0
    for count in (direct_methods, virtual_methods):
        method_idx = 0
        for _ in range(count):
            diff, pos = _uleb128(data, pos)
            _access, pos = _uleb128(data, pos)
            code_off, pos = _uleb128(data, pos)
            method_idx += diff
            if method_idx >= method_count:
                raise ValueError("method index out of range")
            if code_off:
                if code_off + 16 > len(data):
                    raise ValueError("code_off out of range")
                registers, ins, outs, tries, _debug, insns = struct.unpack_from("<HHHHII", data, code_off)
                if insns > 10000000 or code_off + 16 + insns * 2 > len(data):
                    raise ValueError("insns_size out of range")
                code_items += 1
            methods.append({"method_idx": method_idx, "code_off": code_off})
    return {"methods": methods, "code_items": code_items}


def validate_elf(path: str | Path, abi: str | None = None) -> dict[str, Any]:
    quick = elf_quick(path)
    result = {
        "path": str(path),
        "sha256": sha256_file(path),
        "size": Path(path).stat().st_size,
        "abi_expected": abi,
        "elf": quick,
        "valid": bool(quick.get("valid")),
        "errors": [],
        "warnings": [],
    }
    if quick.get("valid"):
        if abi and quick.get("abi_guess") and quick.get("abi_guess") != abi:
            result["errors"].append(f"ABI guess {quick.get('abi_guess')} does not match directory ABI {abi}")
        if quick.get("class") not in ("ELF32", "ELF64"):
            result["errors"].append("unexpected ELF class")
    else:
        result["errors"].append(quick.get("error") or "invalid ELF")
    result["valid"] = not result["errors"]
    return result


def validate_workspace(workspace_root: str | Path, *, run_external: bool = False) -> dict[str, Any]:
    root = Path(workspace_root)
    dex_results = []
    candidates = sorted((root / "extracted" / "apk").glob("*.dex"))
    candidates += sorted((root / "recovery" / "exact").glob("*.dex"))
    candidates += sorted((root / "recovery" / "reconstructed").glob("**/*.dex"))
    for path in sorted(set(candidates)):
        dex_results.append(validate_dex(path, run_external=run_external))
    write_jsonl(root / "validation" / "dex.jsonl", dex_results)

    elf_results = []
    for path in sorted((root / "extracted" / "apk" / "lib").glob("*/*.so")):
        elf_results.append(validate_elf(path, path.parent.name))
    for path in sorted((root / "recovery" / "reconstructed").glob("**/*.so")):
        elf_results.append(validate_elf(path))
    write_jsonl(root / "validation" / "native.jsonl", elf_results)
    summary = {
        "dex": {
            "total": len(dex_results),
            "valid": sum(1 for r in dex_results if r["valid"]),
            "invalid": sum(1 for r in dex_results if not r["valid"]),
        },
        "native": {
            "total": len(elf_results),
            "valid": sum(1 for r in elf_results if r["valid"]),
            "invalid": sum(1 for r in elf_results if not r["valid"]),
        },
    }
    write_json(root / "validation" / "summary.json", summary)
    return {"dex": dex_results, "native": elf_results, "summary": summary}

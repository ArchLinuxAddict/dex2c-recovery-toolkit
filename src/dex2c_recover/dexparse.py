"""DEX ingestion, method inventory, loader evidence, and DEX-to-DEX comparison."""
from __future__ import annotations

import hashlib
import re
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # androguard emits loguru diagnostics for malformed APKs; keep stdout clean.
    from loguru import logger as _loguru_logger

    _loguru_logger.remove()
except Exception:  # pragma: no cover
    pass

from .jni import (
    jni_long_name,
    jni_short_name,
    method_class_params,
    normalize_descriptor,
)
from .util import sha256_bytes

DEX_MAGIC_RE = re.compile(rb"^dex\n[0-9]{3}\x00$")


@dataclass
class DexHeader:
    magic: str
    version: int
    checksum: int
    checksum_ok: bool
    signature: str
    signature_ok: bool
    file_size: int
    header_size: int
    endian_tag: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int
    map_off: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "version": self.version,
            "checksum": f"0x{self.checksum:08x}",
            "checksum_ok": self.checksum_ok,
            "signature": self.signature,
            "signature_ok": self.signature_ok,
            "file_size": self.file_size,
            "header_size": self.header_size,
            "endian_tag": f"0x{self.endian_tag:08x}",
            "string_ids_size": self.string_ids_size,
            "string_ids_off": self.string_ids_off,
            "type_ids_size": self.type_ids_size,
            "type_ids_off": self.type_ids_off,
            "proto_ids_size": self.proto_ids_size,
            "proto_ids_off": self.proto_ids_off,
            "field_ids_size": self.field_ids_size,
            "field_ids_off": self.field_ids_off,
            "method_ids_size": self.method_ids_size,
            "method_ids_off": self.method_ids_off,
            "class_defs_size": self.class_defs_size,
            "class_defs_off": self.class_defs_off,
            "data_size": self.data_size,
            "data_off": self.data_off,
            "map_off": self.map_off,
        }


def parse_header(data: bytes) -> DexHeader:
    if len(data) < 0x70:
        raise ValueError(f"DEX too small: {len(data)} bytes")
    magic = data[:8]
    if not DEX_MAGIC_RE.match(magic):
        raise ValueError(f"bad DEX magic: {magic!r}")
    version = int(magic[4:7].decode("ascii"))
    checksum = struct.unpack_from("<I", data, 8)[0]
    stored_sig = data[12:32]
    calc_checksum = zlib.adler32(data[12:]) & 0xFFFFFFFF
    calc_sig = hashlib.sha1(data[32:]).digest()
    (
        file_size,
        header_size,
        endian_tag,
        _link_size,
        _link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    ) = struct.unpack_from("<20I", data, 32)
    return DexHeader(
        magic=magic.decode("latin-1"),
        version=version,
        checksum=checksum,
        checksum_ok=checksum == calc_checksum,
        signature=stored_sig.hex(),
        signature_ok=stored_sig == calc_sig,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        string_ids_size=string_ids_size,
        string_ids_off=string_ids_off,
        type_ids_size=type_ids_size,
        type_ids_off=type_ids_off,
        proto_ids_size=proto_ids_size,
        proto_ids_off=proto_ids_off,
        field_ids_size=field_ids_size,
        field_ids_off=field_ids_off,
        method_ids_size=method_ids_size,
        method_ids_off=method_ids_off,
        class_defs_size=class_defs_size,
        class_defs_off=class_defs_off,
        data_size=data_size,
        data_off=data_off,
        map_off=map_off,
    )


def load_dex(data: bytes):
    from androguard.core.dex import DEX

    return DEX(data)


def load_apk_dex(apk_path: str | Path) -> list[tuple[str, bytes, Any]]:
    from androguard.core.apk import APK

    apk = APK(str(apk_path))
    out: list[tuple[str, bytes, Any]] = []
    for index, raw in enumerate(apk.get_all_dex()):
        name = "classes.dex" if index == 0 else f"classes{index + 1}.dex"
        out.append((name, raw, load_dex(raw)))
    return out


def dex_name_for_index(index: int) -> str:
    return "classes.dex" if index == 0 else f"classes{index + 1}.dex"


def access_flags(flags: int) -> list[str]:
    names = [
        (0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
        (0x10, "final"), (0x20, "synchronized"), (0x40, "bridge"),
        (0x80, "varargs"), (0x100, "native"), (0x200, "interface"),
        (0x400, "abstract"), (0x800, "strictfp"), (0x1000, "synthetic"),
        (0x2000, "annotation"), (0x4000, "enum"), (0x10000, "constructor"),
        (0x20000, "declared_synchronized"),
    ]
    return [name for bit, name in names if flags & bit]


def _code_info(method: Any) -> dict[str, Any]:
    code = method.get_code() if hasattr(method, "get_code") else None
    if code is None:
        return {
            "code_present": False,
            "registers_size": None,
            "ins_size": None,
            "outs_size": None,
            "tries_size": None,
            "insns_size": None,
            "code_item_sha256": None,
            "code_item_size": None,
        }
    try:
        raw = bytes(code.get_raw())
    except Exception:
        raw = b""
    return {
        "code_present": True,
        "registers_size": getattr(code, "registers_size", None),
        "ins_size": getattr(code, "ins_size", None),
        "outs_size": getattr(code, "outs_size", None),
        "tries_size": getattr(code, "tries_size", None),
        "insns_size": getattr(code, "insns_size", None),
        "code_item_sha256": sha256_bytes(raw) if raw else None,
        "code_item_size": len(raw) if raw else None,
    }


def _annotation_types(annotation_set_item: Any, cm: Any) -> list[str]:
    out: list[str] = []
    try:
        for off_item in annotation_set_item.get_annotation_off_item():
            annotation_item = cm.get_obj_by_offset(off_item.get_annotation_off())
            annotation = annotation_item.get_annotation()
            type_idx = annotation.get_type_idx()
            out.append(cm.get_type(type_idx))
    except Exception:
        pass
    return sorted(set(out))


def dex_strings(dex: Any) -> list[str]:
    try:
        return list(dex.get_strings())
    except Exception:
        return []


def iter_classes(dex: Any, dex_name: str, dex_sha256: str) -> Iterator[dict[str, Any]]:
    cm = getattr(dex, "CM", None)
    for cls in dex.get_classes():
        name = cls.get_name()
        method_objs = list(cls.get_methods())
        field_objs = list(cls.get_fields())
        native = []
        code = []
        for m in method_objs:
            flags = m.get_access_flags()
            if flags & 0x100:
                native.append(m)
            if m.get_code() is not None:
                code.append(m)
        annotations = sorted(set(cls.get_annotations() or []))
        method_annotations: dict[str, list[str]] = {}
        adi = getattr(cls, "annotations_directory_item", None)
        if adi is not None and cm is not None:
            try:
                for mi in adi.get_method_annotations():
                    offset = mi.get_annotations_off()
                    if offset:
                        item = cm.get_obj_by_offset(offset)
                        method_annotations[str(mi.get_method_idx())] = _annotation_types(item, cm)
            except Exception:
                pass
        clinit = any(m.get_name() == "<clinit>" for m in method_objs)
        source_file_idx = getattr(cls, "get_source_file_idx", lambda: None)()
        source_file = None
        if isinstance(source_file_idx, int) and source_file_idx not in (-1, 0xFFFFFFFF):
            strings = dex_strings(dex)
            if 0 <= source_file_idx < len(strings):
                source_file = strings[source_file_idx]
        yield {
            "dex_file": dex_name,
            "dex_sha256": dex_sha256,
            "descriptor": name,
            "access_flags": cls.get_access_flags(),
            "access_flags_hex": f"0x{cls.get_access_flags():x}",
            "access": access_flags(cls.get_access_flags()),
            "superclass": cls.get_superclassname(),
            "interfaces": sorted(cls.get_interfaces() or []),
            "source_file": source_file,
            "source_file_idx": source_file_idx,
            "annotations": annotations,
            "method_annotations": method_annotations,
            "method_count": len(method_objs),
            "native_count": len(native),
            "code_count": len(code),
            "field_count": len(field_objs),
            "native_ratio": (len(native) / len(method_objs)) if method_objs else 0.0,
            "all_methods_native": bool(method_objs) and len(native) == len(method_objs),
            "has_native_constructor": any(m.get_name() == "<init>" for m in native),
            "has_clinit": clinit,
            "fields": [
                {
                    "name": f.get_name(),
                    "descriptor": normalize_descriptor(f.get_descriptor()),
                    "access_flags": f.get_access_flags(),
                    "access": access_flags(f.get_access_flags()),
                }
                for f in field_objs
            ],
        }


def iter_methods(dex: Any, dex_name: str, dex_sha256: str) -> Iterator[dict[str, Any]]:
    for cls in dex.get_classes():
        cls_name = cls.get_name()
        cls_annotations = sorted(set(cls.get_annotations() or []))
        for method in cls.get_methods():
            flags = method.get_access_flags()
            descriptor = normalize_descriptor(method.get_descriptor())
            info = _code_info(method)
            record = {
                "method_key": f"{cls_name}->{method.get_name()}{descriptor}",
                "dex_file": dex_name,
                "dex_sha256": dex_sha256,
                "class": cls_name,
                "class_access_flags": cls.get_access_flags(),
                "class_annotations": cls_annotations,
                "method": method.get_name(),
                "descriptor": descriptor,
                "access_flags": flags,
                "access_flags_hex": f"0x{flags:x}",
                "access": access_flags(flags),
                "native": bool(flags & 0x100),
                "abstract": bool(flags & 0x400),
                "synthetic": bool(flags & 0x1000),
                "static": bool(flags & 0x8),
                "constructor": method.get_name() in ("<init>", "<clinit>"),
                "class_initializer": method.get_name() == "<clinit>",
                "jni_long_name": jni_long_name(cls_name, method.get_name(), descriptor),
                "jni_short_name": jni_short_name(cls_name, method.get_name()),
                "method_index": getattr(method, "get_idx", lambda: None)(),
                **info,
            }
            ret, params = method_class_params(descriptor)
            record["return_type"] = ret
            record["parameter_types"] = params
            record["dalvik_parameter_words"] = sum(2 if x in ("J", "D") else 1 for x in params)
            yield record


def method_key(record: dict[str, Any]) -> str:
    return f"{record['class']}->{record['method']}{record['descriptor']}"


def method_instructions(method: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for index, ins in enumerate(method.get_instructions()):
            out.append(
                {
                    "index": index,
                    "name": ins.get_name(),
                    "output": ins.get_output(),
                    "opcode": ins.get_op_value(),
                    "length": ins.get_length(),
                }
            )
    except Exception:
        pass
    return out


def find_library_loads(dex: Any, dex_name: str) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for cls in dex.get_classes():
        cls_name = cls.get_name()
        for method in cls.get_methods():
            if method.get_code() is None:
                continue
            instructions = method_instructions(method)
            for index, ins in enumerate(instructions):
                output = ins.get("output", "")
                if "loadLibrary" not in output and "Ljava/lang/System;->load(" not in output:
                    continue
                library = None
                for prev in reversed(instructions[max(0, index - 4) : index]):
                    if prev["name"].startswith("const-string"):
                        text = prev["output"]
                        first_quote = text.find('"')
                        last_quote = text.rfind('"')
                        if first_quote >= 0 and last_quote > first_quote:
                            library = text[first_quote + 1 : last_quote]
                        break
                evidence.append(
                    {
                        "dex_file": dex_name,
                        "class": cls_name,
                        "method": method.get_name(),
                        "descriptor": normalize_descriptor(method.get_descriptor()),
                        "library": library,
                        "instruction": output,
                        "instruction_index": index,
                    }
                )
    return evidence


def interesting_strings(dex: Any) -> list[dict[str, Any]]:
    strings = dex_strings(dex)
    patterns = {
        "class_descriptor": re.compile(r"^L[^;]+;$"),
        "library_name": re.compile(r"^(lib)?[A-Za-z0-9_.-]+\.so$|^[A-Za-z0-9_.-]+$"),
        "method_signature": re.compile(r"^\([^)]*\)[A-Za-z0-9_/;\[]+$"),
        "jni_symbol": re.compile(r"^Java_|^JNI_OnLoad$"),
        "dex2c_marker": re.compile(r"(?i)dex2c|d2c|registerNatives|libstub"),
    }
    out: list[dict[str, Any]] = []
    for index, value in enumerate(strings):
        for kind, pattern in patterns.items():
            if pattern.search(value):
                if kind == "library_name" and len(value) > 128:
                    continue
                if kind == "library_name" and not (
                    value.endswith(".so") or ("/" not in value and "." not in value)
                ):
                    continue
                out.append({"index": index, "kind": kind, "value": value})
                break
    return out


def diff_dex(a: Any, b: Any, a_name: str, b_name: str) -> dict[str, Any]:
    """Compare two DEXs by class/method signature and code-item hash."""

    def build(dex: Any, name: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for cls in dex.get_classes():
            for m in cls.get_methods():
                rec = {
                    "class": cls.get_name(),
                    "method": m.get_name(),
                    "descriptor": normalize_descriptor(m.get_descriptor()),
                    "access_flags": m.get_access_flags(),
                    "code_item_sha256": _code_info(m)["code_item_sha256"],
                    "code_present": m.get_code() is not None,
                }
                out[method_key(rec)] = rec
        return out

    amap = build(a, a_name)
    bmap = build(b, b_name)
    common = sorted(set(amap) & set(bmap))
    only_a = sorted(set(amap) - set(bmap))
    only_b = sorted(set(bmap) - set(amap))
    access_diff = [k for k in common if amap[k]["access_flags"] != bmap[k]["access_flags"]]
    code_diff = [
        k
        for k in common
        if amap[k]["code_item_sha256"] != bmap[k]["code_item_sha256"]
        or amap[k]["code_present"] != bmap[k]["code_present"]
    ]
    return {
        "a_dex": a_name,
        "b_dex": b_name,
        "a_methods": len(amap),
        "b_methods": len(bmap),
        "common_methods": len(common),
        "only_a": only_a,
        "only_b": only_b,
        "access_flag_differences": access_diff,
        "code_differences": code_diff,
        "exact_signature_coverage": (len(common) / max(1, len(amap))),
    }


def code_item_bytes(method: Any) -> bytes | None:
    code = method.get_code()
    if code is None:
        return None
    try:
        return bytes(code.get_raw())
    except Exception:
        return None


def instruction_text(method: Any) -> str:
    return "\n".join(f"{ins['name']} {ins['output']}".strip() for ins in method_instructions(method))

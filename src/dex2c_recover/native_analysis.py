"""Native disassembly, control-flow evidence, and conservative semantic classification."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from .elfs import (
    _detect_memory_offset,
    _disassembler,
    _section_bytes,
    function_symbols,
)
from .jni import jnienv_name_for_offset, normalize_descriptor
from .util import safe_filename, write_json, write_jsonl

try:
    import capstone
except Exception:  # pragma: no cover
    capstone = None


SAFE_JNI_CALLS = {"NewLocalRef", "DeleteLocalRef", "ExceptionCheck", "GetVersion"}


def _vaddr_to_text(elf: ELFFile, addr: int, size: int) -> bytes | None:
    for sec in elf.iter_sections():
        try:
            start = int(sec["sh_addr"])
            end = start + int(sec["sh_size"])
            if start <= addr < end and sec["sh_type"] != "SHT_NOBITS":
                data = sec.data()
                rel = addr - start
                return data[rel : rel + size]
        except Exception:
            continue
    return None


def _next_function_address(symbols: list[dict[str, Any]], address: int) -> int | None:
    later = sorted({s["value"] for s in symbols if s.get("value", 0) > address and s.get("type") in ("STT_FUNC", "STT_GNU_IFUNC")})
    return later[0] if later else None


def _function_size(elf: ELFFile, info: dict[str, Any], address: int, declared_size: int | None) -> int:
    if declared_size and declared_size > 0:
        return declared_size
    next_addr = _next_function_address(function_symbols(info), address)
    if next_addr and next_addr > address:
        return min(next_addr - address, 256 * 1024)
    text = elf.get_section_by_name(".text")
    if text is not None:
        end = int(text["sh_addr"]) + int(text["sh_size"])
        if address < end:
            return min(end - address, 64 * 1024)
    return 4096


def _branch_target(insn: Any) -> int | None:
    if not insn.operands:
        return None
    op = insn.operands[0]
    if getattr(op, "type", None) == 2:
        try:
            return int(op.imm)
        except Exception:
            return None
    return None


def _is_call(insn: Any) -> bool:
    return insn.mnemonic.lower() in ("bl", "blx", "call", "callq")


def _is_ret(insn: Any) -> bool:
    return insn.mnemonic.lower() in ("ret", "retq")


def _immediate_from_instruction(insn: Any) -> int | None:
    """Return a constant written to w0/x0 by a simple instruction, if evident."""
    mnemonic = insn.mnemonic.lower()
    op_str = insn.op_str.lower().replace(" ", "")
    if not (op_str.startswith("w0") or op_str.startswith("x0")):
        return None
    if mnemonic in ("mov", "movz", "movn", "orr", "add", "sub", "eor") and "," in op_str:
        rhs = op_str.split(",", 1)[1]
        if rhs in ("wzr", "xzr"):
            return 0
        match = re.search(r"#(-?0x[0-9a-f]+|-?\d+)", rhs)
        if match:
            try:
                value = int(match.group(1), 0)
                if mnemonic == "movn":
                    value = ~value & 0xFFFFFFFF
                return value
            except ValueError:
                return None
    return None


def _semantic_analysis(insns: list[Any], return_type: str, jni_calls: list[dict[str, Any]], arch: str) -> dict[str, Any]:
    direct_calls = []
    for insn in insns:
        if _is_call(insn):
            target = _branch_target(insn)
            direct_calls.append({"address": insn.address, "target": target, "text": f"{insn.mnemonic} {insn.op_str}"})
    external_direct_calls = [c for c in direct_calls if c["target"] is not None and not (insns and insns[0].address <= c["target"] <= insns[-1].address)]
    allowed_jni = [c for c in jni_calls if c.get("jni_function") in SAFE_JNI_CALLS]
    unsafe_jni = [c for c in jni_calls if c.get("jni_function") not in SAFE_JNI_CALLS]
    unsupported_reasons: list[str] = []
    if arch != "aarch64":
        unsupported_reasons.append("semantic classifier currently supports AArch64 only")
    if external_direct_calls:
        unsupported_reasons.append(f"function makes {len(external_direct_calls)} non-JNI direct call(s)")
    if unsafe_jni:
        unsupported_reasons.append(
            "function calls JNI operations with observable/runtime semantics: "
            + ", ".join(sorted({str(c.get('jni_function')) for c in unsafe_jni}))
        )
    if any(insn.mnemonic.lower() in ("bl", "b") and _branch_target(insn) is not None for insn in insns):
        # Branches to other functions are not necessarily unsupported; supported
        # leaves may branch within themselves.  Only external calls matter.
        pass
    kind = "unsupported"
    value = None
    if not unsupported_reasons:
        if return_type == "V" or return_type == "void":
            kind = "return_void_noop"
        else:
            rets = [insn for insn in insns if _is_ret(insn)]
            if rets:
                values = []
                for ret in rets:
                    index = insns.index(ret)
                    found = None
                    for prev in reversed(insns[max(0, index - 16) : index]):
                        candidate = _immediate_from_instruction(prev)
                        if candidate is not None:
                            found = candidate
                            break
                        if prev.mnemonic.lower() in ("cbnz", "cbz", "b", "b.eq", "b.ne", "tbnz", "tbz"):
                            break
                    values.append(found)
                if values and all(v is not None and v == values[0] for v in values):
                    value = values[0]
                    kind = "return_constant"
                else:
                    unsupported_reasons.append("return value is not a single constant on all paths")
            else:
                unsupported_reasons.append("no reachable return instruction")
    if unsupported_reasons:
        kind = "unsupported"
        value = None
    return {
        "supported": kind != "unsupported",
        "kind": kind,
        "value": value,
        "return_type": return_type,
        "allowed_jni_calls": sorted({c.get("jni_function") for c in allowed_jni}),
        "unsafe_jni_calls": sorted({c.get("jni_function") for c in unsafe_jni}),
        "direct_calls": direct_calls[:100],
        "external_direct_calls": external_direct_calls[:50],
        "reason": "; ".join(unsupported_reasons) if unsupported_reasons else "native body is a side-effect-free leaf on the analyzed path",
        "limitations": [
            "A supported classification describes observable Java-level behavior only; JNI local-reference allocation is not represented in Dalvik",
            "The classifier does not prove equivalence for paths not represented in the native disassembly",
        ],
    }


def _build_cfg(insns: list[Any]) -> dict[str, Any]:
    if not insns:
        return {"blocks": [], "edges": []}
    addresses = {insn.address for insn in insns}
    starts = {insns[0].address}
    for insn in insns:
        mnemonic = insn.mnemonic.lower()
        if mnemonic.startswith("b") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz", "bl", "blx", "call", "callq"):
            target = _branch_target(insn)
            if target in addresses:
                starts.add(target)
    ordered = sorted(addresses)
    starts.add(ordered[0])
    start_list = sorted(starts)
    blocks = []
    for index, start in enumerate(start_list):
        end = start_list[index + 1] if index + 1 < len(start_list) else None
        members = [addr for addr in ordered if addr >= start and (end is None or addr < end)]
        if not members:
            continue
        blocks.append(
            {
                "start": start,
                "end": members[-1],
                "instructions": len(members),
            }
        )
    edges = []
    for insn in insns:
        target = _branch_target(insn)
        if target in addresses:
            edges.append({"from": insn.address, "to": target, "kind": "branch", "text": f"{insn.mnemonic} {insn.op_str}"})
    return {"blocks": blocks, "edges": edges}


def analyze_function(
    elffile_path: str | Path,
    elf_info: dict[str, Any],
    *,
    address: int,
    size: int | None,
    method: dict[str, Any],
    function_name: str | None,
    abi: str,
) -> dict[str, Any]:
    path = Path(elffile_path)
    record: dict[str, Any] = {
        "method_key": f"{method['class']}->{method['method']}{normalize_descriptor(method['descriptor'])}",
        "class": method["class"],
        "method": method["method"],
        "descriptor": method["descriptor"],
        "return_type": method.get("return_type") or normalize_descriptor(method["descriptor"]).split(")")[-1],
        "abi": abi,
        "library": elf_info.get("name"),
        "library_sha256": elf_info.get("sha256"),
        "function_name": function_name,
        "address": address,
        "declared_size": size,
        "file_offset": None,
        "instruction_count": 0,
        "jni_env_calls": [],
        "direct_calls": [],
        "cfg": {"blocks": [], "edges": []},
        "semantic": None,
        "disassembly_file": None,
        "errors": [],
    }
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            machine = elf_info.get("machine") or "aarch64"
            actual_size = _function_size(elf, elf_info, address, size)
            raw = _vaddr_to_text(elf, address, actual_size)
            if raw is None:
                record["errors"].append("address is not backed by a file section")
                return record
            record["size"] = len(raw)
            disasm = _disassembler(machine, elf.elfclass)
            if disasm is None:
                record["errors"].append(f"no disassembler for {machine}")
                return record
            insns = list(disasm.disasm(raw, address))
            record["instruction_count"] = len(insns)
            string_constants = []
            for insn in insns:
                if insn.mnemonic.lower() != "adr" or not insn.operands:
                    continue
                target = _branch_target(insn)
                if target is None:
                    continue
                data = _vaddr_to_text(elf, target, 512)
                if not data:
                    continue
                end = data.find(b"\x00")
                if end < 4:
                    continue
                try:
                    value = data[:end].decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if value and all(c.isprintable() for c in value):
                    string_constants.append(value[:500])
            record["string_constants"] = string_constants[:100]
            text = "\n".join(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".strip() for insn in insns)
            record["disassembly"] = text
            jni_calls = []
            pending: dict[str, dict[str, Any]] = {}
            for insn in insns:
                base, disp = _detect_memory_offset(insn)
                mnemonic = insn.mnemonic.lower()
                if disp is not None and disp >= 0 and disp % 8 == 0:
                    name = jnienv_name_for_offset(disp)
                    if name and not name.startswith("reserved"):
                        if machine == "aarch64" and mnemonic == "ldr" and insn.operands:
                            pending[insn.reg_name(insn.operands[0].reg)] = {
                                "address": insn.address,
                                "table_offset": disp,
                                "jni_function": name,
                                "table_index": disp // 8,
                            }
                        elif machine.startswith("x86") and mnemonic.startswith("mov") and insn.operands:
                            try:
                                reg = insn.reg_name(insn.operands[0].reg)
                            except Exception:
                                reg = None
                            if reg:
                                pending[reg] = {
                                    "address": insn.address,
                                    "table_offset": disp,
                                    "jni_function": name,
                                    "table_index": disp // 8,
                                }
                if mnemonic in ("blr", "br", "blx", "call", "jmp") and insn.operands:
                    try:
                        reg = insn.reg_name(insn.operands[0].reg) if getattr(insn.operands[0], "type", None) == 1 else None
                    except Exception:
                        reg = None
                    if reg and reg in pending:
                        call = dict(pending[reg])
                        call["call_address"] = insn.address
                        jni_calls.append(call)
                        pending.pop(reg, None)
                    elif _branch_target(insn) is not None:
                        pending.clear()
                if _is_call(insn):
                    target = _branch_target(insn)
                    record["direct_calls"].append({"address": insn.address, "target": target, "text": f"{insn.mnemonic} {insn.op_str}"})
            record["jni_env_calls"] = jni_calls
            record["cfg"] = _build_cfg(insns)
            record["semantic"] = _semantic_analysis(insns, record["return_type"], jni_calls, machine)
    except Exception as exc:
        record["errors"].append(str(exc))
    return record


def analyze_mappings(
    workspace_root: str | Path,
    methods: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    libraries: list[dict[str, Any]],
    *,
    abis: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = Path(workspace_root)
    abis = abis or ["arm64-v8a", "x86_64", "armeabi-v7a", "x86"]
    libs_by_key = {(lib.get("name"), lib.get("abi")): lib for lib in libraries}
    methods_by_key = {f"{m['class']}->{m['method']}{m['descriptor']}": m for m in methods}
    functions: list[dict[str, Any]] = []
    seen = set()
    for mapping in mappings:
        method = methods_by_key.get(mapping["method_key"])
        if not method:
            continue
        for cand in mapping.get("candidates") or []:
            abi = cand.get("abi")
            if abi not in abis:
                continue
            lib = libs_by_key.get((cand.get("library"), abi))
            if not lib or not cand.get("address"):
                continue
            key = (cand.get("library"), abi, int(cand["address"]), mapping["method_key"])
            if key in seen:
                continue
            seen.add(key)
            rec = analyze_function(
                lib.get("path"),
                lib,
                address=int(cand["address"]),
                size=cand.get("size"),
                method=method,
                function_name=cand.get("symbol"),
                abi=abi,
            )
            rec["mapping_source"] = cand.get("source")
            rec["mapping_status"] = mapping.get("mapping_status")
            rec["disassembly_file"] = str(
                root / "native" / "disassembly" / f"{safe_filename(abi)}__{safe_filename(lib.get('name','lib'))}__{int(cand['address']):x}.asm"
            )
            functions.append(rec)
    # Sort and write disassembly files.
    functions.sort(key=lambda r: (r["abi"], r["library"], r["address"], r["method_key"]))
    for rec in functions:
        path = Path(rec["disassembly_file"])
        path.parent.mkdir(parents=True, exist_ok=True)
        header = (
            f"; Native function {rec.get('function_name') or hex(rec['address'])}\n"
            f"; ABI {rec['abi']}; library {rec['library']}; method {rec['method_key']}\n"
            f"; address 0x{rec['address']:x}; declared size {rec.get('declared_size')}; analyzed size {rec.get('size')}\n"
            f"; JNI calls: {', '.join(c.get('jni_function','?') for c in rec.get('jni_env_calls', []))}\n\n"
        )
        path.write_text(header + rec.get("disassembly", "") + "\n", encoding="utf-8")
    summary = {
        "functions_analyzed": len(functions),
        "by_abi": dict(sorted(Counter(r["abi"] for r in functions).items())),
        "by_library": dict(sorted(Counter(r["library"] for r in functions).items())),
        "semantic_supported": sum(1 for r in functions if (r.get("semantic") or {}).get("supported")),
        "semantic_unsupported": sum(1 for r in functions if not (r.get("semantic") or {}).get("supported")),
        "with_jni_calls": sum(1 for r in functions if r.get("jni_env_calls")),
        "errors": sum(1 for r in functions if r.get("errors")),
    }
    write_json(root / "native" / "function-analysis.json", [{k: v for k, v in r.items() if k != "disassembly"} for r in functions])
    write_jsonl(root / "native" / "function-analysis.jsonl", [{k: v for k, v in r.items() if k != "disassembly"} for r in functions])
    return functions, summary


def build_call_graphs(workspace_root: str | Path, libraries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    root = Path(workspace_root)
    graphs = []
    for lib in libraries:
        if lib.get("abi") not in ("arm64-v8a", "x86_64", "armeabi-v7a", "x86"):
            continue
        exports = {int(s["value"]): s["name"] for s in lib.get("jni_exports") or [] if s.get("value")}
        if not exports:
            continue
        try:
            with open(lib["path"], "rb") as fh:
                elf = ELFFile(fh)
                text = _section_bytes(elf, ".text")
                if not text:
                    continue
                text_bytes, text_addr = text
                disasm = _disassembler(lib.get("machine") or "aarch64", elf.elfclass)
                if disasm is None:
                    continue
                nodes = [{"address": a, "name": n, "size": next((s.get("size") for s in lib.get("jni_exports") or [] if s.get("name") == n), 0)} for a, n in exports.items()]
                edges = []
                current = None
                for insn in disasm.disasm(text_bytes, text_addr):
                    if insn.address in exports:
                        current = insn.address
                    if current is None:
                        continue
                    if insn.mnemonic.lower() in ("bl", "call", "callq"):
                        target = _branch_target(insn)
                        if target:
                            edges.append({"from": current, "to": target, "target_name": exports.get(target), "address": insn.address})
                graph = {
                    "library": lib.get("name"),
                    "abi": lib.get("abi"),
                    "nodes": sorted(nodes, key=lambda x: x["address"]),
                    "edges": sorted(edges, key=lambda x: (x["from"], x["address"])),
                }
                graphs.append(graph)
                out = root / "native" / "call-graphs" / f"{safe_filename(lib.get('abi'))}__{safe_filename(lib.get('name'))}.json"
                write_json(out, graph)
        except Exception:
            continue
    return graphs

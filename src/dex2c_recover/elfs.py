"""Native ELF inventory, JNI export discovery, disassembly, and registration scans."""
from __future__ import annotations

import re
import struct
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .jni import is_jni_export, jnienv_name_for_offset
from .util import sha256_file

try:
    import capstone
except Exception:  # pragma: no cover
    capstone = None


INTERESTING_PATTERNS = {
    "class_descriptor": re.compile(r"^L[A-Za-z0-9_$/]+;$"),
    "method_signature": re.compile(r"^\([^)]*\)[A-Za-z0-9_/;$\[+]+$"),
    "jni_symbol": re.compile(r"^(Java_|JNI_OnLoad$)"),
    "library": re.compile(r"^(lib)?[A-Za-z0-9_.-]+\.so$"),
    "dex2c_runtime": re.compile(r"dex2c|d2c_|RegisterNatives|JNI_OnLoad|libstub", re.IGNORECASE),
    "hook_or_root": re.compile(r"frida|xhook|ptrace|magisk|SignatureKiller|/proc/self/maps|inotify", re.IGNORECASE),
    "android_framework": re.compile(r"^(android|java|javax|kotlin|androidx|com/google)/"),
}


def _machine_name(machine: Any) -> str:
    if isinstance(machine, str):
        return {
            "EM_386": "x86", "EM_MIPS": "mips", "EM_ARM": "arm",
            "EM_X86_64": "x86_64", "EM_AARCH64": "aarch64",
            "EM_RISCV": "riscv", "EM_PPC64": "ppc64", "EM_S390": "s390",
            "EM_SPARC": "sparc",
        }.get(machine, machine.lower().replace("em_", ""))
    return {
        3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64",
        243: "riscv", 21: "ppc64", 22: "s390", 2: "sparc",
    }.get(machine, f"machine-{machine}")


def _abi_from_machine(machine: str) -> str | None:
    return {
        "aarch64": "arm64-v8a",
        "arm": "armeabi-v7a",
        "x86": "x86",
        "x86_64": "x86_64",
        "riscv": "riscv64",
    }.get(machine)


def _read_cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace")


def elf_quick(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read(64)
            if len(data) < 20 or data[:4] != b"\x7fELF":
                return {"valid": False, "error": "not an ELF file"}
            is_64 = data[4] == 2
            endian = "<" if data[5] == 1 else ">"
            if is_64:
                e_type, e_machine, e_version, e_entry = struct.unpack_from(endian + "HHIQ", data, 16)
            else:
                e_type, e_machine, e_version, e_entry = struct.unpack_from(endian + "HHII", data, 16)
            return {
                "valid": True,
                "class": "ELF64" if is_64 else "ELF32",
                "endianness": "little" if data[5] == 1 else "big",
                "machine_id": e_machine,
                "machine": _machine_name(e_machine),
                "abi_guess": _abi_from_machine(_machine_name(e_machine)),
                "type": e_type,
                "entry": e_entry,
            }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def _disassembler(machine: str, bits: int):
    if capstone is None:
        return None
    arch = getattr(capstone, "CS_ARCH_ARM64", None)
    if arch is None:
        arch = getattr(capstone, "CS_ARCH_AARCH64", None)
    try:
        if machine == "aarch64":
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        elif machine == "arm":
            cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
        elif machine == "x86_64":
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif machine == "x86":
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            return None
        cs.detail = True
        return cs
    except Exception:
        return None
    return None


def _detect_memory_offset(insn: Any) -> tuple[str | None, int | None]:
    for op in insn.operands:
        if getattr(op, "type", None) == 3 and getattr(op, "mem", None) is not None:
            mem = op.mem
            base = insn.reg_name(mem.base) if mem.base else None
            disp = int(mem.disp or 0)
            return base, disp
    # x86 uses base + disp
    for op in insn.operands:
        if getattr(op, "type", None) == 3 and getattr(op, "mem", None) is not None:
            mem = op.mem
            return insn.reg_name(mem.base) if mem.base else None, int(mem.disp or 0)
    return None, None


def _scan_jni_table_calls(disasm: Any, text_bytes: bytes, text_addr: int, machine: str) -> list[dict[str, Any]]:
    if disasm is None:
        return []
    calls: list[dict[str, Any]] = []
    pending: dict[str, dict[str, Any]] = {}
    try:
        for insn in disasm.disasm(text_bytes, text_addr):
            mnemonic = insn.mnemonic.lower()
            base, disp = _detect_memory_offset(insn)
            if disp is not None and disp >= 0 and disp % 8 == 0:
                name = jnienv_name_for_offset(disp)
                if name and not name.startswith("reserved") and disp <= 0x7FF:
                    if machine == "aarch64" and mnemonic == "ldr" and base:
                        pending[insn.reg_name(insn.operands[0].reg)] = {
                            "address": insn.address,
                            "table_offset": disp,
                            "jni_function": name,
                            "table_index": disp // 8,
                            "load_register": insn.reg_name(insn.operands[0].reg),
                            "base_register": base,
                        }
                    elif machine == "x86_64" and mnemonic.startswith("mov") and base:
                        reg = insn.reg_name(insn.operands[0].reg) if insn.operands else None
                        if reg:
                            pending[reg] = {
                                "address": insn.address,
                                "table_offset": disp,
                                "jni_function": name,
                                "table_index": disp // 8,
                                "load_register": reg,
                                "base_register": base,
                            }
            if mnemonic in ("blr", "br", "blx", "b", "call", "jmp"):
                target_reg = None
                if insn.operands and getattr(insn.operands[0], "type", None) == 1:
                    try:
                        target_reg = insn.reg_name(insn.operands[0].reg)
                    except Exception:
                        target_reg = None
                if target_reg and target_reg in pending:
                    rec = dict(pending[target_reg])
                    rec["call_address"] = insn.address
                    calls.append(rec)
                    pending.pop(target_reg, None)
                elif insn.operands and getattr(insn.operands[0], "type", None) == 2:
                    pending.clear()
    except Exception:
        pass
    return calls


def _section_bytes(elf: ELFFile, name: str) -> tuple[bytes, int] | None:
    sec = elf.get_section_by_name(name)
    if sec is None:
        return None
    try:
        return sec.data(), int(sec["sh_addr"])
    except Exception:
        return None


def _pointer_map(elf: ELFFile) -> dict[int, int]:
    """Map virtual addresses in loadable data to pointer values from relocations."""
    pointers: dict[int, int] = {}
    for sec in elf.iter_sections():
        if sec["sh_type"] not in ("SHT_RELA", "SHT_REL"):
            continue
        try:
            relocs = sec.iter_relocations()
        except Exception:
            continue
        for reloc in relocs:
            try:
                offset = int(reloc["r_offset"])
                addend = int(reloc["r_addend"]) if reloc["r_addend"] is not None else 0
                if addend == 0:
                    addend = _read_vaddr_pointer(elf, offset)
                pointers[offset] = addend
            except Exception:
                continue
    return pointers


def _read_vaddr_pointer(elf: ELFFile, addr: int) -> int:
    for sec in elf.iter_sections():
        start = int(sec["sh_addr"])
        size = int(sec["sh_size"])
        if start <= addr < start + size and sec["sh_type"] != "SHT_NOBITS":
            data = sec.data()
            rel = addr - start
            if rel + 8 <= len(data):
                return struct.unpack_from("<Q", data, rel)[0]
    return 0


def _vaddr_read(elf: ELFFile, addr: int, count: int) -> bytes | None:
    for sec in elf.iter_sections():
        start = int(sec["sh_addr"])
        size = int(sec["sh_size"])
        if start <= addr < start + size and sec["sh_type"] != "SHT_NOBITS":
            data = sec.data()
            rel = addr - start
            if rel < len(data):
                return data[rel : rel + count]
    return None


def _vaddr_cstring(elf: ELFFile, addr: int, limit: int = 512) -> str | None:
    data = _vaddr_read(elf, addr, limit)
    if not data:
        return None
    end = data.find(b"\x00")
    if end < 0:
        return None
    try:
        value = data[:end].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not value or any(c < " " or c > "~" for c in value):
        return None
    return value


def _parse_native_method_tables(elf: ELFFile, info: dict[str, Any]) -> list[dict[str, Any]]:
    pointers = _pointer_map(elf)
    exec_ranges: list[tuple[int, int]] = []
    for sec in elf.iter_sections():
        try:
            if int(sec["sh_flags"]) & 0x4 and int(sec["sh_size"]) > 0:
                exec_ranges.append((int(sec["sh_addr"]), int(sec["sh_addr"]) + int(sec["sh_size"])))
        except Exception:
            continue

    def executable(addr: int) -> bool:
        return any(start <= addr < end for start, end in exec_ranges)

    entries: list[dict[str, Any]] = []
    data_sections = [".data.rel.ro", ".data", ".rodata"]
    for sec_name in data_sections:
        sec = elf.get_section_by_name(sec_name)
        if sec is None or sec["sh_type"] == "SHT_NOBITS":
            continue
        try:
            data = sec.data()
            base = int(sec["sh_addr"])
        except Exception:
            continue
        rel = 0
        while rel + 24 <= len(data):
            addr = base + rel
            p0 = pointers.get(addr, struct.unpack_from("<Q", data, rel)[0])
            p1 = pointers.get(addr + 8, struct.unpack_from("<Q", data, rel + 8)[0])
            p2 = pointers.get(addr + 16, struct.unpack_from("<Q", data, rel + 16)[0])
            name = _vaddr_cstring(elf, p0, 256) if p0 and p1 and p2 else None
            sig = _vaddr_cstring(elf, p1, 512) if p0 and p1 and p2 else None
            if (
                not name
                or not sig
                or not sig.startswith("(")
                or ")" not in sig
                or not re.match(r"^[A-Za-z0-9_$<>]+$", name)
                or not executable(p2)
            ):
                rel += 8
                continue
            entries.append(
                {
                    "array_address": addr,
                    "name": name,
                    "signature": sig,
                    "function_address": p2,
                    "name_address": p0,
                    "signature_address": p1,
                    "section": sec_name,
                    "relocation_backed": False,
                }
            )
            entries[-1]["relocation_backed"] = any(
                candidate in pointers for candidate in (addr, addr + 8, addr + 16)
            )
            rel += 24
    # Collapse consecutive entries into arrays.
    entries.sort(key=lambda x: x["array_address"])
    arrays: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for entry in entries:
        duplicate_in_current = any(
            item["name"] == entry["name"] and item["signature"] == entry["signature"]
            for item in current
        )
        if current and (entry["array_address"] != current[-1]["array_address"] + 24 or duplicate_in_current):
            arrays.append({
                "array_address": current[0]["array_address"],
                "size": len(current),
                "entries": current,
            })
            current = []
        current.append(entry)
    if current:
        arrays.append({
            "array_address": current[0]["array_address"],
            "size": len(current),
            "entries": current,
        })
    info["native_method_tables"] = arrays
    return arrays


def analyze_elf(path: str | Path, *, abi: str | None = None, max_strings: int = 4000) -> dict[str, Any]:
    path = Path(path)
    result: dict[str, Any] = {
        "path": str(path),
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "abi": abi,
        "valid": False,
    }
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            machine = _machine_name(elf.header.e_machine)
            result.update(
                {
                    "valid": True,
                    "elf_class": "ELF32" if elf.elfclass == 32 else "ELF64",
                    "endianness": "little" if elf.little_endian else "big",
                    "machine": machine,
                    "machine_id": elf.header.e_machine,
                    "type": elf.header.e_type,
                    "entry": elf.header.e_entry,
                    "abi_guess": _abi_from_machine(machine),
                    "soname": None,
                    "needed": [],
                    "build_id": None,
                    "sections": [],
                    "segments": [],
                    "dynamic_symbols": 0,
                    "symtab_symbols": 0,
                    "stripped": True,
                    "jni_exports": [],
                    "imports": [],
                    "jni_onload": None,
                    "strings_of_interest": [],
                    "native_method_tables": [],
                    "jni_env_calls": [],
                    "register_natives_calls": [],
                }
            )
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_SONAME":
                        result["soname"] = tag.soname
                    elif tag.entry.d_tag == "DT_NEEDED":
                        result["needed"].append(tag.needed)
            for sec in elf.iter_sections():
                try:
                    result["sections"].append(
                        {
                            "name": sec.name,
                            "type": sec["sh_type"],
                            "address": int(sec["sh_addr"]),
                            "offset": int(sec["sh_offset"]),
                            "size": int(sec["sh_size"]),
                            "flags": int(sec["sh_flags"]),
                        }
                    )
                except Exception:
                    continue
            for segment in elf.iter_segments():
                try:
                    header = segment.header
                    result["segments"].append(
                        {
                            "type": header.p_type,
                            "offset": int(header.p_offset),
                            "vaddr": int(header.p_vaddr),
                            "filesz": int(header.p_filesz),
                            "memsz": int(header.p_memsz),
                            "flags": int(header.p_flags),
                        }
                    )
                except Exception:
                    continue
            symbols: list[dict[str, Any]] = []
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                if section.name == ".symtab":
                    result["symtab_symbols"] = section.num_symbols()
                elif section.name == ".dynsym":
                    result["dynamic_symbols"] = section.num_symbols()
                for sym in section.iter_symbols():
                    try:
                        entry = {
                            "name": sym.name,
                            "value": int(sym["st_value"]),
                            "size": int(sym["st_size"]),
                            "type": str(sym["st_info"]["type"]),
                            "bind": str(sym["st_info"]["bind"]),
                            "shndx": int(sym["st_shndx"]) if isinstance(sym["st_shndx"], int) else str(sym["st_shndx"]),
                            "section": section.name,
                        }
                    except Exception:
                        continue
                    if entry["shndx"] != 0 and entry["name"]:
                        symbols.append(entry)
                    elif not entry["name"]:
                        continue
                    elif section.name == ".dynsym":
                        result["imports"].append(entry["name"])
            result["stripped"] = not any(sec.name == ".symtab" for sec in elf.iter_sections())
            for sym in symbols:
                if sym["type"] in ("STT_FUNC", "STT_GNU_IFUNC") and is_jni_export(sym["name"]):
                    result["jni_exports"].append(sym)
                    if sym["name"] == "JNI_OnLoad":
                        result["jni_onload"] = sym
            result["imports"] = sorted(set(result["imports"]))
            note = elf.get_section_by_name(".note.gnu.build-id")
            if note is not None:
                try:
                    data = note.data()
                    if len(data) > 16:
                        result["build_id"] = data[16:].hex()
                except Exception:
                    pass
            text = _section_bytes(elf, ".text")
            if text:
                text_bytes, text_addr = text
                disasm = _disassembler(machine, elf.elfclass)
                calls = _scan_jni_table_calls(disasm, text_bytes, text_addr, machine)
                result["jni_env_calls"] = calls[:5000]
                result["register_natives_calls"] = [
                    call for call in calls if call.get("jni_function") == "RegisterNatives"
                ]
            # String extraction (bounded; read whole file, filter printable).
            data = path.read_bytes()
            strings = []
            for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
                value = match.group(0).decode("ascii", "replace")
                for kind, pattern in INTERESTING_PATTERNS.items():
                    if pattern.search(value):
                        strings.append({"offset": match.start(), "kind": kind, "value": value[:500]})
                        break
                if len(strings) >= max_strings:
                    break
            result["strings_of_interest"] = strings
            result["native_method_tables"] = []
            _parse_native_method_tables(elf, result)
            result["role"] = classify_library(result)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def classify_library(info: dict[str, Any]) -> str:
    name = (info.get("name") or "").lower()
    soname = (info.get("soname") or "").lower()
    exports = info.get("jni_exports") or []
    imports = set(info.get("imports") or [])
    if not info.get("valid"):
        return "invalid_elf"
    if info.get("register_natives_calls"):
        return "jni_dynamic_registration_library"
    if "signaturekiller" in name or "signaturekiller" in soname or "xhook" in imports:
        return "third_party_protection_library"
    if len(exports) >= 20 and ("stub" in name or "stub" in soname or "dex2c" in " ".join(info.get("needed") or [])):
        return "dex2c_generated_library"
    if len(exports) > 0:
        if any(token in (soname or name) for token in ("androidx", "kotlin", "play", "firebase", "gms")):
            return "third_party_native_library"
        if len(exports) >= 20:
            return "large_jni_library"
        return "small_jni_library"
    if info.get("jni_onload"):
        return "jni_onload_without_exports"
    return "unrelated_or_support"


def demangle_export_names(names: Iterable[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for name in sorted(set(names)):
        if name.startswith("Java_"):
            out.append({"symbol": name, "kind": "java_export"})
        elif name == "JNI_OnLoad":
            out.append({"symbol": name, "kind": "jni_onload"})
    return out


def function_symbols(elf_info: dict[str, Any]) -> list[dict[str, Any]]:
    funcs = []
    for sym in elf_info.get("jni_exports", []):
        if sym.get("type") in ("STT_FUNC", "STT_GNU_IFUNC"):
            funcs.append(sym)
    if elf_info.get("jni_onload"):
        funcs.append(elf_info["jni_onload"])
    return sorted(funcs, key=lambda s: (s["value"], s["name"]))


def compare_abi_libraries(infos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for info in infos:
        grouped[info["name"]][info.get("abi") or "?"] = info
    rows: list[dict[str, Any]] = []
    for name, by_abi in sorted(grouped.items()):
        abis = sorted(by_abi)
        export_sets = {abi: {x["name"] for x in by_abi[abi].get("jni_exports", [])} for abi in abis}
        all_exports = set().union(*export_sets.values()) if export_sets else set()
        common = set.intersection(*export_sets.values()) if export_sets else set()
        rows.append(
            {
                "library": name,
                "abis": abis,
                "hashes": {abi: by_abi[abi].get("sha256") for abi in abis},
                "machines": {abi: by_abi[abi].get("machine") for abi in abis},
                "jni_export_counts": {abi: len(export_sets[abi]) for abi in abis},
                "common_jni_exports": sorted(common),
                "abi_only_exports": {abi: sorted(export_sets[abi] - common) for abi in abis},
                "same_export_set": all(export_sets[abi] == common for abi in abis),
                "union_jni_exports": sorted(all_exports),
            }
        )
    return rows

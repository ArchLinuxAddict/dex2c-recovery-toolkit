"""Exact artifact recovery and conservative equivalent-Dex reconstruction."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from .dexparse import (
    diff_dex,
    load_dex,
    method_key,
    normalize_descriptor,
)
from .environment import _candidate_paths, _first_existing
from .jni import method_class_params
from .util import (
    ensure_dir,
    read_json,
    run_command,
    safe_filename,
    sha256_file,
    write_json,
    write_jsonl,
)


def _descriptor_to_smali_type(desc: str) -> str:
    return normalize_descriptor(desc)


def _access_to_smali_method(flags: int) -> str:
    names = []
    for bit, name in [
        (0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
        (0x10, "final"), (0x20, "synchronized"), (0x40, "bridge"),
        (0x80, "varargs"), (0x400, "abstract"), (0x800, "strictfp"),
        (0x1000, "synthetic"), (0x10000, "constructor"),
    ]:
        if flags & bit and name not in ("bridge", "varargs", "constructor"):
            names.append(name)
    return " ".join(names)


def _access_to_smali_field(flags: int) -> str:
    names = []
    for bit, name in [
        (0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
        (0x10, "final"), (0x40, "volatile"), (0x80, "transient"),
        (0x1000, "synthetic"), (0x4000, "enum"),
    ]:
        if flags & bit:
            names.append(name)
    return " ".join(names)


def _class_smali_header(cls: dict[str, Any]) -> list[str]:
    access = _access_to_smali_field(cls.get("access_flags") or 0)
    # class access flags overlap field flags for the common modifiers
    return [f".class {access} {cls['descriptor']}".replace("  ", " "), f".super {cls.get('superclass') or 'Ljava/lang/Object;'}"]


def _constant_body(value: int, registers: int) -> list[str]:
    if value == 0:
        return ["    const/4 v0, 0x0", "    return v0"]
    if -32768 <= value <= 32767:
        return [f"    const/16 v0, {value}", "    return v0"]
    return [f"    const v0, {value}", "    return v0"]


def _register_count(descriptor: str, static: bool) -> int:
    _, params = method_class_params(descriptor)
    words = sum(2 if p in ("J", "D") else 1 for p in params)
    ins = words + (0 if static else 1)
    return ins + 1


def _render_reconstructed_method(method: dict[str, Any], semantic: dict[str, Any], cls: dict[str, Any]) -> str:
    flags = int(method.get("access_flags") or 0) & ~0x100
    if flags & 0x400:
        flags &= ~0x400
    access = _access_to_smali_method(flags)
    descriptor = normalize_descriptor(method["descriptor"])
    static = bool(flags & 0x8)
    registers = _register_count(descriptor, static)
    lines = [
        "",
        f".method {access} {method['method']}{descriptor}".replace("  ", " "),
        f"    .registers {registers}",
        "",
    ]
    kind = (semantic or {}).get("kind")
    if kind == "return_void_noop":
        lines.append("    return-void")
    elif kind == "return_constant":
        lines.extend(_constant_body(int((semantic or {}).get("value") or 0), registers))
    else:
        raise ValueError(f"unsupported semantic kind {kind}")
    lines.extend(["", ".end method", ""])
    return "\n".join(lines)


def _render_class(cls: dict[str, Any], methods: list[dict[str, Any]], semantics: dict[str, dict[str, Any]]) -> str:
    lines = _class_smali_header(cls)
    for iface in cls.get("interfaces") or []:
        lines.append(f".implements {iface}")
    lines.append("")
    for field in cls.get("fields") or []:
        access = _access_to_smali_field(int(field.get("access_flags") or 0))
        desc = normalize_descriptor(field.get("descriptor") or "")
        lines.append(f".field {access} {field.get('name')}:{desc}".replace("  ", " "))
    lines.append("")
    for method in methods:
        lines.append(_render_reconstructed_method(method, semantics[method_key(method)], cls))
    return "\n".join(lines) + "\n"


def _render_harness(reconstructed: list[tuple[dict[str, Any], dict[str, Any]]]) -> str:
    lines = [
        ".class public Ldex2c_recover/Harness;",
        ".super Ljava/lang/Object;",
        "",
    ]
    names = []
    for index, (method, semantic) in enumerate(reconstructed):
        name = f"test_{index}_{safe_filename(method['class'].strip('L;').replace('/', '_'))}_{safe_filename(method['method'])}"
        names.append((name, method, semantic))
        kind = semantic.get("kind")
        if kind == "return_void_noop":
            lines += [
                f".method public static {name}()V",
                "    .registers 1",
                "    return-void",
                ".end method",
                "",
            ]
        else:
            value = int(semantic.get("value") or 0)
            lines += [
                f".method public static {name}()Z",
                "    .registers 2",
                "    const/4 v0, 0x0" if value == 0 else f"    const/16 v0, {value}",
                "    return v0",
                ".end method",
                "",
            ]
    lines += [
        ".method public static main([Ljava/lang/String;)V",
        "    .registers 4",
        "    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;",
    ]
    for index, (name, method, semantic) in enumerate(names):
        kind = semantic.get("kind")
        if kind == "return_void_noop":
            lines.append(f"    invoke-static {{}}, Ldex2c_recover/Harness;->{name}()V")
            lines.append(f"    const-string v1, \"{index}:void\"")
        else:
            lines.append(f"    invoke-static {{}}, Ldex2c_recover/Harness;->{name}()Z")
            lines.append("    move-result v1")
            lines.append("    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Z)V")
            continue
        lines.append("    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V")
    lines += [
        "    return-void",
        ".end method",
        "",
    ]
    return "\n".join(lines)


def recover_exact_dex(workspace_root: str | Path) -> dict[str, Any]:
    root = Path(workspace_root)
    inputs = read_json(root / "inventory" / "inputs.json", {}) or {}
    protected_dex_paths = sorted((root / "extracted" / "apk").glob("*.dex"))
    protected = []
    for path in protected_dex_paths:
        protected.append({"name": path.name, "path": path, "data": path.read_bytes()})
    recovered = []
    for embedded in inputs.get("embedded_apks") or []:
        artifact = root / embedded["path"]
        if not artifact.exists():
            continue
        try:
            from androguard.core.apk import APK

            apk = APK(str(artifact))
            dexes = list(apk.get_all_dex())
        except Exception as exc:
            recovered.append({"status": "INVALID_CANDIDATE", "origin": embedded["origin_zip_entry"], "error": str(exc)})
            continue
        for index, raw in enumerate(dexes):
            try:
                emb = load_dex(raw)
            except Exception:
                continue
            emb_classes = {c.get_name() for c in emb.get_classes()}
            best = None
            best_coverage = 0.0
            for p in protected:
                try:
                    pdex = load_dex(p["data"])
                    pclasses = {c.get_name() for c in pdex.get_classes()}
                    inter = len(emb_classes & pclasses)
                    coverage = inter / max(1, len(emb_classes))
                    if coverage > best_coverage:
                        best = p
                        best_coverage = coverage
                except Exception:
                    continue
            if not best:
                recovered.append(
                    {
                        "status": "INVALID_CANDIDATE",
                        "origin": embedded["origin_zip_entry"],
                        "embedded_dex_index": index,
                        "sha256": diff_hash(raw),
                        "reason": "no protected DEX with overlapping class inventory",
                    }
                )
                continue
            pdex = load_dex(best["data"])
            diff = diff_dex(pdex, emb, best["name"], f"embedded:{embedded['origin_zip_entry']}:{index}")
            protected_native = 0
            restored = 0
            for cls in pdex.get_classes():
                for m in cls.get_methods():
                    if m.get_access_flags() & 0x100:
                        protected_native += 1
            # Count protected native methods that have a code body in the
            # embedded candidate with the same class/method/prototype.
            emb_map = {}
            for cls in emb.get_classes():
                for m in cls.get_methods():
                    emb_map[method_key({
                        "class": cls.get_name(), "method": m.get_name(),
                        "descriptor": normalize_descriptor(m.get_descriptor()),
                    })] = m
            for cls in pdex.get_classes():
                for m in cls.get_methods():
                    if not (m.get_access_flags() & 0x100):
                        continue
                    key = method_key({"class": cls.get_name(), "method": m.get_name(), "descriptor": normalize_descriptor(m.get_descriptor())})
                    om = emb_map.get(key)
                    if om is not None and om.get_code() is not None:
                        restored += 1
            status = "EXACT_DEX"
            if best_coverage < 0.99 or diff["common_methods"] < 0.99 * len(emb_map):
                status = "PARTIAL_CAPTURE"
            out_name = f"{best['name'].replace('.dex','')}__from_embedded_{index}.dex"
            out_path = root / "recovery" / "exact" / out_name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(raw)
            entry = {
                "status": status,
                "recovery_status": "EXACT_DEX_RECOVERED" if status == "EXACT_DEX" else "PARTIAL_CAPTURE",
                "classification": "artifact_present_in_supplied_apk",
                "source_kind": "embedded_artifact",
                "independent_recovery": False,
                "origin_zip_entry": embedded["origin_zip_entry"],
                "origin_artifact_sha256": embedded["sha256"],
                "embedded_dex_index": index,
                "embedded_dex_sha256": diff_hash(raw),
                "recovered_path": str(out_path),
                "recovered_sha256": sha256_file(out_path),
                "matched_protected_dex": best["name"],
                "matched_protected_dex_sha256": diff_hash(best["data"]),
                "class_coverage": best_coverage,
                "method_signature_coverage": diff["exact_signature_coverage"],
                "common_methods": diff["common_methods"],
                "protected_native_methods_in_matched_dex": protected_native,
                "native_methods_with_code_in_candidate": restored,
                "same_artifact_as_input": diff_hash(raw) == sha256_file(root / "extracted" / "apk" / best["name"]),
                "validation": "pending",
                "evidence": [
                    f"embedded artifact {embedded['origin_zip_entry']} is a ZIP/APK present in the supplied protected APK",
                    f"class coverage {best_coverage:.4f}; signature coverage {diff['exact_signature_coverage']:.4f}",
                    f"{restored}/{protected_native} native declarations in {best['name']} have code in the candidate",
                ],
                "limitations": [
                    "This is an artifact present in the supplied APK, not instructions recovered from native machine code",
                    "It is not assumed to be the original build input and does not automatically cover other DEX files or injected classes",
                ],
            }
            recovered.append(entry)
    write_json(root / "recovery" / "exact" / "manifest.json", recovered)
    return {"artifacts": recovered, "exact": sum(1 for r in recovered if r.get("status") == "EXACT_DEX")}


def diff_hash(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def recover_equivalent_dex(
    workspace_root: str | Path,
    functions: list[dict[str, Any]],
    methods: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    *,
    candidates: list[dict[str, Any]] | None = None,
    max_methods: int = 100,
) -> dict[str, Any]:
    root = Path(workspace_root)
    class_by_desc = {c["descriptor"]: c for c in classes}
    methods_by_key = {method_key(m): m for m in methods}
    eligible = None
    if candidates is not None:
        eligible = {
            c["method_key"] for c in candidates
            if c.get("status") == "LIKELY_DEX2C_TRANSFORMED" and c.get("recovery_eligible")
        }
    supported: dict[str, dict[str, Any]] = {}
    for func in functions:
        sem = func.get("semantic") or {}
        if not sem.get("supported"):
            continue
        key = func["method_key"]
        if eligible is not None and key not in eligible:
            continue
        if key in supported:
            continue
        supported[key] = {"semantic": sem, "function": func}
        if len(supported) >= max_methods:
            break
    selected = []
    for key, item in sorted(supported.items()):
        method = methods_by_key.get(key)
        if not method or method["class"] not in class_by_desc:
            continue
        selected.append((method, item["semantic"], item["function"]))
    by_class: dict[str, list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for method, sem, func in selected:
        by_class[method["class"]].append((method, sem, func))
    smali_root = root / "recovery" / "reconstructed" / "smali"
    if smali_root.exists():
        import shutil

        shutil.rmtree(smali_root)
    ensure_dir(smali_root)
    rendered_classes = []
    for cls_desc, items in sorted(by_class.items()):
        cls = class_by_desc[cls_desc]
        methods_for_class = [x[0] for x in items]
        semantics = {method_key(x[0]): x[1] for x in items}
        text = _render_class(cls, methods_for_class, semantics)
        out = smali_root / (cls_desc[1:-1].replace("/", "_") + ".smali")
        out.write_text(text, encoding="utf-8")
        rendered_classes.append({"class": cls_desc, "methods": [method_key(x[0]) for x in items], "smali": str(out)})
    # Harness with statically callable copies of the recovered behavior, so it
    # can be executed on a device without loading unrelated class dependencies.
    harness_dir = root / "recovery" / "reconstructed" / "harness-smali"
    if harness_dir.exists():
        import shutil

        shutil.rmtree(harness_dir)
    ensure_dir(harness_dir)
    if selected:
        (harness_dir / "Harness.smali").write_text(_render_harness([(m, s) for m, s, _ in selected]), encoding="utf-8")
    smali_jar = _first_existing(_candidate_paths()["smali"])
    assembled = []
    if smali_jar:
        dex_out = root / "recovery" / "reconstructed" / "reconstructed.dex"
        cmd = run_command(["java", "-jar", str(smali_jar), "assemble", str(smali_root), "-o", str(dex_out)], timeout=300)
        if cmd.ok and dex_out.exists():
            assembled.append({"artifact": "reconstructed.dex", "path": str(dex_out), "sha256": sha256_file(dex_out), "ok": True})
        else:
            assembled.append({"artifact": "reconstructed.dex", "ok": False, "error": cmd.stderr[-2000:], "returncode": cmd.returncode})
        harness_out = root / "recovery" / "reconstructed" / "harness.dex"
        cmd = run_command(["java", "-jar", str(smali_jar), "assemble", str(harness_dir), "-o", str(harness_out)], timeout=300)
        if cmd.ok and harness_out.exists():
            assembled.append({"artifact": "harness.dex", "path": str(harness_out), "sha256": sha256_file(harness_out), "ok": True})
        else:
            assembled.append({"artifact": "harness.dex", "ok": False, "error": cmd.stderr[-2000:], "returncode": cmd.returncode})
    method_rows = []
    for method, sem, func in selected:
        method_rows.append(
            {
                "method_key": method_key(method),
                "status": "BEHAVIOR_RECONSTRUCTED" if sem.get("kind") == "return_constant" else "PARTIALLY_RECONSTRUCTED",
                "classification": "equivalent_behavior_not_original_instructions",
                "dex_file": method.get("dex_file"),
                "native_evidence": {
                    "library": func.get("library"),
                    "abi": func.get("abi"),
                    "address": func.get("address"),
                    "function": func.get("function_name"),
                    "jni_calls": [c.get("jni_function") for c in func.get("jni_env_calls", [])],
                    "semantic": sem,
                    "disassembly": func.get("disassembly_file"),
                },
                "generated_behavior": {"kind": sem.get("kind"), "value": sem.get("value")},
                "limitations": [
                    "Generated Dalvik is equivalent for the analyzed leaf behavior, not a recovery of original DEX instructions",
                    "The reconstructed class is a partial class skeleton and is not a drop-in replacement for the protected APK",
                    "JNI local-reference allocation is not represented in Dalvik",
                ],
            }
        )
    manifest = {
        "schema_version": "1.0",
        "classification": "BEHAVIOR_EQUIVALENT_RECONSTRUCTION",
        "note": "These artifacts are not claimed to be original DEX and are not full application replacements.",
        "selected_methods": len(selected),
        "classes": rendered_classes,
        "artifacts": assembled,
        "methods": method_rows,
        "smali_dir": str(smali_root),
        "harness_smali_dir": str(harness_dir),
    }
    write_json(root / "recovery" / "reconstructed" / "manifest.json", manifest)
    write_jsonl(root / "recovery" / "reconstructed" / "methods.jsonl", method_rows)
    return manifest


def build_unresolved(workspace_root: str | Path, candidates: list[dict[str, Any]], mappings: list[dict[str, Any]], reconstruction: dict[str, Any]) -> list[dict[str, Any]]:
    root = Path(workspace_root)
    exact = read_json(root / "recovery" / "exact" / "manifest.json", []) or []
    exact_covered = set()
    for entry in exact:
        if entry.get("status") == "EXACT_DEX":
            exact_covered.add(entry.get("matched_protected_dex"))
    recon_keys = {m["method_key"] for m in reconstruction.get("methods", [])}
    mapping_by_key = {m["method_key"]: m for m in mappings}
    rows = []
    for cand in candidates:
        key = cand["method_key"]
        mapping = mapping_by_key.get(key, {})
        if cand.get("status") in ("PREEXISTING_NATIVE",):
            continue
        if cand.get("category") == "protection_loader_infrastructure":
            continue
        if key in recon_keys:
            continue
        if cand.get("dex_file") in exact_covered:
            continue
        status = "UNRESOLVED"
        reason = "no exact DEX artifact and no supported native-to-Dalvik reconstruction"
        if not mapping.get("primary_function"):
            reason = "native implementation was not mapped"
            status = "AMBIGUOUS" if cand.get("status") == "AMBIGUOUS" else "UNRESOLVED"
        elif (mapping.get("primary_function") or {}).get("source") in ("static_export", "dynamic_registration_array"):
            reason = "native function mapped and disassembled, but behavior exceeds the supported reconstruction subset"
            status = "UNSUPPORTED"
        rows.append(
            {
                "method_key": key,
                "class": cand["class"],
                "method": cand["method"],
                "descriptor": cand["descriptor"],
                "dex_file": cand.get("dex_file"),
                "candidate_status": cand.get("status"),
                "mapping_status": mapping.get("mapping_status"),
                "primary_function": mapping.get("primary_function"),
                "recovery_status": status,
                "reason": reason,
                "native_analysis": (mapping.get("primary_function") or {}).get("library"),
                "limitations": [
                    "Native pseudocode is not original source code",
                    "A native mapping does not imply original DEX instructions are available",
                ],
                "evidence": cand.get("evidence", []) + mapping.get("evidence", []),
            }
        )
    write_jsonl(root / "recovery" / "unresolved.jsonl", rows)
    return rows

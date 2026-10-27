"""Machine-readable and human-readable reporting plus provenance."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .source_model import OBSERVED_APK_FACTS, SOURCE_CONFIRMED_FACTS, SOURCE_REVISION
from .util import (
    now_utc,
    read_json,
    read_jsonl,
    sha256_file,
    write_json,
)


def _count(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(r.get(field)) for r in rows).items()))


def load_report_inputs(workspace: str | Path) -> dict[str, Any]:
    root = Path(workspace)
    return {
        "inputs": read_json(root / "inventory" / "inputs.json", {}) or {},
        "environment": read_json(root / "inventory" / "environment.json", {}) or {},
        "dex_summary": read_json(root / "inventory" / "dex-summary.json", {}) or {},
        "discovery_summary": read_json(root / "inventory" / "discovery-summary.json", {}) or {},
        "methods": read_jsonl(root / "inventory" / "methods.jsonl"),
        "candidates": read_jsonl(root / "inventory" / "protected-method-candidates.jsonl"),
        "libraries": read_json(root / "inventory" / "native-libraries.json", []) or [],
        "abi_comparison": read_json(root / "inventory" / "native-abi-comparison.json", []) or [],
        "registration": read_jsonl(root / "native" / "jni-registration.jsonl"),
        "mappings": read_jsonl(root / "native" / "method-mappings.jsonl"),
        "functions": read_jsonl(root / "native" / "function-analysis.jsonl"),
        "ghidra": read_json(root / "native" / "ghidra-index.json", []) or [],
        "exact": read_json(root / "recovery" / "exact" / "manifest.json", []) or [],
        "reconstructed": read_json(root / "recovery" / "reconstructed" / "manifest.json", {}) or {},
        "unresolved": read_jsonl(root / "recovery" / "unresolved.jsonl"),
        "runtime": read_json(root / "runtime" / "session.json", {}) or {},
        "validation": read_json(root / "validation" / "summary.json", {}) or {},
        "state": read_json(root / ".state.json", {}) or {},
    }


def build_report(workspace: str | Path, *, command: str = "", test_results: dict[str, Any] | None = None) -> dict[str, Any]:
    root = Path(workspace)
    d = load_report_inputs(root)
    inputs = d["inputs"]
    methods = d["methods"]
    candidates = d["candidates"]
    mappings = d["mappings"]
    functions = d["functions"]
    libraries = d["libraries"]
    native_methods = [m for m in methods if m.get("native")]
    code_methods = [m for m in methods if m.get("code_present")]
    transformed = [c for c in candidates if c.get("status") == "LIKELY_DEX2C_TRANSFORMED"]
    preexisting = [c for c in candidates if c.get("status") == "PREEXISTING_NATIVE"]
    loader = [c for c in candidates if c.get("category") == "protection_loader_infrastructure"]
    exact = d["exact"]
    recon = d["reconstructed"]
    recon_methods = recon.get("methods", []) if isinstance(recon, dict) else []
    exact_entries = [e for e in exact if e.get("status") == "EXACT_DEX"]
    exact_artifacts = [e for e in exact if e.get("recovered_path")]
    exact_covered_keys = set()
    for entry in exact_entries:
        matched = entry.get("matched_protected_dex")
        for c in transformed:
            if c.get("dex_file") == matched:
                exact_covered_keys.add(c["method_key"])
    recon_keys = {m["method_key"] for m in recon_methods}
    unsupported_rows = [u for u in d["unresolved"] if u.get("recovery_status") == "UNSUPPORTED"]
    unresolved_rows = [u for u in d["unresolved"] if u.get("recovery_status") in ("UNRESOLVED", "AMBIGUOUS")]
    libraries_by_role = _count(libraries, "role")
    jni_export_total = sum(len(lib.get("jni_exports") or []) for lib in libraries)
    registration_arrays = sum(len(lib.get("native_method_tables") or []) for lib in libraries)
    register_natives_calls = sum(len(lib.get("register_natives_calls") or []) for lib in libraries)
    functions_by_abi = _count(functions, "abi")
    functions_decompiled = len([g for g in d["ghidra"] if g.get("decompiled")])
    semantic_supported = [f for f in functions if (f.get("semantic") or {}).get("supported")]
    transformed_keys = {c["method_key"] for c in transformed}
    semantic_supported_transformed = [f for f in semantic_supported if f.get("method_key") in transformed_keys]
    runtime_devices = (d["runtime"] or {}).get("devices", []) if isinstance(d["runtime"], dict) else []
    runtime_artifacts = [a for dev in runtime_devices for a in dev.get("artifacts", [])]

    exact_methods_by_artifact = {}
    for entry in exact_artifacts:
        exact_methods_by_artifact[entry.get("recovered_path")] = {
            "matched_protected_dex": entry.get("matched_protected_dex"),
            "native_declarations_in_matched_dex": entry.get("protected_native_methods_in_matched_dex"),
            "native_declarations_with_code": entry.get("native_methods_with_code_in_candidate"),
            "status": entry.get("status"),
            "sha256": entry.get("recovered_sha256"),
        }

    dynamic_limitations = []
    for dev in runtime_devices:
        for error in dev.get("errors") or []:
            dynamic_limitations.append(f"{dev.get('serial')}: {error}")
    report = {
        "schema_version": "1.0",
        "generated_at": now_utc(),
        "tool": {"name": "dex2c-recover", "command": command},
        "input": {
            "path": inputs.get("input", {}).get("absolute_path"),
            "sha256": inputs.get("input", {}).get("sha256"),
            "size": inputs.get("input", {}).get("size"),
            "immutability": inputs.get("input", {}).get("immutability"),
        },
        "source_recon": {
            "revision": SOURCE_REVISION,
            "source_confirmed_facts": SOURCE_CONFIRMED_FACTS,
            "observed_apk_facts": OBSERVED_APK_FACTS,
        },
        "summary": {
            "dex_files": len(inputs.get("dex") or []),
            "classes": (d["dex_summary"].get("totals") or {}).get("classes") or len({m.get("class") for m in methods}),
            "methods_total": len(methods),
            "methods_with_code": len(code_methods),
            "native_methods": len(native_methods),
            "abstract_or_no_code_non_native": len(
                [m for m in methods if not m.get("native") and not m.get("abstract") and not m.get("code_present")]
            ),
            "candidate_methods": len(candidates),
            "candidate_statuses": _count(candidates, "status"),
            "candidate_confidence": _count(candidates, "confidence"),
            "likely_dex2c_transformed": len(transformed),
            "preexisting_native": len(preexisting),
            "protection_loader_methods": len(loader),
            "native_libraries": len(libraries),
            "native_library_names": sorted({lib.get("name") for lib in libraries if lib.get("name")}),
            "native_libraries_by_role": libraries_by_role,
            "jni_exports": jni_export_total,
            "registration_arrays": registration_arrays,
            "register_natives_calls": register_natives_calls,
            "mappings_total": len(mappings),
            "mapping_statuses": _count(mappings, "mapping_status"),
            "mapped_primary_functions": sum(1 for m in mappings if m.get("primary_function")),
            "shared_native_functions": sum(1 for m in mappings if m.get("shared_function")),
            "functions_disassembled": len(functions),
            "functions_by_abi": functions_by_abi,
            "functions_decompiled": functions_decompiled,
            "semantic_supported_functions": len(semantic_supported),
            "semantic_supported_transformed_methods": len({f["method_key"] for f in semantic_supported_transformed}),
            "exact_dex_artifacts": len(exact_entries),
            "exact_dex_artifacts_including_partial": len(exact_artifacts),
            "exact_transformed_methods_covered": len(exact_covered_keys),
            "behavior_reconstructed_methods": len(recon_methods),
            "unresolved_entries": len(unresolved_rows),
            "unsupported_entries": len(unsupported_rows),
            "unresolved_or_unsupported_entries": len(d["unresolved"]),
            "runtime_devices_observed": len(runtime_devices),
            "runtime_native_artifacts": len(runtime_artifacts),
            "runtime_behavior_tests_passed": sum(1 for d in runtime_devices if (d.get("behavior_test") or {}).get("status") == "PASS"),
            "runtime_behavior_tests_failed": sum(1 for d in runtime_devices if (d.get("behavior_test") or {}).get("status") == "FAIL"),
        },
        "denominators": {
            "transformed_method_candidates": len(transformed),
            "transformed_methods_with_exact_dex_evidence": len(exact_covered_keys),
            "transformed_methods_with_behavior_reconstruction": len(recon_keys & transformed_keys),
            "transformed_methods_with_both_exact_and_behavior": len(recon_keys & transformed_keys & exact_covered_keys),
            "transformed_methods_without_exact_or_behavior": len(transformed_keys - exact_covered_keys - recon_keys),
            "transformed_methods_unresolved": len(transformed_keys & {u["method_key"] for u in unresolved_rows}),
            "transformed_methods_unsupported": len(transformed_keys & {u["method_key"] for u in unsupported_rows}),
            "native_methods_total": len(native_methods),
            "native_methods_preexisting": len(preexisting),
            "native_methods_mapped_confirmed": sum(1 for m in mappings if m.get("mapping_status") == "CONFIRMED"),
            "native_methods_mapped_strong": sum(1 for m in mappings if m.get("mapping_status") == "STRONGLY_SUPPORTED"),
            "native_methods_mapping_ambiguous": sum(1 for m in mappings if m.get("mapping_status") == "AMBIGUOUS"),
            "native_methods_unresolved_mapping": sum(1 for m in mappings if m.get("mapping_status") == "UNRESOLVED"),
        },
        "artifacts": {
            "dex": inputs.get("dex") or [],
            "native_libraries": [
                {
                    "name": lib.get("name"),
                    "abi": lib.get("abi"),
                    "role": lib.get("role"),
                    "sha256": lib.get("sha256"),
                    "jni_exports": len(lib.get("jni_exports") or []),
                    "register_natives_calls": len(lib.get("register_natives_calls") or []),
                    "native_method_tables": len(lib.get("native_method_tables") or []),
                }
                for lib in libraries
            ],
            "embedded_apks": [
                {
                    "origin": e.get("origin_zip_entry"),
                    "sha256": e.get("sha256"),
                    "package": (e.get("metadata") or {}).get("package"),
                    "dex": (e.get("metadata") or {}).get("dex"),
                }
                for e in inputs.get("embedded_apks") or []
            ],
            "assets": inputs.get("assets") or [],
        },
        "dex": {
            "summary": d["dex_summary"],
            "native_methods": native_methods,
            "methods_without_code": [
                {"class": m["class"], "method": m["method"], "descriptor": m["descriptor"], "access": m.get("access")}
                for m in methods
                if not m.get("native") and not m.get("abstract") and not m.get("code_present")
            ],
        },
        "discovery": {
            "summary": d["discovery_summary"],
            "candidates": candidates,
            "preexisting_native_evidence": [
                {
                    "method_key": c["method_key"],
                    "status": c["status"],
                    "evidence": c.get("evidence"),
                    "alternatives": c.get("alternatives"),
                }
                for c in candidates
                if c.get("status") == "PREEXISTING_NATIVE"
            ],
        },
        "native": {
            "libraries": libraries,
            "abi_comparison": d["abi_comparison"],
            "registration": d["registration"],
            "mappings": mappings,
            "function_analysis": functions,
            "ghidra_index": d["ghidra"],
        },
        "recovery": {
            "exact_artifacts": exact,
            "exact_methods_by_artifact": exact_methods_by_artifact,
            "reconstructed": recon,
            "unresolved": d["unresolved"],
            "status_explanation": {
                "EXACT_DEX": "A DEX artifact genuinely present in the supplied APK and validated against the protected DEX inventory; not derived from native code.",
                "NATIVE_IMPLEMENTATION_MAPPED": "A DEX native declaration was correlated to a native function; this is not recovered DEX.",
                "BEHAVIOR_RECONSTRUCTED": "A generated Dalvik method is behaviorally equivalent for the analyzed leaf subset, not the original instruction sequence.",
                "PARTIALLY_RECONSTRUCTED": "Only a subset of the native behavior is represented in Dalvik.",
                "UNRESOLVED": "No exact artifact or supported equivalent reconstruction was established.",
            },
        },
        "runtime": d["runtime"],
        "validation": d["validation"],
        "commands": {
            "analysis": "from dex2c_recover.cli import main; main()",
            "report": "dex2c-recover report --workspace <out>",
            "tests": "pytest -q",
        },
        "limitations": [
            "Native mappings do not reveal original DEX instructions.",
            "Ghidra pseudocode is decompiler output, not original source and not proof of semantic equivalence.",
            "Two selected Ghidra function exports were not decompiled (245 candidates, 243 C files); raw disassembly remains available.",
            "The equivalent-Dalvik reconstruction supports a deliberately small, evidence-backed subset of leaf behaviors; most protected methods remain unresolved.",
            "Runtime observation may not expose every code path or every runtime-generated artifact.",
            "Results depend on artifact completeness, stripped-symbol availability, device capabilities, and tool versions.",
            "The embedded APK/asset is reported as an artifact present in the supplied APK; it is not assumed to be the original build input and is not a native-code recovery.",
        ] + dynamic_limitations,
        "test_results": test_results or {},
        "provenance": {
            "state": d["state"],
            "environment": d["environment"],
        },
    }
    write_json(root / "reports" / "report.json", report)
    (root / "reports" / "report.txt").write_text(render_text(report), encoding="utf-8")
    (root / "reports" / "report.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def _fmt_list(items: list[Any], limit: int = 8) -> str:
    if not items:
        return "(none)"
    text = ", ".join(str(x) for x in items[:limit])
    if len(items) > limit:
        text += f", ... ({len(items)} total)"
    return text


def render_text(r: dict[str, Any]) -> str:
    s = r["summary"]
    den = r["denominators"]
    lines = [
        "Dex2C STANDALONE ANALYSIS REPORT",
        "================================",
        "",
        f"Input: {r['input'].get('path')}",
        f"SHA-256: {r['input'].get('sha256')}",
        f"Input immutable during analysis: {r['input'].get('immutability')}",
        f"Source revision examined: {SOURCE_REVISION['commit']} ({SOURCE_REVISION['commit_date']})",
        "",
        "1. Artifacts found in the protected APK",
        f"   DEX files: {s['dex_files']}; native libraries: {s['native_libraries']}; embedded APK artifacts: {len(r['artifacts']['embedded_apks'])}",
        f"   Native library names: {s['native_library_names']}",
        f"   Native library roles (per ABI): {s['native_libraries_by_role']}",
        f"   JNI exports across ABI inventories: {s['jni_exports']}; registration arrays: {s['registration_arrays']}; RegisterNatives call sites: {s['register_natives_calls']}",
        "   Export counts are per-ABI inventory counts; identical symbol names across ABIs are not independent methods.",
        "",
        "2. DEX method inventory",
        f"   Classes: {s['classes']}; methods: {s['methods_total']}; with DEX code: {s['methods_with_code']}; native declarations: {s['native_methods']}",
        f"   Non-native, non-abstract methods without code: {s['abstract_or_no_code_non_native']}",
        "",
        "3. Likely Dex2C-transformed methods",
        f"   Candidate statuses: {s['candidate_statuses']}",
        f"   Likely transformed: {s['likely_dex2c_transformed']}; pre-existing native: {s['preexisting_native']}; loader infrastructure: {s['protection_loader_methods']}",
        f"   Confidence distribution: {s['candidate_confidence']}",
        "   Evidence is in inventory/protected-method-candidates.jsonl; status is not based on names alone.",
        "",
        "4. Native libraries containing implementations",
        f"   Roles: {s['native_libraries_by_role']}",
        "   Details: inventory/native-libraries.json and native/elf-analysis/",
        "",
        "5. Method-to-function mappings",
        f"   Statuses: {s['mapping_statuses']}",
        f"   Primary functions: {s['mapped_primary_functions']}; shared native functions: {s['shared_native_functions']}",
        "",
        "6. Disassembly and decompilation",
        f"   Functions disassembled: {s['functions_disassembled']} by ABI {s['functions_by_abi']}",
        f"   Ghidra-decompiled exports: {s['functions_decompiled']}; conservative semantic candidates: {s['semantic_supported_functions']} ({s['semantic_supported_transformed_methods']} protected methods)",
        "   Raw disassembly: native/disassembly/; Ghidra output: native/pseudocode/; CFG/call graphs: native/call-graphs/",
        "",
        "7. Exact DEX evidence",
        f"   EXACT_DEX artifacts: {s['exact_dex_artifacts']}; transformed candidates covered by exact artifacts: {den['transformed_methods_with_exact_dex_evidence']}/{den['transformed_method_candidates']}",
        f"   Behavior reconstruction overlap with exact evidence: {den['transformed_methods_with_both_exact_and_behavior']}; without exact or behavior: {den['transformed_methods_without_exact_or_behavior']}",
        f"   Exact artifacts: {[e.get('recovered_path') for e in r['recovery']['exact_artifacts'] if e.get('status') == 'EXACT_DEX']}",
        "   These are artifacts present in the supplied APK, not DEX instructions recovered from native code; independent_recovery=false.",
        "",
        "8. Runtime evidence",
        f"   Devices observed: {s['runtime_devices_observed']}; runtime native artifacts: {s['runtime_native_artifacts']}",
        f"   Artifact classifications: {_fmt_list([a.get('classification') for dev in r['runtime'].get('devices', []) for a in dev.get('artifacts', []) if a.get('classification')])}",
        f"   Reconstructed harness behavior tests: {s.get('runtime_behavior_tests_passed')} passed, {s.get('runtime_behavior_tests_failed')} failed",
        "",
        "9. Behaviorally reconstructed DEX",
        f"   Methods: {s['behavior_reconstructed_methods']}; generated artifacts: {[a.get('artifact') for a in (r['recovery']['reconstructed'].get('artifacts') or [])]}",
        "   These are equivalent-behavior artifacts, not original DEX instructions or drop-in APK replacements.",
        "",
        "10. Unresolved methods",
        f"   Unresolved entries: {s['unresolved_entries']}; unsupported translated-subset entries: {s['unsupported_entries']}; transformed candidates unsupported/unresolved: {den['transformed_methods_unsupported']}/{den['transformed_methods_unresolved']}",
        "   Details: recovery/unresolved.jsonl",
        "",
        "11. Evidence and provenance",
        "   Per-method evidence: inventory/protected-method-candidates.jsonl and native/method-mappings.jsonl",
        "   Hashes and execution metadata: provenance/SHA256SUMS and provenance/execution-manifest.json",
        "   Validation: validation/",
        "",
        "12. Translation limitations",
        "   Methods outside the supported leaf subset are not assigned invented Dalvik instructions.",
        "   See recovery/reconstructed/manifest.json and recovery/unresolved.jsonl.",
        "",
        "13. Device testing",
    ]
    for dev in r["runtime"].get("devices", []):
        lines.append(
            f"   {dev.get('serial')}: root={dev.get('root')} status={dev.get('status')} "
            f"launch_pid={(dev.get('launch') or {}).get('pid')} artifacts={len(dev.get('artifacts', []))} "
            f"behavior_test={(dev.get('behavior_test') or {}).get('status')}"
        )
    if not r["runtime"].get("devices"):
        lines.append("   (no runtime session requested or no authorized devices)")
    lines += [
        "",
        "14. Limitations",
    ]
    for item in r["limitations"]:
        lines.append(f"   - {item}")
    if r.get("test_results"):
        tr = r["test_results"]
        lines += [
            "",
            "Test results",
            f"   {tr.get('passed', 0)} passed, {tr.get('failed', 0)} failed, {tr.get('skipped', 0)} skipped, {tr.get('errors', 0)} errors; "
            f"{tr.get('tests', 0)} tests in {tr.get('duration_seconds', 0):.1f}s; device tests enabled={tr.get('device_tests_enabled')}",
            "   Command: " + str(tr.get("command")),
        ]
    lines += [
        "",
        "Inventory denominators and confidence criteria are kept separate; this report does not combine exact artifacts, native mapping, and behavioral reconstruction into a single recovery percentage.",
    ]
    return "\n".join(lines) + "\n"


def render_markdown(r: dict[str, Any]) -> str:
    s = r["summary"]
    den = r["denominators"]
    lines = [
        "# Dex2C Standalone Analysis Report",
        "",
        f"- Input: `{r['input'].get('path')}`",
        f"- SHA-256: `{r['input'].get('sha256')}`",
        f"- Input unchanged: `{r['input'].get('immutability')}`",
        f"- Source revision: `{SOURCE_REVISION['commit']}`",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| DEX files | {s['dex_files']} |",
        f"| Classes | {s['classes']} |",
        f"| Methods | {s['methods_total']} |",
        f"| Methods with DEX code | {s['methods_with_code']} |",
        f"| Native declarations | {s['native_methods']} |",
        f"| Likely Dex2C-transformed | {s['likely_dex2c_transformed']} |",
        f"| Pre-existing native | {s['preexisting_native']} |",
        f"| Native libraries | {s['native_libraries']} |",
        f"| JNI exports | {s['jni_exports']} |",
        f"| Mapped primary functions | {s['mapped_primary_functions']} |",
        f"| Functions disassembled | {s['functions_disassembled']} |",
        f"| Ghidra-decompiled exports | {s['functions_decompiled']} |",
        f"| Exact DEX artifacts | {s['exact_dex_artifacts']} |",
        f"| Transformed methods with exact DEX evidence | {den['transformed_methods_with_exact_dex_evidence']} / {den['transformed_method_candidates']} |",
        f"| Behavior-reconstructed methods | {s['behavior_reconstructed_methods']} |",
        f"| Unsupported transformed candidates | {den['transformed_methods_unsupported']} |",
        f"| Unresolved transformed candidates | {den['transformed_methods_unresolved']} |",
        "",
        "## Required questions",
        "",
        f"1. **Artifacts found:** {s['dex_files']} DEX files, {s['native_libraries']} native libraries, {len(r['artifacts']['embedded_apks'])} embedded APK artifacts.",
        f"2. **DEX methods:** {s['methods_with_code']} have code; {s['native_methods']} are native declarations.",
        f"3. **Likely transformed:** {s['likely_dex2c_transformed']} candidates. Evidence rather than name resemblance is in `inventory/protected-method-candidates.jsonl`.",
        f"4. **Native implementation libraries:** {s['native_libraries_by_role']}.",
        f"5. **Mappings:** {s['mapping_statuses']}.",
        f"6. **Disassembled/decompiled:** {s['functions_disassembled']} disassembled, {s['functions_decompiled']} Ghidra-decompiled, {s['semantic_supported_transformed_methods']} protected methods in the conservative semantic subset.",
        f"7. **Recoverable DEX evidence:** {s['exact_dex_artifacts']} exact artifacts; coverage {den['transformed_methods_with_exact_dex_evidence']}/{den['transformed_method_candidates']} transformed candidates.",
        f"8. **Runtime artifacts:** {s['runtime_native_artifacts']} runtime native artifacts across {s['runtime_devices_observed']} devices.",
        f"9. **Behavioral reconstruction:** {s['behavior_reconstructed_methods']} methods, explicitly labeled equivalent, not original.",
        f"10. **Unresolved/unsupported:** {s['unresolved_entries']} unresolved and {s['unsupported_entries']} explicitly unsupported by the translator; see `recovery/unresolved.jsonl`.",
        "11. **Evidence:** per-method evidence files plus `provenance/SHA256SUMS`.",
        "12. **Translation limitations:** only the evidence-backed leaf subset is translated; see `recovery/reconstructed/manifest.json`.",
        f"13. **Device tests:** {[(d.get('serial'), d.get('status'), (d.get('launch') or {}).get('pid'), (d.get('behavior_test') or {}).get('status')) for d in r['runtime'].get('devices', [])]}.",
        "14. **Limitations:** see below.",
        "",
        "## Status taxonomy",
        "",
    ]
    lines += [f"- **{k}**: {v}" for k, v in r["recovery"]["status_explanation"].items()]
    lines += [
        "",
        "## Limitations",
        "",
    ]
    lines += [f"- {x}" for x in r["limitations"]]
    lines += [
        "",
        "## Source-confirmed transformation model",
        "",
    ]
    for fact in SOURCE_CONFIRMED_FACTS:
        lines.append(f"- **{fact['topic']}**: {fact['fact']}")
    lines += [
        "",
        "## Observed APK facts",
        "",
    ]
    lines += [f"- {x}" for x in OBSERVED_APK_FACTS]
    lines += [
        "",
        "## Validation and provenance",
        "",
        f"Validation summary: `{r['validation']}`",
        "",
        "This report does not report a misleading overall recovery percentage: exact artifacts, native mappings, disassembly, and equivalent reconstruction are separate evidence classes.",
        "",
    ]
    return "\n".join(lines) + "\n"


def write_provenance(workspace: str | Path, *, input_sha256: str | None = None, command: str = "", test_results: dict[str, Any] | None = None) -> dict[str, Any]:
    root = Path(workspace)
    state = read_json(root / ".state.json", {}) or {}
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if rel.as_posix() == "provenance/SHA256SUMS":
            continue
        if path.name.endswith(".tmp"):
            continue
        files.append({"path": rel.as_posix(), "size": path.stat().st_size, "sha256": sha256_file(path)})
    sums_path = root / "provenance" / "SHA256SUMS"
    sums_path.parent.mkdir(parents=True, exist_ok=True)
    sums_path.write_text("".join(f"{f['sha256']}  {f['path']}\n" for f in files), encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "generated_at": now_utc(),
        "tool": "dex2c-recover",
        "command": command,
        "input_sha256": input_sha256,
        "stages": state.get("stages", {}),
        "artifacts": files,
        "sha256sums": str(sums_path),
        "source_revision": SOURCE_REVISION,
        "test_results": test_results or {},
        "caveats": [
            "SHA-256 entries cover report and analysis artifacts; the immutable input APK is outside the workspace.",
            "Resumed stages are explicitly recorded in .state.json; no reference APK, filters.txt, or prior output is required.",
        ],
    }
    write_json(root / "provenance" / "execution-manifest.json", manifest)
    # Recompute sums so the manifest itself is included.
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if rel.as_posix() == "provenance/SHA256SUMS" or path.name.endswith(".tmp"):
            continue
        files.append({"path": rel.as_posix(), "size": path.stat().st_size, "sha256": sha256_file(path)})
    sums_path.write_text("".join(f"{f['sha256']}  {f['path']}\n" for f in files), encoding="utf-8")
    return manifest

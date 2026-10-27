"""Pipeline orchestration for standalone static analysis, recovery, and runtime."""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .dexparse import (
    find_library_loads,
    interesting_strings,
    iter_classes,
    iter_methods,
    load_dex,
)
from .discovery import classify_all_methods, discover_candidates
from .elfs import analyze_elf, compare_abi_libraries
from .environment import discover_environment
from .ghidra import collect_pseudocode, ghidra_path, run_ghidra
from .ingest import ingest_apk
from .mapping import (
    build_mappings,
    enrich_candidates,
    register_natives_evidence,
    registration_mappings,
)
from .native_analysis import analyze_mappings, build_call_graphs
from .recovery import build_unresolved, recover_equivalent_dex, recover_exact_dex
from .report import build_report, write_provenance
from .runtime import runtime_observe
from .util import (
    read_json,
    read_jsonl,
    sha256_file,
    write_json,
    write_jsonl,
)
from .validation import validate_workspace
from .workspace import Workspace


class Pipeline:
    def __init__(
        self,
        apk: str | Path,
        out: str | Path,
        *,
        force: bool = False,
        ghidra: str = "auto",
        runtime: str = "none",
        allow_install: bool = False,
        serials: list[str] | None = None,
        max_reconstruct: int = 100,
        abis: list[str] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.ws = Workspace(out, apk)
        self.force = force
        self.ghidra_mode = ghidra
        self.runtime_mode = runtime
        self.allow_install = allow_install
        self.serials = serials
        self.max_reconstruct = max_reconstruct
        self.abis = abis
        self.log = log or (lambda message: None)
        self.input_sha = sha256_file(apk)
        self.summaries: dict[str, Any] = {}

    def stage(self, name: str, func: Callable[[], Any], *, force: bool = False) -> Any:
        if not (self.force or force) and self.ws.stage_done(name, self.input_sha):
            self.log(f"[skip] {name} (completed for input {self.input_sha[:12]})")
            state = self.ws.load_state()
            self.summaries[name] = (state.get("stages", {}).get(name) or {}).get("details", {})
            return self.summaries[name]
        self.log(f"[run ] {name}")
        self.ws.mark_stage(name, "running", input_sha256=self.input_sha)
        started = time.time()
        try:
            result = func()
            details = result if isinstance(result, dict) else {"result": str(result)}
            self.ws.mark_stage(name, "completed", input_sha256=self.input_sha, details=details)
            self.summaries[name] = details
            self.log(f"[done] {name} ({time.time() - started:.1f}s)")
            return result
        except Exception as exc:
            self.ws.mark_stage(name, "failed", input_sha256=self.input_sha, error=str(exc))
            self.log(f"[fail] {name}: {exc}")
            raise

    # ---- stages ---------------------------------------------------------
    def stage_environment(self) -> dict[str, Any]:
        from .source_model import (
            OBSERVED_APK_FACTS,
            SOURCE_CONFIRMED_FACTS,
            SOURCE_REVISION,
        )

        write_json(
            self.ws.path("inventory", "source-recon.json"),
            {
                "revision": SOURCE_REVISION,
                "source_confirmed_facts": SOURCE_CONFIRMED_FACTS,
                "observed_apk_facts": OBSERVED_APK_FACTS,
            },
        )
        env = discover_environment(devices=True, output=self.ws.path("inventory", "environment.json"))
        return {
            "tools": {k: {"available": v.get("available"), "version": v.get("version")} for k, v in env.get("tools", {}).items()},
            "capabilities": env.get("capabilities"),
            "devices": env.get("devices"),
            "limitations": env.get("limitations"),
        }

    def stage_ingest(self) -> dict[str, Any]:
        inputs = ingest_apk(self.ws.apk, self.ws.root)
        return {
            "input_sha256": inputs["input"]["sha256"],
            "immutability": inputs["input"]["immutability"],
            "dex": len(inputs["dex"]),
            "native_libraries": len(inputs["native_libraries"]),
            "embedded_apks": len(inputs["embedded_apks"]),
            "package": inputs.get("manifest", {}).get("package"),
        }

    def stage_dex(self) -> dict[str, Any]:
        inputs = read_json(self.ws.path("inventory", "inputs.json"), {}) or {}
        dex_rows = inputs.get("dex") or []
        classes: list[dict[str, Any]] = []
        methods: list[dict[str, Any]] = []
        summaries = []
        loader_evidence = []
        for row in sorted(dex_rows, key=lambda x: x["name"]):
            path = self.ws.path(row["path"])
            data = path.read_bytes()
            dex = load_dex(data)
            dex_name = row["name"]
            sha = row["sha256"]
            cls_rows = list(iter_classes(dex, dex_name, sha))
            method_rows = list(iter_methods(dex, dex_name, sha))
            classes.extend(cls_rows)
            methods.extend(method_rows)
            loads = find_library_loads(dex, dex_name)
            loader_evidence.extend(loads)
            strings = interesting_strings(dex)
            summaries.append(
                {
                    "name": dex_name,
                    "path": row["path"],
                    "sha256": sha,
                    "size": row["size"],
                    "classes": len(cls_rows),
                    "methods": len(method_rows),
                    "native_methods": sum(1 for m in method_rows if m["native"]),
                    "code_methods": sum(1 for m in method_rows if m["code_present"]),
                    "abstract_methods": sum(1 for m in method_rows if m["abstract"]),
                    "loader_evidence": loads,
                    "interesting_strings": strings[:2000],
                    "header": row.get("header"),
                }
            )
        write_jsonl(self.ws.path("inventory", "classes.jsonl"), classes)
        write_jsonl(self.ws.path("inventory", "methods.jsonl"), methods)
        write_json(
            self.ws.path("inventory", "dex-summary.json"),
            {
                "dex": summaries,
                "totals": {
                    "classes": len(classes),
                    "methods": len(methods),
                    "native_methods": sum(1 for m in methods if m["native"]),
                    "code_methods": sum(1 for m in methods if m["code_present"]),
                    "dex_files": len(summaries),
                },
                "loader_evidence": loader_evidence,
            },
        )
        return {
            "dex_files": len(summaries),
            "classes": len(classes),
            "methods": len(methods),
            "native_methods": sum(1 for m in methods if m["native"]),
            "loader_evidence": len(loader_evidence),
        }

    def stage_native(self) -> dict[str, Any]:
        inputs = read_json(self.ws.path("inventory", "inputs.json"), {}) or {}
        out = []
        for item in sorted(inputs.get("native_libraries") or [], key=lambda x: (x.get("abi") or "", x.get("name") or "")):
            path = self.ws.path(item["path"])
            info = analyze_elf(path, abi=item.get("abi"))
            info["inventory_zip_entry"] = item.get("zip_entry")
            info["inventory_path"] = item.get("path")
            out_path = self.ws.path("native", "elf-analysis", f"{item.get('abi','unknown')}__{item.get('name','lib')}.json")
            write_json(out_path, info)
            info["analysis_path"] = str(out_path)
            out.append(info)
        write_json(self.ws.path("inventory", "native-libraries.json"), out)
        comparison = compare_abi_libraries(out)
        write_json(self.ws.path("inventory", "native-abi-comparison.json"), comparison)
        return {
            "libraries": len(out),
            "roles": {lib.get("name"): lib.get("role") for lib in out},
            "jni_exports": sum(len(lib.get("jni_exports") or []) for lib in out),
            "register_natives_calls": sum(len(lib.get("register_natives_calls") or []) for lib in out),
            "native_method_tables": sum(len(lib.get("native_method_tables") or []) for lib in out),
        }

    def _get_methods(self) -> list[dict[str, Any]]:
        return read_jsonl(self.ws.path("inventory", "methods.jsonl"))

    def _get_classes(self) -> list[dict[str, Any]]:
        return read_jsonl(self.ws.path("inventory", "classes.jsonl"))

    def _get_libraries(self) -> list[dict[str, Any]]:
        return read_json(self.ws.path("inventory", "native-libraries.json"), []) or []

    def stage_mapping(self) -> dict[str, Any]:
        methods = self._get_methods()
        libraries = self._get_libraries()
        registration = registration_mappings(libraries, methods)
        registration_calls = register_natives_evidence(libraries)
        rows = []
        for lib in libraries:
            rows.append(
                {
                    "library": lib.get("name"),
                    "abi": lib.get("abi"),
                    "role": lib.get("role"),
                    "source": "JNI_OnLoad",
                    "jni_onload": lib.get("jni_onload"),
                    "register_natives_calls": lib.get("register_natives_calls") or [],
                    "static_export_count": len([x for x in lib.get("jni_exports") or [] if x.get("name") != "JNI_OnLoad"]),
                }
            )
        rows.extend(registration)
        rows.extend(registration_calls)
        write_jsonl(self.ws.path("native", "jni-registration.jsonl"), rows)
        mappings, mapping_summary = build_mappings(methods, libraries, registration)
        write_jsonl(self.ws.path("native", "method-mappings.jsonl"), mappings)
        write_json(
            self.ws.path("native", "mapping-summary.json"),
            {
                **mapping_summary,
                "registration_rows": len(rows),
                "registration_arrays": sum(len(lib.get("native_method_tables") or []) for lib in libraries),
                "register_natives_call_sites": sum(len(lib.get("register_natives_calls") or []) for lib in libraries),
            },
        )
        return mapping_summary

    def stage_discovery(self) -> dict[str, Any]:
        methods = self._get_methods()
        classes = self._get_classes()
        libraries = self._get_libraries()
        dex_summary = read_json(self.ws.path("inventory", "dex-summary.json"), {}) or {}
        loader_evidence = dex_summary.get("loader_evidence") or []
        mappings = read_jsonl(self.ws.path("native", "method-mappings.jsonl"))
        candidates, discovery_summary = discover_candidates(methods, classes, libraries, loader_evidence)
        candidates = enrich_candidates(candidates, mappings)
        write_jsonl(self.ws.path("inventory", "protected-method-candidates.jsonl"), candidates)
        write_json(self.ws.path("inventory", "discovery-summary.json"), discovery_summary)
        classified = classify_all_methods(methods, candidates)
        write_jsonl(self.ws.path("inventory", "methods-classified.jsonl"), classified)
        write_json(
            self.ws.path("inventory", "discovery-summary.json"),
            {
                **discovery_summary,
                "final_by_status": {k: sum(1 for c in candidates if c.get("status") == k) for k in sorted({c.get("status") for c in candidates})},
                "preexisting_methods": [c["method_key"] for c in candidates if c.get("status") == "PREEXISTING_NATIVE"],
                "loader_methods": [c["method_key"] for c in candidates if c.get("category") == "protection_loader_infrastructure"],
            },
        )
        return {
            "native_methods": len(candidates),
            "by_status": {k: sum(1 for c in candidates if c.get("status") == k) for k in sorted({c.get("status") for c in candidates})},
            "by_confidence": {k: sum(1 for c in candidates if c.get("confidence") == k) for k in sorted({c.get("confidence") for c in candidates})},
        }

    def stage_analysis(self) -> dict[str, Any]:
        methods = self._get_methods()
        mappings = read_jsonl(self.ws.path("native", "method-mappings.jsonl"))
        libraries = self._get_libraries()
        abis = self.abis or sorted({lib.get("abi") for lib in libraries if lib.get("abi")})
        functions, summary = analyze_mappings(self.ws.root, methods, mappings, libraries, abis=abis)
        graphs = build_call_graphs(self.ws.root, libraries)
        write_json(
            self.ws.path("native", "call-graphs", "summary.json"),
            {
                "graphs": len(graphs),
                "by_library": {
                    f"{g['abi']}:{g['library']}": {"nodes": len(g["nodes"]), "edges": len(g["edges"])}
                    for g in graphs
                },
            },
        )
        return {**summary, "call_graphs": len(graphs), "abis": abis}

    def stage_ghidra(self) -> dict[str, Any]:
        if self.ghidra_mode == "off" or (self.ghidra_mode == "auto" and not ghidra_path()):
            return {"enabled": False, "reason": "disabled or Ghidra unavailable", "decompiled": 0}
        libraries = self._get_libraries()
        targets = [
            lib for lib in libraries
            if lib.get("abi") == "arm64-v8a" and len(lib.get("jni_exports") or []) > 10
        ]
        # Prefer the large generated library.
        targets.sort(key=lambda lib: (0 if lib.get("role") == "dex2c_generated_library" else 1, -len(lib.get("jni_exports") or [])))
        results = []
        decompiled_count = 0
        for lib in targets[:1]:
            result = run_ghidra(
                self.ws.root,
                lib.get("path"),
                lib.get("abi"),
                prefixes="Java_,JNI_OnLoad,d2c_",
            )
            if result.get("ok"):
                collected = collect_pseudocode(self.ws.root, result)
                result["collected_pseudocode"] = len(collected)
                decompiled_count += sum(1 for f in result.get("functions") or [] if f.get("decompiled"))
            results.append({k: v for k, v in result.items() if k not in ("functions",)})
        write_json(self.ws.path("native", "ghidra-run.json"), results)
        return {
            "enabled": True,
            "runs": len(results),
            "decompiled": decompiled_count,
            "results": results,
        }

    def stage_recovery(self) -> dict[str, Any]:
        exact = recover_exact_dex(self.ws.root)
        methods = self._get_methods()
        classes = self._get_classes()
        functions = read_jsonl(self.ws.path("native", "function-analysis.jsonl"))
        candidates = read_jsonl(self.ws.path("inventory", "protected-method-candidates.jsonl"))
        recon = recover_equivalent_dex(
            self.ws.root,
            functions,
            methods,
            classes,
            candidates=candidates,
            max_methods=self.max_reconstruct,
        )
        unresolved = build_unresolved(
            self.ws.root,
            read_jsonl(self.ws.path("inventory", "protected-method-candidates.jsonl")),
            read_jsonl(self.ws.path("native", "method-mappings.jsonl")),
            recon,
        )
        return {
            "exact_artifacts": len(exact.get("artifacts") or []),
            "exact_dex": exact.get("exact", 0),
            "reconstructed_methods": len(recon.get("methods") or []),
            "unresolved": len(unresolved),
            "artifacts": recon.get("artifacts") or [],
        }

    def stage_validation(self) -> dict[str, Any]:
        result = validate_workspace(self.ws.root, run_external=True)
        dex_by_path = {Path(r["path"]).resolve(): r for r in result["dex"]}
        exact_manifest_path = self.ws.path("recovery", "exact", "manifest.json")
        exact_entries = read_json(exact_manifest_path, []) or []
        for entry in exact_entries:
            recovered = entry.get("recovered_path")
            if recovered:
                val = dex_by_path.get(Path(recovered).resolve())
                if val:
                    entry["validation"] = {
                        "valid": val["valid"],
                        "errors": val["errors"],
                        "checks": val["checks"],
                        "validation_file": "validation/dex.jsonl",
                    }
                    entry["status"] = "EXACT_DEX" if val["valid"] and entry.get("status") == "EXACT_DEX" else "INVALID_CANDIDATE"
        write_json(exact_manifest_path, exact_entries)
        return result["summary"]

    def stage_runtime(self) -> dict[str, Any]:
        if self.runtime_mode == "none":
            return {"enabled": False, "reason": "runtime not requested"}
        session = runtime_observe(
            self.ws.root,
            self.ws.apk,
            serials=self.serials,
            allow_install=self.allow_install,
        )
        return {
            "enabled": True,
            "devices": len(session.get("devices") or []),
            "statuses": {d.get("serial"): d.get("status") for d in session.get("devices") or []},
            "artifacts": sum(len(d.get("artifacts") or []) for d in session.get("devices") or []),
        }

    def stage_report(self, command: str = "", test_results: dict[str, Any] | None = None) -> dict[str, Any]:
        report = build_report(self.ws.root, command=command, test_results=test_results)
        manifest = write_provenance(
            self.ws.root,
            input_sha256=self.input_sha,
            command=command,
            test_results=test_results,
        )
        return {
            "summary": report.get("summary"),
            "provenance_artifacts": len(manifest.get("artifacts") or []),
        }

    # ---- top-level ------------------------------------------------------
    def run_static(self, *, command: str = "analyze", include_report: bool = True) -> dict[str, Any]:
        self.stage("environment", self.stage_environment)
        self.stage("ingest", self.stage_ingest)
        self.stage("dex", self.stage_dex)
        self.stage("native", self.stage_native)
        self.stage("mapping", self.stage_mapping)
        self.stage("discovery", self.stage_discovery)
        self.stage("analysis", self.stage_analysis)
        self.stage("ghidra", self.stage_ghidra)
        self.stage("recovery", self.stage_recovery)
        self.stage("validation", self.stage_validation)
        if include_report:
            self.stage("report", lambda: self.stage_report(command=command), force=True)
        return {"workspace": str(self.ws.root), "input_sha256": self.input_sha, "stages": self.summaries}

    def run_all(self, *, command: str = "all", include_report: bool = True) -> dict[str, Any]:
        self.run_static(command=command, include_report=False)
        self.stage("runtime", self.stage_runtime)
        if include_report:
            self.stage("report", lambda: self.stage_report(command=command), force=True)
        return {"workspace": str(self.ws.root), "input_sha256": self.input_sha, "stages": self.summaries}

    def rerun_report(self, *, command: str = "report", test_results: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.stage_report(command=command, test_results=test_results)

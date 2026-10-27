"""Evidence-based protected-method discovery and method-to-native correlation."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .jni import (
    jni_long_name,
    jni_short_name,
)

STATUS_DEX_PRESENT = "DEX_PRESENT"
STATUS_PREEXISTING_NATIVE = "PREEXISTING_NATIVE"
STATUS_LIKELY_TRANSFORMED = "LIKELY_DEX2C_TRANSFORMED"
STATUS_TRANSFORMED = "TRANSFORMED_TO_NATIVE"
STATUS_MAPPED = "NATIVE_IMPLEMENTATION_MAPPED"
STATUS_ANALYZED = "NATIVE_ANALYZED"
STATUS_AMBIGUOUS = "AMBIGUOUS"
STATUS_UNRESOLVED = "UNRESOLVED"
STATUS_UNSUPPORTED = "UNSUPPORTED"


DEFAULT_THRESHOLDS = {
    "high_confidence": 0.72,
    "medium_confidence": 0.48,
    "class_native_ratio": 0.50,
    "class_native_count": 2,
    "loader_export_count": 20,
}


def _method_key(m: dict[str, Any]) -> str:
    return f"{m['class']}->{m['method']}{m['descriptor']}"


def _class_key(m: dict[str, Any]) -> str:
    return m["class"]


def _score_to_level(score: float, thresholds: dict[str, Any]) -> str:
    if score >= thresholds["high_confidence"]:
        return "high"
    if score >= thresholds["medium_confidence"]:
        return "medium"
    return "low"


def _library_loaded_evidence(loader_evidence: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, set[str]]:
    loaded: set[str] = set()
    primary = None
    for item in loader_evidence:
        lib = (item.get("library") or "").strip()
        if not lib:
            continue
        normalized = lib
        if not normalized.endswith(".so"):
            normalized = "lib" + normalized + ".so"
        loaded.add(normalized.lower())
        if primary is None:
            primary = item
    return primary, loaded


def _export_index(libs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for lib in libs:
        for sym in lib.get("jni_exports") or []:
            index[sym["name"]].append(
                {
                    "library": lib.get("name"),
                    "abi": lib.get("abi"),
                    "path": lib.get("path"),
                    "role": lib.get("role"),
                    "symbol": sym["name"],
                    "address": sym.get("value"),
                    "size": sym.get("size"),
                }
            )
    for key in index:
        index[key].sort(key=lambda x: (str(x.get("abi")), str(x.get("library"))))
    return index


def _library_string_evidence(method: dict[str, Any], libs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence = []
    cls = method["class"]
    name = method["method"]
    sig = method["descriptor"]
    for lib in libs:
        strings = lib.get("strings_of_interest") or []
        values = {s.get("value") for s in strings}
        if cls in values and (name in values or sig in values):
            evidence.append(
                {
                    "kind": "class_and_member_strings_in_library",
                    "source": lib.get("path"),
                    "detail": f"{lib.get('name')} contains {cls} and method markers",
                }
            )
    return evidence


def _protection_library_roles(libs: list[dict[str, Any]], loaded_libs: set[str]) -> set[str]:
    roles = set()
    for lib in libs:
        role = lib.get("role") or ""
        name = (lib.get("name") or "").lower()
        base = name
        if base in loaded_libs or any(base == item for item in loaded_libs):
            if role in ("dex2c_generated_library", "large_jni_library", "jni_dynamic_registration_library"):
                roles.add(role)
        if role == "dex2c_generated_library":
            roles.add(role)
    return roles


def discover_candidates(
    methods: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    libraries: list[dict[str, Any]],
    loader_evidence: list[dict[str, Any]],
    *,
    thresholds: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    exports = _export_index(libraries)
    loader_item, loaded_libs = _library_loaded_evidence(loader_evidence)
    protected_roles = _protection_library_roles(libraries, loaded_libs)
    class_stats = {c["descriptor"]: c for c in classes}
    candidates: list[dict[str, Any]] = []

    # A library load is not sufficient evidence that the declaring class is the
    # protection loader: ordinary third-party libraries load themselves in
    # <clinit> too.  Prefer a loaded library classified as Dex2C-generated and
    # require loader-like class evidence for infrastructure classification.
    all_loader_classes = {item["class"] for item in loader_evidence}
    protection_loader_classes: set[str] = set()
    primary_library: dict[str, Any] | None = None
    for item in loader_evidence:
        lib = (item.get("library") or "").strip()
        if not lib:
            continue
        if not lib.endswith(".so"):
            lib = "lib" + lib + ".so"
        match = next((x for x in libraries if (x.get("name") or "").lower() == lib.lower()), None)
        cs = class_stats.get(item["class"], {})
        loader_like = (
            "dcc" in item["class"].lower()
            or "dex2c" in item["class"].lower()
            or (cs.get("method_count") or 99) <= 4
            or (cs.get("native_count") or 0) <= 2
        )
        if match and match.get("role") == "dex2c_generated_library":
            if primary_library is None or len(match.get("jni_exports") or []) > len(primary_library.get("jni_exports") or []):
                primary_library = match
            if loader_like:
                protection_loader_classes.add(item["class"])
    if primary_library is None:
        # Fallback: the library with the most JNI exports referenced by a
        # loader, but do not call it protection infrastructure without evidence.
        best = None
        for item in loader_evidence:
            lib = (item.get("library") or "").strip()
            if not lib:
                continue
            if not lib.endswith(".so"):
                lib = "lib" + lib + ".so"
            match = next((x for x in libraries if (x.get("name") or "").lower() == lib.lower()), None)
            if match and (best is None or len(match.get("jni_exports") or []) > len(best.get("jni_exports") or [])):
                best = match
        primary_library = best
    loader_classes = protection_loader_classes

    for method in methods:
        if not method.get("native"):
            continue
        cls = method["class"]
        cs = class_stats.get(cls, {})
        score = 0.0
        evidence: list[dict[str, Any]] = []
        alternatives: list[str] = []
        mapping_candidates: list[dict[str, Any]] = []
        expected_long = jni_long_name(cls, method["method"], method["descriptor"])
        expected_short = jni_short_name(cls, method["method"])
        for expected in (expected_long, expected_short):
            for candidate in exports.get(expected, []):
                mapping_candidates.append(candidate)
                evidence.append(
                    {
                        "kind": "jni_export_symbol",
                        "source": candidate.get("path"),
                        "detail": f"{candidate['symbol']} at 0x{candidate.get('address', 0):x}",
                        "library": candidate.get("library"),
                        "abi": candidate.get("abi"),
                    }
                )
                if candidate.get("role") == "dex2c_generated_library" or candidate.get("role") in protected_roles:
                    score += 0.50
                else:
                    score += 0.30
        if cls in loader_classes:
            evidence.append(
                {
                    "kind": "loaded_by_class_initializer",
                    "source": "DEX",
                    "detail": f"{cls} calls System.loadLibrary",
                }
            )
            score += 0.08
        if cs.get("all_methods_native"):
            score += 0.15
            evidence.append(
                {
                    "kind": "all_methods_native",
                    "source": "DEX",
                    "detail": f"{cs.get('native_count')} of {cs.get('method_count')} methods are native",
                }
            )
        if (cs.get("native_ratio") or 0) >= thresholds["class_native_ratio"]:
            score += 0.10
            evidence.append(
                {
                    "kind": "high_native_ratio",
                    "source": "DEX",
                    "detail": f"native ratio {cs.get('native_ratio'):.2f}",
                }
            )
        if cs.get("has_native_constructor"):
            score += 0.08
            evidence.append(
                {
                    "kind": "native_constructor_cluster",
                    "source": "DEX",
                    "detail": "class has one or more native constructors",
                }
            )
        if (cs.get("native_count") or 0) >= thresholds["class_native_count"]:
            score += 0.05
        if any(("Dex2C" in a) for a in cs.get("annotations") or []):
            score += 0.20
            evidence.append({"kind": "dex2c_annotation", "source": "DEX", "detail": "class has Dex2C annotation"})
        # Native method declared in a class with no code at all is a very strong
        # Dex2C signal, but only for non-loader classes.
        if (cs.get("method_count") or 0) > 0 and (cs.get("code_count") or 0) == 0 and cls not in loader_classes:
            score += 0.10
            evidence.append({"kind": "class_has_no_dalvik_code", "source": "DEX", "detail": "all methods lack code"})

        lib_string_evidence = _library_string_evidence(method, libraries)
        if lib_string_evidence:
            evidence.extend(lib_string_evidence)
            # A class/member string in a library is supporting evidence but not
            # enough on its own, because string tables commonly retain names.
            score += 0.08

        category = "protected_method"
        primary_status = STATUS_UNRESOLVED
        recovery_eligible = True

        if cls in loader_classes:
            category = "protection_loader_infrastructure"
            recovery_eligible = False
            primary_status = STATUS_TRANSFORMED
            alternatives.append("Loader class may be injected by the protection tool rather than transformed app code")
        elif primary_library and mapping_candidates:
            roles = {c.get("role") for c in mapping_candidates}
            if roles & protected_roles or "dex2c_generated_library" in roles:
                primary_status = STATUS_LIKELY_TRANSFORMED
        if not mapping_candidates and lib_string_evidence:
            primary_status = STATUS_AMBIGUOUS
        if mapping_candidates and not (primary_library and any(c.get("role") in protected_roles for c in mapping_candidates)):
            # Exported JNI function in a library not proven to be protection-generated.
            if any(c.get("role") == "third_party_native_library" for c in mapping_candidates):
                alternatives.append("Exported symbol belongs to a third-party native library")

        # Preexisting native classification: a matching implementation exists
        # in a library that is not part of the protection library set and whose
        # strings/role indicate a normal third-party or app native library.
        third_party_matches = [
            c for c in mapping_candidates
            if c.get("role") in ("third_party_native_library", "third_party_protection_library", "small_jni_library", "unrelated_or_support")
        ]
        if third_party_matches and not (mapping_candidates and any(c.get("role") == "dex2c_generated_library" for c in mapping_candidates)):
            primary_status = STATUS_PREEXISTING_NATIVE
            category = "preexisting_native"
            recovery_eligible = False
            alternatives.append("Method may have been native before protection; no transformed DEX body is implied")
            score = min(score, 0.45)

        # App namespace native methods without any library evidence remain ambiguous.
        if not mapping_candidates and not lib_string_evidence and not cs.get("all_methods_native"):
            primary_status = STATUS_AMBIGUOUS

        if score >= thresholds["high_confidence"] and primary_status not in (STATUS_PREEXISTING_NATIVE,):
            primary_status = STATUS_LIKELY_TRANSFORMED
        elif score >= thresholds["medium_confidence"] and primary_status == STATUS_UNRESOLVED:
            primary_status = STATUS_AMBIGUOUS

        confidence_level = _score_to_level(min(score, 1.0), thresholds)
        if primary_status == STATUS_PREEXISTING_NATIVE:
            confidence_level = "medium" if mapping_candidates else "low"
        candidates.append(
            {
                "schema_version": "1.0",
                "method_key": _method_key(method),
                "dex_file": method.get("dex_file"),
                "class": cls,
                "method": method["method"],
                "descriptor": method["descriptor"],
                "access_flags": method.get("access_flags"),
                "access": method.get("access"),
                "native": True,
                "code_present_in_protected_dex": method.get("code_present", False),
                "class_patterns": {
                    "method_count": cs.get("method_count"),
                    "native_count": cs.get("native_count"),
                    "code_count": cs.get("code_count"),
                    "native_ratio": cs.get("native_ratio"),
                    "all_methods_native": cs.get("all_methods_native"),
                    "has_native_constructor": cs.get("has_native_constructor"),
                    "class_annotations": cs.get("annotations", []),
                },
                "candidate_native_library": (mapping_candidates[0].get("library") if mapping_candidates else (primary_library or {}).get("name")),
                "candidate_native_libraries": sorted({c.get("library") for c in mapping_candidates if c.get("library")}),
                "mapping_candidates": mapping_candidates,
                "evidence": evidence,
                "score": round(score, 4),
                "confidence": confidence_level,
                "confidence_score": round(min(score, 1.0), 4),
                "status": primary_status,
                "category": category,
                "recovery_eligible": recovery_eligible,
                "analysis_status": "DISCOVERED",
                "alternatives": sorted(set(alternatives)),
                "notes": [],
            }
        )
    candidates.sort(key=lambda r: (r["class"], r["method"], r["descriptor"]))
    summary = {
        "thresholds": thresholds,
        "loader_evidence": loader_evidence,
        "loader_classes": sorted(loader_classes),
        "all_library_loading_classes": sorted(all_loader_classes),
        "loaded_libraries": sorted(loaded_libs),
        "primary_library": primary_library.get("name") if primary_library else None,
        "protection_library_roles": sorted(protected_roles),
        "native_methods": len(candidates),
        "by_status": dict(sorted(Counter(c["status"] for c in candidates).items())),
        "by_confidence": dict(sorted(Counter(c["confidence"] for c in candidates).items())),
        "recovery_eligible": sum(1 for c in candidates if c["recovery_eligible"]),
    }
    return candidates, summary


def classify_all_methods(methods: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidate_by_key = {c["method_key"]: c for c in candidates}
    out: list[dict[str, Any]] = []
    for m in methods:
        key = _method_key(m)
        c = candidate_by_key.get(key)
        row = dict(m)
        if m.get("native"):
            row["primary_status"] = c["status"] if c else STATUS_AMBIGUOUS
            row["candidate"] = bool(c)
        else:
            row["primary_status"] = STATUS_DEX_PRESENT if m.get("code_present") else STATUS_UNRESOLVED
            row["candidate"] = False
        out.append(row)
    return out

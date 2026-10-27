"""Method-to-native correlation from JNI exports and registration tables."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .jni import jni_long_name, jni_short_name, normalize_descriptor

MAPPING_CONFIRMED = "CONFIRMED"
MAPPING_STRONG = "STRONGLY_SUPPORTED"
MAPPING_CANDIDATE = "CANDIDATE"
MAPPING_AMBIGUOUS = "AMBIGUOUS"
MAPPING_UNRESOLVED = "UNRESOLVED"


def _method_key(m: dict[str, Any]) -> str:
    return f"{m['class']}->{m['method']}{m['descriptor']}"


def _lib_label(lib: dict[str, Any]) -> str:
    return f"{lib.get('name')}:{lib.get('abi')}"


def index_exports(libraries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for lib in libraries:
        for sym in lib.get("jni_exports") or []:
            if sym.get("name") == "JNI_OnLoad":
                continue
            index[sym["name"]].append(
                {
                    "library": lib.get("name"),
                    "library_sha256": lib.get("sha256"),
                    "library_path": lib.get("path"),
                    "abi": lib.get("abi"),
                    "role": lib.get("role"),
                    "symbol": sym.get("name"),
                    "address": sym.get("value"),
                    "size": sym.get("size"),
                    "source": "static_export",
                }
            )
    for key in index:
        index[key].sort(key=lambda x: (str(x.get("abi")), str(x.get("library")), str(x.get("address"))))
    return index


def registration_mappings(libraries: list[dict[str, Any]], methods: list[dict[str, Any]]) -> list[dict[str, Any]]:
    native_by_name_sig: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for method in methods:
        if method.get("native"):
            native_by_name_sig[f"{method['method']}{method['descriptor']}"].append(method)
    rows: list[dict[str, Any]] = []
    for lib in libraries:
        for table in lib.get("native_method_tables") or []:
            for entry in table.get("entries") or []:
                key = f"{entry['name']}{normalize_descriptor(entry['signature'])}"
                matches = native_by_name_sig.get(key, [])
                # Prefer matches whose class descriptor appears as a string in
                # the library; fall back to the unique method with this shape.
                lib_strings = {s.get("value") for s in lib.get("strings_of_interest") or []}
                class_matches = [
                    m for m in matches
                    if m["class"] in lib_strings or m["class"][1:-1] in lib_strings
                ]
                selected = class_matches or matches
                rows.append(
                    {
                        "library": lib.get("name"),
                        "library_sha256": lib.get("sha256"),
                        "library_path": lib.get("path"),
                        "abi": lib.get("abi"),
                        "role": lib.get("role"),
                        "source": "dynamic_registration_array",
                        "array_address": table.get("array_address"),
                        "array_index": (table.get("entries") or []).index(entry),
                        "name": entry["name"],
                        "signature": entry["signature"],
                        "function_address": entry["function_address"],
                        "matched_methods": [m["method_key"] if "method_key" in m else _method_key(m) for m in selected],
                        "matched_classes": sorted({m["class"] for m in selected}),
                        "class_string_present": bool(class_matches),
                        "ambiguous": len(selected) != 1,
                    }
                )
    rows.sort(key=lambda r: (str(r["library"]), str(r["abi"]), str(r["name"]), int(r.get("function_address") or 0)))
    return rows


def register_natives_evidence(libraries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for lib in libraries:
        calls = lib.get("register_natives_calls") or []
        if not calls:
            continue
        for call in calls:
            rows.append(
                {
                    "library": lib.get("name"),
                    "library_sha256": lib.get("sha256"),
                    "abi": lib.get("abi"),
                    "source": "jni_env_register_natives_call",
                    "call_address": call.get("call_address"),
                    "table_offset": call.get("table_offset"),
                    "jni_function": call.get("jni_function"),
                    "table_index": call.get("table_index"),
                }
            )
    return rows


def build_mappings(
    methods: list[dict[str, Any]],
    libraries: list[dict[str, Any]],
    registration: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    exports = index_exports(libraries)
    registration = registration or registration_mappings(libraries, methods)
    reg_by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in registration:
        for method_key in row.get("matched_methods") or []:
            reg_by_method[method_key].append(row)

    # A native function may implement multiple methods (shared helper or
    # ambiguous symbols).  Track it explicitly.
    address_uses: dict[tuple[str, str, int], list[str]] = defaultdict(list)

    out: list[dict[str, Any]] = []
    for method in methods:
        if not method.get("native"):
            continue
        key = _method_key(method)
        long_name = jni_long_name(method["class"], method["method"], method["descriptor"])
        short_name = jni_short_name(method["class"], method["method"])
        candidates: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        alternatives: list[dict[str, Any]] = []
        for symbol, strength in ((long_name, 0.99), (short_name, 0.72)):
            for cand in exports.get(symbol, []):
                c = dict(cand)
                c["match_kind"] = "long_jni_name" if symbol == long_name else "short_jni_name"
                c["match_strength"] = strength
                candidates.append(c)
                evidence.append(
                    {
                        "kind": "symbol_name_match",
                        "source": cand.get("library_path"),
                        "detail": f"{symbol} exported at 0x{cand.get('address', 0):x}",
                        "strength": strength,
                    }
                )
        for row in reg_by_method.get(key, []):
            c = {
                "library": row.get("library"),
                "library_path": row.get("library_path"),
                "abi": row.get("abi"),
                "role": row.get("role"),
                "symbol": None,
                "address": row.get("function_address"),
                "size": None,
                "source": "dynamic_registration_array",
                "match_kind": "register_natives_array",
                "match_strength": 0.92 if not row.get("ambiguous") else 0.55,
                "array_address": row.get("array_address"),
                "registration_name": row.get("name"),
                "registration_signature": row.get("signature"),
                "class_string_present": row.get("class_string_present"),
                "ambiguous": row.get("ambiguous"),
            }
            candidates.append(c)
            evidence.append(
                {
                    "kind": "register_natives_array_entry",
                    "source": row.get("library_path"),
                    "detail": f"{row.get('name')}{row.get('signature')} -> 0x{row.get('function_address', 0):x}",
                    "strength": c["match_strength"],
                }
            )
        # De-duplicate by library/address/source.
        uniq: dict[tuple, dict[str, Any]] = {}
        for cand in candidates:
            k = (cand.get("library"), cand.get("abi"), cand.get("address"), cand.get("source"))
            if k not in uniq or (cand.get("match_strength") or 0) > (uniq[k].get("match_strength") or 0):
                uniq[k] = cand
        candidates = sorted(uniq.values(), key=lambda c: (-(c.get("match_strength") or 0), str(c.get("abi")), str(c.get("library"))))
        primary = candidates[0] if candidates else None
        if primary:
            address_uses[(primary.get("library"), primary.get("abi"), int(primary.get("address") or 0))].append(key)
        for cand in candidates[1:]:
            alternatives.append(
                {
                    "library": cand.get("library"),
                    "abi": cand.get("abi"),
                    "address": cand.get("address"),
                    "symbol": cand.get("symbol"),
                    "reason": "additional matching export/registration entry",
                }
            )

        if not candidates:
            mapping_status = MAPPING_UNRESOLVED
        elif primary and primary.get("source") == "dynamic_registration_array" and primary.get("ambiguous"):
            mapping_status = MAPPING_AMBIGUOUS
        elif len(candidates) > 1 and len({(c.get("address"), c.get("abi"), c.get("library")) for c in candidates}) > 1:
            # Multiple distinct implementations for one Java method.
            mapping_status = MAPPING_AMBIGUOUS if all((c.get("match_strength") or 0) < 0.9 for c in candidates) else MAPPING_STRONG
        elif primary and primary.get("source") == "static_export" and primary.get("match_kind") == "long_jni_name" or primary and primary.get("source") == "dynamic_registration_array" and not primary.get("ambiguous", False):
            mapping_status = MAPPING_CONFIRMED
        elif primary:
            mapping_status = MAPPING_STRONG
        else:
            mapping_status = MAPPING_UNRESOLVED

        if primary and primary.get("source") == "static_export":
            strength = primary.get("match_strength") or 0
            if strength >= 0.99:
                mapping_status = MAPPING_CONFIRMED
            elif strength >= 0.7:
                mapping_status = MAPPING_STRONG
        confidence = 0.0
        if primary:
            confidence = max((c.get("match_strength") or 0) for c in candidates)
            if len(candidates) > 1:
                confidence -= 0.10
            confidence = round(max(0.0, min(1.0, confidence)), 4)
        out.append(
            {
                "schema_version": "1.0",
                "method_key": key,
                "dex_file": method.get("dex_file"),
                "class": method["class"],
                "method": method["method"],
                "descriptor": method["descriptor"],
                "access_flags": method.get("access_flags"),
                "mapping_status": mapping_status,
                "status": "NATIVE_IMPLEMENTATION_MAPPED" if primary else "UNRESOLVED",
                "analysis_status": "MAPPED" if primary else "DISCOVERED",
                "confidence": confidence,
                "primary_function": primary,
                "candidates": candidates,
                "alternative_candidates": alternatives,
                "evidence": evidence,
                "cross_abi": {
                    c.get("abi"): {
                        "address": c.get("address"),
                        "library": c.get("library"),
                        "symbol": c.get("symbol"),
                        "source": c.get("source"),
                    }
                    for c in candidates
                },
                "library": primary.get("library") if primary else None,
                "abi": primary.get("abi") if primary else None,
                "function_symbol": primary.get("symbol") if primary else None,
                "function_address": primary.get("address") if primary else None,
                "unresolved_questions": [] if primary else ["No exact JNI export or registration table entry matched this method"],
                "shared_function": False,
            }
        )
    # Mark shared functions and add alternatives for every method using one.
    for row in out:
        p = row.get("primary_function")
        if not p:
            continue
        uses = address_uses.get((p.get("library"), p.get("abi"), int(p.get("address") or 0)), [])
        if len(uses) > 1:
            row["shared_function"] = True
            row["shared_with"] = sorted(set(uses) - {row["method_key"]})
            row["unresolved_questions"].append("Native address is referenced by multiple Java methods")
    summary = {
        "native_methods": len(out),
        "by_mapping_status": dict(sorted(Counter(r["mapping_status"] for r in out).items())),
        "with_primary_function": sum(1 for r in out if r.get("primary_function")),
        "shared_functions": sum(1 for r in out if r.get("shared_function")),
        "registration_entries": len(registration),
        "libraries_with_register_natives_calls": sorted(
            {lib.get("name") for lib in libraries if lib.get("register_natives_calls")}
        ),
    }
    return sorted(out, key=lambda r: (r["class"], r["method"], r["descriptor"])), summary


def enrich_candidates(candidates: list[dict[str, Any]], mappings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {m["method_key"]: m for m in mappings}
    for candidate in candidates:
        mapping = by_key.get(candidate["method_key"])
        if not mapping:
            continue
        candidate["mapping_status"] = mapping["mapping_status"]
        candidate["mapping_confidence"] = mapping["confidence"]
        candidate["analysis_status"] = "MAPPED" if mapping.get("primary_function") else "DISCOVERED"
        p = mapping.get("primary_function")
        if not p:
            continue
        role = p.get("role") or ""
        if candidate.get("category") == "protection_loader_infrastructure":
            candidate["status"] = "TRANSFORMED_TO_NATIVE"
        elif role in ("third_party_native_library", "third_party_protection_library") or role == "jni_dynamic_registration_library" and _library_matches_class(p.get("library") or "", candidate["class"]):
            candidate["status"] = "PREEXISTING_NATIVE"
            candidate["category"] = "preexisting_native"
            candidate["recovery_eligible"] = False
        elif role in ("dex2c_generated_library", "large_jni_library"):
            candidate["status"] = "LIKELY_DEX2C_TRANSFORMED"
            candidate["category"] = "protected_method"
            candidate["recovery_eligible"] = True
        candidate.setdefault("candidate_native_libraries", [])
        if p.get("library") and p["library"] not in candidate["candidate_native_libraries"]:
            candidate["candidate_native_libraries"].append(p["library"])
        candidate["candidate_native_libraries"] = sorted(set(candidate["candidate_native_libraries"]))
        if p.get("source"):
            candidate["evidence"].append(
                {
                    "kind": "mapping",
                    "source": p.get("library_path"),
                    "detail": f"{p.get('source')} -> {p.get('symbol') or hex(int(p.get('address') or 0))}",
                }
            )
    return candidates


def _library_matches_class(library: str, class_descriptor: str) -> bool:
    import re

    class_l = class_descriptor.strip("L;").lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", library.lower()) if len(t) >= 4]
    return any(t in class_l for t in tokens)

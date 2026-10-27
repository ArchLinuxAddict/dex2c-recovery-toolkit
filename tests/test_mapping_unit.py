from __future__ import annotations

from dex2c_recover.mapping import build_mappings, registration_mappings


def test_ambiguous_dynamic_registration_is_not_confirmed() -> None:
    methods = [
        {"class": "Lx/A;", "method": "m", "descriptor": "()V", "native": True, "dex_file": "classes.dex", "access_flags": 0x101},
        {"class": "Ly/B;", "method": "m", "descriptor": "()V", "native": True, "dex_file": "classes.dex", "access_flags": 0x101},
    ]
    lib = {
        "name": "libstub.so",
        "abi": "arm64-v8a",
        "role": "dex2c_generated_library",
        "sha256": "0" * 64,
        "path": "libstub.so",
        "strings_of_interest": [],
        "native_method_tables": [
            {"array_address": 0x1000, "entries": [{"name": "m", "signature": "()V", "function_address": 0x9999}]}
        ],
    }
    registration = registration_mappings([lib], methods)
    assert registration and registration[0]["ambiguous"] is True
    rows, summary = build_mappings(methods, [lib], registration)
    assert len(rows) == 2
    assert all(r["mapping_status"] == "AMBIGUOUS" for r in rows)
    assert all(r["primary_function"]["ambiguous"] is True for r in rows)

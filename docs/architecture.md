# Architecture

## Entry point

`dex2c_recover.cli:main` is the console entry point. The repository-local
`./dex2c-recover` launcher prefers `.venv/bin/python` when present, then runs the
package from `src/`.

## Pipeline

`Pipeline` (`src/dex2c_recover/pipeline.py`) runs resumable stages, keyed by the
input APK SHA-256:

1. **environment** — discovers Python libraries and external tools.
2. **ingest** — inventories the unchanged APK, DEX files, native libraries,
   embedded ZIP/APK artifacts, and manifest metadata. Extraction is bounded.
3. **dex** — parses headers, classes, methods, code items, loader evidence, and
   interesting strings.
4. **native** — analyzes ELF metadata, JNI exports, `JNI_OnLoad`, registration
   arrays, `RegisterNatives` call sites, and cross-ABI relationships.
5. **mapping** — joins methods to native functions using long JNI names,
   registration tables, class/member strings, and ABI evidence.
6. **discovery** — classifies transformed, pre-existing native, loader, and
   ambiguous methods with confidence and evidence.
7. **analysis** — disassembles mapped functions, records JNIEnv calls, and
   builds call graphs/control-flow evidence.
8. **ghidra** — optional decompilation of the primary generated library.
9. **recovery** — recovers exact supplied artifacts and a deliberately small
   set of behavioral leaf equivalents; records everything else as unresolved.
10. **validation** — validates DEX/ELF artifacts independently; optional
    dexdump/baksmali cross-checks.
11. **runtime** — optional authorized ADB/Frida observation.
12. **report** — machine-readable/human-readable reports and SHA-256 provenance.

## Modules

| Module | Responsibility |
|---|---|
| `ingest.py` | Safe APK/ZIP inventory and bounded extraction |
| `dexparse.py` | DEX header, class, method, instruction, and string parsing |
| `elfs.py` | ELF/JNI export and registration analysis |
| `discovery.py` | Candidate classification from multiple signals |
| `mapping.py` | Method-to-function correlation and confidence |
| `native_analysis.py` | Disassembly, JNIEnv call extraction, call graphs |
| `ghidra.py` | Optional Ghidra import/decompilation |
| `recovery.py` | Exact-artifact handling and conservative leaf reconstruction |
| `validation.py` | Structural DEX/ELF and workspace validation |
| `runtime.py` | Optional ADB/Frida runtime evidence |
| `report.py` | Reports and provenance manifests |
| `workspace.py` | Stage state, input hashing, output layout |
| `environment.py` | Tool/dependency discovery and overrides |
| `source_model.py` | Attributed Dex2C transformation facts |

## Data flow

```text
APK -> ingest inventory -> DEX/ELF analysis -> candidate classification
    -> JNI mapping -> native function analysis -> recovery decision
    -> structural validation -> report + provenance
```

The supplied APK is never modified. Writes are confined to the chosen output
directory. Stage state records the input hash and can be resumed or forced.

## Design boundaries

- Status, evidence, confidence, and validation are separate fields.
- Exact artifact recovery and behavioral reconstruction are separate
  classifications.
- Missing external tools are recorded as limitations; they do not silently
  fabricate success.
- The public toolkit intentionally excludes target-specific research drivers
  and fixtures that cannot be redistributed.

# Test report — 1.0.0

## Environment

- Linux
- Python 3.14.8
- pytest 9.1.1
- No private target APK or ADB device used for the default suite

## Command

```bash
.venv/bin/pytest -q -rs
```

## Results

| Metric | Count |
|---|---:|
| Passed | 23 |
| Failed | 0 |
| Skipped | 2 |
| Errors | 0 |

## Skipped tests

1. **Real-target integration** — skipped because `DEX2C_TEST_APK` is not set.
   Run it only with an authorized APK:
   `DEX2C_TEST_APK=/path/to/authorized.apk pytest -q -m integration`.
2. **Synthetic smali assembly** — skipped because `smali` is unavailable. The
   prebuilt synthetic DEX fixture tests still run.

## What is covered

- Synthetic DEX parsing, header checks, class/method inventory, truncation and
  tamper rejection.
- Synthetic APK end-to-end static pipeline: ingest, DEX analysis, discovery,
  recovery, validation, report, and provenance.
- JNI name/descriptor helpers.
- Ambiguous dynamic registration behavior.
- Workspace resume/isolation.
- CLI help, version, device discovery, missing/non-ZIP input rejection.
- Optional synthetic ELF assembly when gcc and headers are available.

## Not covered by the public suite

- Real Dex2C-protected APKs (no such APK is distributed).
- Ghidra decompilation (optional external tool).
- Runtime ADB/Frida observation (no device in CI).
- Universal behavioral equivalence (not a testable claim from finite cases).

## Pre-existing failures

No failures in the public suite. The original private research suite had stale
Phase VII count/provenance assertions; those are documented and corrected in the
research lab, not used as public toolkit tests.

## Coverage

Coverage is not measured in 1.0.0 and no percentage is claimed. Critical
synthetic paths and malformed-input handling are prioritized.

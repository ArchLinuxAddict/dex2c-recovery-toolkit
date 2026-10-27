# Dex2C Recovery Toolkit

[![tests](https://github.com/ArchLinuxAddict/dex2c-recovery-toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/ArchLinuxAddict/dex2c-recovery-toolkit/actions/workflows/tests.yml)

An evidence-driven analysis toolkit for APKs protected with
[codehasan/dex2c](https://github.com/codehasan/dex2c). It inventories DEX and
native libraries, discovers likely transformed methods, maps JNI exports and
registration tables, analyzes native implementations, validates recovered
artifacts, and produces deterministic reports and provenance.

**Status:** early public release (1.0.0, beta). The generic pipeline is tested;
advanced target-specific recovery research is documented in the companion
[Dex2C Recovery Lab](https://github.com/ArchLinuxAddict/dex2c-recovery-lab).

## What it does

- Ingests an APK without modifying it and inventories DEX files, native
  libraries, embedded ZIP/APK artifacts, and metadata.
- Parses DEX headers, classes, methods, code items, and loader evidence.
- Analyzes ELF libraries for JNI exports, `JNI_OnLoad`, `JNINativeMethod`
  tables, `RegisterNatives` call sites, and cross-ABI differences.
- Discovers likely Dex2C-transformed methods using native declarations,
  loader evidence, export shapes, registration data, and class-level signals.
- Maps methods to native functions with confidence and retained evidence.
- Recovers exact DEX artifacts only when a candidate is genuinely present and
  independently validated; labels them as supplied-artifact recovery, not
  original-code recovery.
- Reconstructs a deliberately small set of side-effect-free leaf methods
  (for example constant/void returns) as behavioral equivalents.
- Validates DEX/ELF artifacts structurally and can cross-check with
  `dexdump` and baksmali when installed.
- Optionally observes authorized runtime evidence through ADB and Frida.
- Writes reports, unresolved-method records, and SHA-256 provenance manifests.

## What it does not do

- It does not recover original source code.
- It does not claim that a native function uniquely determines the original
  Dalvik instruction sequence.
- It does not claim universal semantic equivalence from structural validity or
  a finite test set.
- It does not bypass security controls, modify devices, or install an APK
  unless `--allow-install` is used and the package is absent.
- It does not include a target APK, recovered third-party application code, or
  embedded payloads.
- Phase IV–VII target-specific research drivers are **not** part of this
  stable toolkit release. Their sanitized findings and methodology live in the
  lab repository.

## Requirements

- Python 3.10 or newer (verified on Linux with Python 3.14.8)
- Linux is the verified host platform. Other POSIX systems may work but are not
  part of the tested release claim.
- Optional external tools, discovered from environment variables or `PATH`:
  - Android SDK platform tools (`adb`)
  - `dexdump`, baksmali, smali
  - Ghidra (decompilation)
  - JADX / apktool (supplementary inspection)
  - Android NDK (native test fixtures)
  - Frida Python package and a device for runtime observation

The toolkit works without Ghidra or a device; capabilities are reported in the
environment inventory and missing tools become explicit limitations.

## Install

```bash
git clone https://github.com/ArchLinuxAddict/dex2c-recovery-toolkit.git
cd dex2c-recovery-toolkit
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/dex2c-recover --version
```

For the runtime extra:

```bash
.venv/bin/pip install -e ".[dev,runtime]"
```

See [docs/installation.md](docs/installation.md) for tool-specific setup.

## Quick start

Provide your own authorized Dex2C-protected APK; none is included.

```bash
.venv/bin/dex2c-recover analyze \
  --apk /path/to/authorized.apk \
  --out output/analysis

.venv/bin/dex2c-recover validate \
  --apk /path/to/authorized.apk \
  --out output/analysis

.venv/bin/dex2c-recover report \
  --apk /path/to/authorized.apk \
  --out output/analysis
```

Full static plus authorized runtime observation:

```bash
.venv/bin/dex2c-recover all \
  --apk /path/to/authorized.apk \
  --out output/analysis \
  --runtime auto
```

Device discovery:

```bash
.venv/bin/dex2c-recover devices --json
```

## Commands

```text
dex2c-recover analyze  --apk APK --out DIR [--ghidra auto|on|off]
dex2c-recover all      --apk APK --out DIR [--runtime none|auto|required] [--allow-install]
dex2c-recover runtime  --apk APK --out DIR [--runtime ...] [--device SERIAL]
dex2c-recover validate --apk APK --out DIR [--force]
dex2c-recover report   --apk APK --out DIR [--test-results FILE]
dex2c-recover devices  [--json]
```

Every command supports `--help`. Invalid paths, non-ZIP inputs, empty files, and
unreadable inputs are rejected with a non-zero exit code. Existing workspace
stages are resumed unless `--force` is supplied.

## Output

```text
output/analysis/
  inventory/        APK, DEX, method, native-library, discovery, environment
  native/           JNI registration, mappings, function analysis, call graphs,
                    disassembly, optional Ghidra pseudocode
  recovery/         exact-artifact manifest, reconstructed leaf DEX, unresolved
  validation/       DEX/ELF validation records
  reports/          report.json, report.txt
  provenance/       execution manifest and SHA256SUMS
  runtime/          optional device evidence
```

Open `reports/report.json` first. Status and evidence classes are separate:
structural validity does not imply behavioral equivalence.

## Testing

```bash
.venv/bin/pytest -q
```

The default suite uses self-created synthetic DEX and APK fixtures, runs the
static pipeline end-to-end, and does not need a private APK or device. The end-to-end pipeline test is marked `integration` and
is skipped unless an authorized APK is supplied:

```bash
DEX2C_TEST_APK=/path/to/authorized.apk .venv/bin/pytest -q -m integration
```

Optional external-tool checks and real-target integration tests skip cleanly
when the tool, device, or `DEX2C_TEST_APK` is unavailable. See [docs/development.md](docs/development.md).

## Documentation

- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Validation](docs/validation.md)
- [Output and provenance](docs/output-and-provenance.md)
- [Native/JNI analysis](docs/native-analysis.md)
- [Limitations](docs/limitations.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Development](docs/development.md)
- [Test report](docs/test-report.md)

## Troubleshooting

- `dexdump`/baksmali missing: validation still runs structurally; external
  cross-checks are skipped and reported as limitations.
- Ghidra unavailable: static analysis still runs; pseudocode stages report
  unavailable instead of failing the whole pipeline.
- No ADB device: runtime observation is skipped unless `--runtime required`.
- APK rejected: confirm the file is an unmodified ZIP/APK and readable. The
  toolkit never executes the input APK.

More in [docs/troubleshooting.md](docs/troubleshooting.md).

## Limitations

- No exact original bytecode is recovered from native code alone.
- Only a small leaf subset is behaviorally reconstructed.
- Ghidra pseudocode is decompiler output, not source or proof.
- Dynamic registration and stripped libraries can remain ambiguous.
- Runtime evidence depends on device access, root state, and tool versions.
- Results depend on the input artifact and installed tools.
- No universal semantic-equivalence or complete-recovery claim is made.

See [docs/limitations.md](docs/limitations.md).

## Responsible use

Use this toolkit only on applications you own or are authorized to analyze.
Respect applicable laws, contracts, and platform terms. Do not use it to bypass
security controls or to distribute third-party application code. The toolkit
does not include target APKs or recovered third-party code.

## License and attribution

Original code is licensed under the MIT License; see [LICENSE](LICENSE) and
[THIRD_PARTY.md](THIRD_PARTY.md). Dex2C is a separate upstream project and is
not bundled.

## Contributing and support

- [Contributing](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Support](SUPPORT.md)
- [Security policy](SECURITY.md)
- [Issues](https://github.com/ArchLinuxAddict/dex2c-recovery-toolkit/issues)
- [Research lab](https://github.com/ArchLinuxAddict/dex2c-recovery-lab)

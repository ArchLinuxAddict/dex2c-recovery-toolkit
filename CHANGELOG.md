# Changelog

All notable public changes are recorded here. The project uses
[Semantic Versioning](https://semver.org/) for the toolkit package.

## [1.0.0] - 2026-10-27

Initial public toolkit release.

### Added

- Standalone APK ingestion with bounded DEX/native/embedded-artifact inventory.
- DEX parsing, method/class inventory, and header/checksum validation.
- ELF analysis for JNI exports, `JNI_OnLoad`, registration arrays, and ABI
  comparison.
- Native-to-DEX candidate discovery and JNI mapping with confidence/evidence.
- Conservative exact-artifact handling and small leaf behavioral reconstruction.
- Structural validation with optional `dexdump`/`baksmali` cross-checks.
- Deterministic reports and SHA-256 provenance.
- Optional authorized runtime observation through ADB/Frida.
- CLI commands: `analyze`, `all`, `runtime`, `validate`, `report`, `devices`.
- Synthetic DEX/APK fixtures, unit tests, an end-to-end static pipeline test, and a gated real-target integration test.
- Public documentation covering installation, usage, architecture, configuration,
  limitations, and development.

### Notes

- No target APK, recovered third-party DEX, embedded payload, or external tool
  binary is included.
- Phase IV–VII target-specific research drivers are not part of this stable
  toolkit release; sanitized findings are published in the companion lab.
- Exact recovery, universal semantic equivalence, and complete method recovery
  are not claimed.

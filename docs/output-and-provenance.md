# Output and provenance

## Layout

```text
<out>/
  .state.json
  inventory/inputs.json
  inventory/environment.json
  inventory/dex-summary.json
  inventory/classes.jsonl
  inventory/methods.jsonl
  inventory/native-libraries.json
  inventory/native-abi-comparison.json
  inventory/protected-method-candidates.jsonl
  native/jni-registration.jsonl
  native/method-mappings.jsonl
  native/function-analysis.jsonl
  native/call-graphs/
  native/elf-analysis/
  native/disassembly/
  native/pseudocode/            (optional Ghidra)
  recovery/exact/manifest.json
  recovery/reconstructed/manifest.json
  recovery/unresolved.jsonl
  validation/
  reports/report.json
  reports/report.txt
  provenance/execution-manifest.json
  provenance/SHA256SUMS
  runtime/                      (optional)
```

## Provenance

- Input APK SHA-256 is recorded in inventory and execution manifest.
- Artifacts are hashed in `provenance/SHA256SUMS`.
- Reports separate status, evidence, confidence, and validation.
- Hashes establish artifact identity, not semantic correctness.

## Determinism

JSON is written with stable key ordering; JSONL preserves explicit row order.
External tool output may vary by version and is retained as evidence rather than
normalized away.

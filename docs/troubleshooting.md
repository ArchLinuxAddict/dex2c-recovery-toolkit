# Troubleshooting

## Input rejected

- Confirm the file is a readable ZIP/APK.
- Truncated or non-ZIP inputs fail before extraction.
- The toolkit does not repair or execute the APK.

## No DEX files found

The APK may use an unsupported container, split, or protection layout. Inspect
`inventory/inputs.json` and `inventory/dex-summary.json`. The toolkit does not
invent DEX content.

## No native mappings

- The library may be stripped and use opaque dynamic registration.
- The APK may not be Dex2C-protected.
- Check `native/elf-analysis/`, `native/mapping-summary.json`, and
  `inventory/discovery-summary.json`.
- Ambiguous registrations remain `AMBIGUOUS`; they are not promoted to
  confirmed mappings.

## Ghidra unavailable

Analysis continues without pseudocode. Set `DEX2C_GHIDRA_HEADLESS` or install
Ghidra and use `--ghidra on` to require it.

## dexdump/baksmali unavailable

Structural validation still runs. External cross-checks are listed as
unavailable rather than treated as passed.

## No ADB device

`devices --json` returns an empty selection. Use `--runtime none` for static
analysis, or connect an authorized device and rerun. `--runtime required` fails
intentionally when no device is present.

## Report contains unresolved methods

This is expected. Native analysis and mapping do not prove original bytecode.
Unresolved/unsupported records are evidence-backed outputs, not bugs.

## Output exists

Completed stages resume. Use `--force` to rerun them. The toolkit does not
delete previous workspaces.

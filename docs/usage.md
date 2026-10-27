# Usage

All commands require an authorized, user-supplied APK. No APK is bundled.

## Static analysis

```bash
dex2c-recover analyze \
  --apk /path/to/authorized.apk \
  --out output/analysis
```

Options:

- `--ghidra auto|on|off` — decompilation policy. `auto` uses Ghidra only when
  discovered. `on` requires it.
- `--abi ABI` — repeatable ABI filter.
- `--max-reconstruct N` — cap on attempted leaf reconstructions.
- `--force` — re-run completed stages for the same input hash.

## Full analysis with runtime observation

```bash
dex2c-recover all \
  --apk /path/to/authorized.apk \
  --out output/analysis \
  --runtime auto
```

`--runtime required` fails if no authorized device is present. `--allow-install`
installs the APK only on a rooted device and only when the package is absent.
The toolkit does not uninstall or overwrite an existing package.

## Runtime-only stage

```bash
dex2c-recover runtime \
  --apk /path/to/authorized.apk \
  --out output/analysis \
  --runtime auto \
  --device SERIAL
```

## Validation

```bash
dex2c-recover validate \
  --apk /path/to/authorized.apk \
  --out output/analysis
```

Validation checks DEX magic/version, file size, Adler-32 checksum, SHA-1
signature, table bounds, instruction decoding, and ELF structure. If dexdump or
baksmali is available, external disassembly checks are added.

## Reports and provenance

```bash
dex2c-recover report \
  --apk /path/to/authorized.apk \
  --out output/analysis \
  --test-results path/to/test-results.json
```

The report regenerates `reports/report.json`, `reports/report.txt`, and
`provenance/SHA256SUMS`.

## Devices

```bash
dex2c-recover devices
dex2c-recover devices --json
```

## Exit codes

- `0` — command completed.
- `1` — analysis/runtime failure.
- `2` — invalid invocation or input path/type.

## Input safety

- The input APK is hashed and copied to a workspace extraction directory; the
  source file is not modified.
- ZIP extraction rejects absolute/traversal paths and applies size limits.
- Invalid/truncated ZIP files are rejected before analysis.
- Output is written only under `--out`.

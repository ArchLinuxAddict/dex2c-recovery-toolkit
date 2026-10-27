# Development

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

## Tests

- Default suite: synthetic DEX/APK fixtures, unit tests, and an end-to-end static pipeline test; no private APK/device.
- Integration: `DEX2C_TEST_APK=/path/to/authorized.apk .venv/bin/pytest -q -m integration`
- Synthetic smali test skips if smali is unavailable.
- Synthetic ELF test skips if `gcc` or `jni.h` is unavailable.
- No test requires the original research target.

## Adding a rule

1. Define the evidence required.
2. Define rejection conditions.
3. Add a synthetic fixture and a positive/negative test.
4. Keep status, evidence, confidence, and validation separate.
5. Do not promote a method to exact/semantic equivalence without an
   authoritative reference.

## Release checklist

- Update `CHANGELOG.md` and version.
- Run default tests, ruff, and CLI smoke commands.
- Run the release audit script.
- Confirm no APK/DEX/native binary or local path is staged.
- Tag `vX.Y.Z` and publish release notes.

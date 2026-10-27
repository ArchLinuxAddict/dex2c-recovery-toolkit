# Contributing

Thanks for helping improve the Dex2C Recovery Toolkit.

## Before you start

- Use only applications you own or are authorized to analyze.
- Do not attach target APKs, proprietary DEX files, recovered third-party code,
  device logs, or personal paths to issues or pull requests.
- For security issues, follow [SECURITY.md](SECURITY.md), not a public issue.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

The default suite must not require a private APK or a device. Put
environment-dependent tests behind explicit environment variables and mark them
`integration` or `slow`.

## Pull requests

1. Keep changes focused and reviewable.
2. Add or update tests for behavior changes.
3. Update documentation and `CHANGELOG.md` for user-visible changes.
4. Do not weaken validation or promote evidence classifications without new
   evidence.
5. Run `python scripts/release_audit.py` before submitting.

## Evidence rules

- Structural validity is not semantic correctness.
- A finite test set is not universal equivalence.
- Exact recovery requires an authoritative reference artifact.
- Keep status, evidence, confidence, and validation separate.
- Rejection and unresolved outcomes are valid, useful results.

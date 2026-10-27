# Installation

## Verified environment

- Linux
- Python 3.10+ (public verification used Python 3.14.8)
- `pip`
- Optional: Java 17+ for smali/baksmali/dexdump; Android SDK; Ghidra; ADB

macOS/Windows are not part of the tested release claim.

## From a clone

```bash
git clone https://github.com/ArchLinuxAddict/dex2c-recovery-toolkit.git
cd dex2c-recovery-toolkit
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
.venv/bin/dex2c-recover --version
.venv/bin/pytest -q
```

Runtime instrumentation extra:

```bash
.venv/bin/pip install -e ".[dev,runtime]"
```

## External tools

The toolkit discovers tools in this order (first match wins):

1. `DEX2C_ADB`, `DEX2C_DEXDUMP`, `DEX2C_AAPT2`, `DEX2C_APKSIGNER`,
   `DEX2C_SMALI_JAR`, `DEX2C_BAKSMALI_JAR`, `DEX2C_GHIDRA_HEADLESS`,
   `DEX2C_NDK`, `DEX2C_JADX`, `DEX2C_APKTOOL_JAR`
2. Android SDK roots from `ANDROID_HOME` / `ANDROID_SDK_ROOT`
3. Repository-local `tools/` paths (development only)
4. `PATH`

You do not need every tool. `analyze` works without Ghidra, smali, or a device.
Missing tools appear in `inventory/environment.json` and in report limitations.

## Verify

```bash
.venv/bin/dex2c-recover --help
.venv/bin/dex2c-recover devices --json
.venv/bin/pytest -q
```

`devices --json` returns an empty selection when no authorized ADB device is
attached; this is not an installation failure.

## Tested dependency baseline

`constraints-tested.txt` records the versions used for the 1.0.0 publication
verification. It is a constraints file, not a fully resolved lockfile.

## Troubleshooting installation

- `ModuleNotFoundError`: activate the same interpreter used for installation,
  or run through `.venv/bin/dex2c-recover`.
- `java: not found`: Java-based optional tools are unavailable; core analysis
  still works.
- Permission errors: choose a writable `--out` directory.

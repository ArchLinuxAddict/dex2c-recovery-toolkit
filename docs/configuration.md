# Configuration

The CLI takes explicit paths; there is no required configuration file.

## Environment variables

| Variable | Purpose |
|---|---|
| `DEX2C_ADB` | Path to `adb` |
| `DEX2C_DEXDUMP` | Path to `dexdump` |
| `DEX2C_AAPT2` | Path to `aapt2` |
| `DEX2C_APKSIGNER` | Path to `apksigner` |
| `DEX2C_SMALI_JAR` | Path to `smali.jar` |
| `DEX2C_BAKSMALI_JAR` | Path to `baksmali.jar` |
| `DEX2C_GHIDRA_HEADLESS` | Path to Ghidra `analyzeHeadless` |
| `DEX2C_NDK` | Android NDK root |
| `DEX2C_JADX` | Path to JADX launcher |
| `DEX2C_APKTOOL_JAR` | Path to `apktool.jar` |
| `ANDROID_HOME` / `ANDROID_SDK_ROOT` | Android SDK root(s) |
| `DEX2C_TEST_APK` | Authorized APK for the gated integration test |
| `DEX2C_RUN_DEVICE_TESTS` | Reserved by the original research suite; not required by the public toolkit |

## Workspace state

`<out>/.state.json` records the input SHA-256 and per-stage status. Stages are
resumed for the same input. `--force` re-runs them. Changing the input hash
starts a separate stage state.

## Runtime policy

- `none`: no device access.
- `auto`: use authorized devices if present; otherwise record a limitation.
- `required`: fail if no authorized device is present.

## Network

The toolkit itself does not require network access. Package installation and
optional tools may require network access depending on your environment.

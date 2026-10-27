# Third-party software and attribution

This repository does not vendor third-party source code, Android APKs, native
libraries, or external tool binaries.

## Python dependencies

Users install these from their own package indexes under the licenses declared
by their upstream projects:

- **androguard** — Android application/DEX analysis.
- **capstone** — disassembly engine.
- **pyelftools** — ELF parsing.
- **lief** — ELF/binary inspection.
- **frida** (optional runtime extra) — authorized runtime instrumentation.
- **pytest** and **ruff** (development only).

## External tools

The toolkit can use external tools when they are installed by the user:

- Android SDK platform tools (`adb`, `dexdump`, `apksigner`, `aapt2`)
- smali/baksmali
- Ghidra
- JADX
- apktool
- Android NDK
- Frida

These tools are not redistributed. Their licenses and redistribution terms are
their own. Environment variables and discovery paths are documented in
`docs/configuration.md`.

## Research attribution

The source-transformation facts in `src/dex2c_recover/source_model.py` summarize
the behavior of the upstream [codehasan/dex2c](https://github.com/codehasan/dex2c)
project at commit `2af11db9af7d813d5bc86c883459c1c3efe0896b`. They are
attributed summaries, not copied source code.

The research companion repository contains sanitized findings about a
Dex2C-protected target. It does not contain target APKs, recovered third-party
code, or embedded payloads.

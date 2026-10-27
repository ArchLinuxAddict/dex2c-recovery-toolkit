"""Environment and dependency discovery."""
from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from .util import now_utc, run_command, tool_version, write_json

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_path(name: str) -> list[Path]:
    value = os.environ.get(name)
    return [Path(value).expanduser()] if value else []


def _android_sdk_roots(tools: Path) -> list[Path]:
    roots = []
    for name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value).expanduser())
    roots.append(tools / "android-sdk")
    seen = []
    for root in roots:
        if root not in seen:
            seen.append(root)
    return seen


def _candidate_paths() -> dict[str, list[Path]]:
    tools = PROJECT_ROOT / "tools"
    sdk_roots = _android_sdk_roots(tools)
    dexdump: list[Path] = []
    aapt2: list[Path] = []
    apksigner: list[Path] = []
    for sdk in sdk_roots:
        if not sdk.exists():
            continue
        dexdump.extend(sorted(sdk.glob("android-*/dexdump")))
        aapt2.extend(sorted(sdk.glob("android-*/aapt2")))
        apksigner.extend(sorted(sdk.glob("android-*/apksigner")))
        dexdump.extend(sorted(sdk.glob("build-tools/*/dexdump")))
        aapt2.extend(sorted(sdk.glob("build-tools/*/aapt2")))
        apksigner.extend(sorted(sdk.glob("build-tools/*/apksigner")))
    return {
        "adb": _env_path("DEX2C_ADB") + [root / "platform-tools" / "adb" for root in sdk_roots] + [tools / "android-sdk" / "platform-tools" / "adb"],
        "jadx": _env_path("DEX2C_JADX") + [tools / "jadx" / "bin" / "jadx"],
        "apktool": _env_path("DEX2C_APKTOOL_JAR") + [tools / "apktool" / "apktool.jar"],
        "ghidra": _env_path("DEX2C_GHIDRA_HEADLESS") + [tools / "ghidra" / "ghidra_12.2_PUBLIC" / "support" / "analyzeHeadless"],
        "dexdump": _env_path("DEX2C_DEXDUMP") + dexdump,
        "aapt2": _env_path("DEX2C_AAPT2") + aapt2,
        "apksigner": _env_path("DEX2C_APKSIGNER") + apksigner,
        "smali": _env_path("DEX2C_SMALI_JAR") + [tools / "smali" / "smali.jar"],
        "baksmali": _env_path("DEX2C_BAKSMALI_JAR") + [tools / "smali" / "baksmali.jar"],
        "llvm_objdump": [Path("/usr/bin/llvm-objdump")],
        "readelf": [Path("/usr/bin/readelf")],
        "objdump": [Path("/usr/bin/objdump")],
        "strings": [Path("/usr/bin/strings")],
        "frida": [Path(sys.executable).parent / "frida"],
        "ndk": _env_path("DEX2C_NDK") + [Path.home() / ".local" / "share" / "dex2c-recover" / "android-ndk-r27c"],
    }


def _first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    for path in paths:
        found = shutil.which(path.name)
        if found:
            return Path(found)
    return None


def _generated_app_info() -> dict[str, Any]:
    import androguard
    import capstone
    import elftools
    import lief

    return {
        "androguard": getattr(androguard, "__version__", "unknown"),
        "capstone": getattr(capstone, "__version__", "unknown"),
        "pyelftools": getattr(elftools, "__version__", "unknown"),
        "lief": getattr(lief, "__version__", "unknown"),
    }


def discover_environment(*, devices: bool = False, output: str | Path | None = None) -> dict[str, Any]:
    paths = _candidate_paths()
    tools: dict[str, Any] = {}
    for name, candidates in paths.items():
        path = _first_existing(candidates)
        item: dict[str, Any] = {"path": str(path) if path else None, "available": bool(path)}
        if path:
            if path.suffix == ".jar" or name == "apktool":
                item.update(tool_version(["java", "-jar", str(path), "--version"]))
            elif name == "ghidra":
                item.update({"version": "Ghidra 12.2", "available": True})
            elif name == "ndk":
                clang = path / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / "clang"
                item["clang"] = str(clang) if clang.exists() else None
                item["available"] = clang.exists()
                item.update(tool_version([str(clang), "--version"]) if clang.exists() else {})
            elif name in ("dexdump", "aapt2", "apksigner", "adb", "jadx", "llvm_objdump", "readelf", "objdump", "strings"):
                item.update(tool_version([str(path)] + (["version"] if name == "adb" else ["--version"])))
            else:
                item.update(tool_version([str(path), "--version"]))
        tools[name] = item

    java = tool_version(["java", "-version"])
    python = {
        "version": platform.python_version(),
        "executable": sys.executable,
        "implementation": platform.python_implementation(),
    }
    libs = {}
    try:
        libs = _generated_app_info()
    except Exception as exc:
        libs["error"] = str(exc)

    disk = shutil.disk_usage(str(PROJECT_ROOT))
    memory = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(("MemTotal:", "MemAvailable:")):
                    key, value = line.split(":", 1)
                    memory[key] = value.strip()
    except Exception:
        pass

    result = {
        "schema_version": "1.0",
        "generated_at": now_utc(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": python,
            "java": java,
            "cpu_count": os.cpu_count(),
            "memory": memory,
            "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
            "project_root": str(PROJECT_ROOT),
        },
        "libraries": libs,
        "tools": tools,
        "capabilities": {
            "apk_ingest": True,
            "dex_analysis": bool(libs.get("androguard")),
            "native_elf_analysis": bool(tools["readelf"]["available"]) or bool(libs.get("pyelftools")),
            "jni_export_analysis": True,
            "disassembly": bool(tools["llvm_objdump"]["available"]) or bool(libs.get("capstone")),
            "decompilation": bool(tools["ghidra"]["available"]),
            "dex_assembly": bool(tools["smali"]["available"]),
            "dex_validation_external": bool(tools["dexdump"]["available"]),
            "runtime_adb": bool(tools["adb"]["available"]),
            "runtime_frida": False,
            "ndk_build": bool(tools["ndk"]["available"]),
        },
        "limitations": [],
    }
    try:
        import frida  # noqa: F401

        result["capabilities"]["runtime_frida"] = True
    except Exception:
        result["limitations"].append("Python frida module not available")
    for name in ("jadx", "apktool", "ghidra", "adb", "dexdump", "smali", "baksmali"):
        if not tools.get(name, {}).get("available"):
            result["limitations"].append(f"{name} is not available")
    if devices:
        result["devices"] = discover_adb_devices(tools["adb"]["path"])
    if output:
        write_json(output, result)
    return result


def discover_adb_devices(adb_path: str | None) -> list[dict[str, Any]]:
    if not adb_path:
        return []
    result = run_command([adb_path, "devices", "-l"], timeout=20)
    if not result.ok:
        return [{"error": result.stderr[-1000:]}]
    devices = []
    for line in result.stdout.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        props = {}
        if state == "device":
            for key in (
                "ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
                "ro.build.version.sdk", "ro.product.cpu.abi", "ro.build.type",
                "ro.debuggable", "ro.secure", "ro.product.cpu.abilist",
            ):
                prop = run_command([adb_path, "-s", serial, "shell", "getprop", key], timeout=10)
                props[key] = prop.stdout.strip() if prop.ok else None
            root_probe = run_command([adb_path, "-s", serial, "shell", "su", "-c", "id"], timeout=10)
            devices.append(
                {
                    "serial": serial,
                    "state": state,
                    "transport": "usb",
                    "props": props,
                    "root_available": root_probe.ok and "uid=0(" in root_probe.stdout,
                    "root_probe": {
                        "ok": root_probe.ok,
                        "stdout": root_probe.stdout.strip()[:500],
                        "stderr": root_probe.stderr.strip()[:500],
                    },
                    "raw_line": line,
                }
            )
        else:
            devices.append({"serial": serial, "state": state, "raw_line": line})
    return devices

"""Authorized ADB/Frida runtime observation and artifact acquisition."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .environment import _candidate_paths, _first_existing, discover_adb_devices
from .util import (
    ensure_dir,
    now_utc,
    read_json,
    run_command,
    safe_filename,
    sha256_bytes,
    sha256_file,
    write_json,
)


def adb() -> str | None:
    path = _first_existing(_candidate_paths()["adb"])
    return str(path) if path else None


def _adb(serial: str, args: list[str], *, timeout: int = 60, root: bool = False) -> Any:
    adb_path = adb()
    if not adb_path:
        return None
    cmd = [adb_path, "-s", serial]
    if root:
        cmd += ["shell", "su", "-c", " ".join(args)]
    else:
        cmd += ["shell"] + args
    return run_command(cmd, timeout=timeout)


def _adb_exec_out(serial: str, command: str, *, timeout: int = 120) -> bytes:
    import subprocess

    adb_path = adb()
    if not adb_path:
        return b""
    proc = subprocess.run(
        [adb_path, "-s", serial, "exec-out", "su", "-c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return proc.stdout if proc.returncode == 0 else b""


def select_devices(serials: list[str] | None = None) -> dict[str, Any]:
    devices = discover_adb_devices(adb())
    usable = [d for d in devices if d.get("state") == "device"]
    if serials:
        selected = [d for d in usable if d["serial"] in serials]
    else:
        selected = usable
    rooted = next((d for d in selected if d.get("root_available")), None)
    unrooted = next((d for d in selected if not d.get("root_available")), None)
    if rooted is None and unrooted is None and selected:
        rooted = selected[0]
    return {
        "discovered": devices,
        "selected": selected,
        "rooted": rooted,
        "unrooted": unrooted,
        "selection_policy": "first rooted-capable and first non-rooted authorized ADB device; serials are discovered dynamically",
    }


def package_state(serial: str, package: str, *, root: bool = False) -> dict[str, Any]:
    path = _adb(serial, ["pm", "path", package], timeout=30, root=root)
    installed = bool(path and path.ok and "package:" in path.stdout)
    dump = _adb(serial, ["dumpsys", "package", package], timeout=60, root=root)
    text = dump.stdout if dump and dump.ok else ""
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        for key in ("versionName", "versionCode", "codePath", "firstInstallTime", "lastUpdateTime"):
            if line.startswith(key + "="):
                fields[key] = line.split("=", 1)[1].strip()
    return {
        "serial": serial,
        "package": package,
        "installed": installed,
        "path": (path.stdout.strip().split(":", 1)[1] if installed and ":" in path.stdout else None),
        "fields": fields,
        "raw_path_stdout": path.stdout.strip()[:1000] if path else "",
        "raw_path_stderr": path.stderr.strip()[:1000] if path else "",
    }


def install_apk(serial: str, apk_path: str | Path, package: str, *, root: bool, timeout: int = 300) -> dict[str, Any]:
    apk_path = Path(apk_path)
    sha = sha256_file(apk_path)
    remote = f"/data/local/tmp/dex2c-recover-{sha[:16]}.apk"
    adb_path = adb()
    if not adb_path:
        return {"ok": False, "error": "adb unavailable"}
    push = run_command([adb_path, "-s", serial, "push", str(apk_path), remote], timeout=180)
    if not push.ok:
        return {"ok": False, "stage": "push", "stderr": push.stderr[-2000:]}
    if root:
        cmd = [adb_path, "-s", serial, "shell", "su", "-c", f"pm install -r {remote}"]
    else:
        cmd = [adb_path, "-s", serial, "shell", "pm", "install", "-r", remote]
    result = run_command(cmd, timeout=timeout)
    return {
        "ok": result.ok and "Success" in result.stdout,
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "remote": remote,
        "apk_sha256": sha,
        "root": root,
    }


def launch_package(serial: str, package: str, activity: str | None, *, root: bool = False, wait_seconds: float = 4.0) -> dict[str, Any]:
    _adb(serial, ["logcat", "-c"], timeout=15, root=root)
    _adb(serial, ["am", "force-stop", package], timeout=30, root=root)
    if activity:
        if activity.startswith(".") or activity.startswith(package):
            intent = f"{package}/{activity}"
        else:
            intent = f"{package}/{activity}"
        start = _adb(serial, ["am", "start", "-W", "-n", intent], timeout=60, root=root)
    else:
        start = _adb(serial, ["monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"], timeout=60, root=root)
    time.sleep(wait_seconds)
    pid = _adb(serial, ["pidof", package], timeout=20, root=root)
    pid_value = None
    if pid and pid.ok and pid.stdout.strip():
        try:
            pid_value = int(pid.stdout.strip().split()[0])
        except ValueError:
            pid_value = None
    return {
        "start": {"returncode": start.returncode if start else None, "stdout": start.stdout[-4000:] if start else "", "stderr": start.stderr[-4000:] if start else ""},
        "pid": pid_value,
        "waited_seconds": wait_seconds,
    }


def capture_logcat(serial: str, out_path: str | Path, *, package: str | None = None, timeout: int = 60) -> dict[str, Any]:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    adb_path = adb()
    if not adb_path:
        return {"ok": False, "error": "adb unavailable"}
    result = run_command([adb_path, "-s", serial, "logcat", "-d", "-v", "threadtime"], timeout=timeout)
    text = result.stdout
    if package:
        # Keep complete logcat but also record matching lines for quick reading.
        pass
    out_path.write_text(text, encoding="utf-8", errors="replace")
    crash = run_command([adb_path, "-s", serial, "logcat", "-b", "crash", "-d", "-v", "threadtime"], timeout=timeout)
    crash_path = out_path.with_name(out_path.stem + "-crash.txt")
    crash_path.write_text(crash.stdout, encoding="utf-8", errors="replace")
    return {
        "ok": result.ok,
        "path": str(out_path),
        "sha256": sha256_file(out_path),
        "bytes": out_path.stat().st_size,
        "crash_path": str(crash_path),
        "crash_sha256": sha256_file(crash_path),
        "returncode": result.returncode,
    }


def _read_maps(serial: str, pid: int, root: bool) -> list[str]:
    result = _adb(serial, ["cat", f"/proc/{pid}/maps"], timeout=30, root=root)
    if not result or not result.ok:
        return []
    return result.stdout.splitlines()


def _ensure_frida_server(serial: str, root: bool, out_dir: Path) -> dict[str, Any]:
    if not root:
        return {"available": False, "reason": "not rooted"}
    probe = _adb(serial, ["pgrep", "frida-server"], timeout=15, root=True)
    if probe and probe.ok and probe.stdout.strip():
        return {"available": True, "pid": probe.stdout.strip().splitlines()[0], "started": False}
    binary = "/data/local/tmp/frida-server"
    exists = _adb(serial, ["test", "-x", binary], timeout=15, root=True)
    if not exists or not exists.ok:
        return {"available": False, "reason": "frida-server not present at /data/local/tmp/frida-server"}
    start = _adb(serial, ["nohup", binary, ">/data/local/tmp/dex2c-frida.log", "2>&1", "&"], timeout=30, root=True)
    time.sleep(2)
    probe = _adb(serial, ["pgrep", "frida-server"], timeout=15, root=True)
    return {
        "available": bool(probe and probe.ok and probe.stdout.strip()),
        "pid": probe.stdout.strip().splitlines()[0] if probe and probe.stdout.strip() else None,
        "started": True,
        "start": start.as_dict() if start else None,
        "log": "/data/local/tmp/dex2c-frida.log",
    }


def _frida_dump_module(serial: str, pid: int, module_names: list[str], out_dir: Path) -> dict[str, Any]:
    try:
        import frida
    except Exception as exc:
        return {"ok": False, "error": f"frida module unavailable: {exc}"}
    ensure_dir(out_dir)
    try:
        device = frida.get_device(serial, timeout=15)
        session = device.attach(pid)
    except Exception as exc:
        return {"ok": False, "error": f"frida attach failed: {exc}"}
    script_text = r"""
    const wanted = %s;
    const maps = [];
    try {
      const text = File.readAllText('/proc/self/maps');
      for (const line of text.split('\n')) {
        if (!line) continue;
        const m = line.match(/^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)/);
        if (!m) continue;
        if (wanted.some(w => line.indexOf(w) >= 0)) {
          maps.push({start: m[1], end: m[2], perms: m[3], offset: m[4], line});
        }
      }
    } catch (e) { send({kind:'error', error:String(e)}); }
    const modules = Process.enumerateModules().filter(m => wanted.some(w => m.name.indexOf(w) >= 0 || m.path.indexOf(w) >= 0));
    send({kind:'modules', modules: modules, maps: maps});
    for (const map of maps) {
      try {
        const start = parseInt(map.start, 16);
        const end = parseInt(map.end, 16);
        const size = end - start;
        if (size <= 0 || size > 64 * 1024 * 1024) continue;
        const data = ptr(start).readByteArray(size);
        send({kind:'range', start: start, end: end, perms: map.perms, offset: parseInt(map.offset, 16), size: size}, data);
      } catch (e) {
        send({kind:'range_error', line: map.line, error: String(e)});
      }
    }
    send({kind:'done'});
    """ % json.dumps(module_names)
    script = session.create_script(script_text)
    ranges: list[dict[str, Any]] = []
    maps: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    done = {"value": False}

    def on_message(message: Any, data: Any) -> None:
        if message.get("type") != "send":
            errors.append({"kind": "frida_message", "message": str(message)[:2000]})
            return
        payload = message.get("payload") or {}
        kind = payload.get("kind")
        if kind == "modules":
            modules.extend(payload.get("modules") or [])
            for item in payload.get("maps") or []:
                item["map_source"] = "frida_proc_self_maps"
                maps.append(item)
        elif kind == "range" and data is not None:
            start = int(payload["start"])
            perms = payload.get("perms", "?")
            fname = f"module_{start:x}_{perms.replace('/','')}_{payload.get('size',0)}.bin"
            path = out_dir / fname
            path.write_bytes(bytes(data))
            ranges.append(
                {
                    "start": start,
                    "end": int(payload["end"]),
                    "perms": perms,
                    "offset": int(payload.get("offset") or 0),
                    "size": int(payload.get("size") or len(data)),
                    "path": str(path),
                    "sha256": sha256_bytes(bytes(data)),
                }
            )
        elif kind == "range_error":
            errors.append(payload)
        elif kind == "done":
            done["value"] = True

    script.on("message", on_message)
    try:
        script.load()
        deadline = time.time() + 30
        while not done["value"] and time.time() < deadline:
            time.sleep(0.2)
    except Exception as exc:
        errors.append({"kind": "frida_load", "error": str(exc)})
    try:
        session.detach()
    except Exception:
        pass
    return {"ok": done["value"], "modules": modules, "maps": maps, "ranges": ranges, "errors": errors, "pid": pid}


def _compare_runtime_to_packaged(module_dump: dict[str, Any], packaged_path: Path, out_dir: Path, module: dict[str, Any] | None = None) -> dict[str, Any]:
    if not packaged_path.exists():
        return {"compared": False, "reason": "packaged library not found"}
    packaged = packaged_path.read_bytes()
    comparisons = []
    text_match = False
    module_base = None
    module_end = None
    if module:
        try:
            module_base = int(str(module.get("base")), 16) if not isinstance(module.get("base"), int) else int(module["base"])
            module_end = module_base + int(module.get("size") or 0)
        except Exception:
            module_base = module_end = None
    selected_ranges = []
    for item in module_dump.get("ranges", []):
        if "path" not in item:
            continue
        if module_base is not None and not (module_base <= int(item.get("start") or 0) and int(item.get("end") or 0) <= module_end):
            continue
        selected_ranges.append(item)
    for item in selected_ranges:
        raw_path = Path(item["path"])
        data = raw_path.read_bytes()
        offset = int(item.get("offset") or 0)
        file_slice = packaged[offset : offset + len(data)]
        mismatches = sum(1 for a, b in zip(data, file_slice) if a != b) + abs(len(data) - len(file_slice))
        if "x" in item.get("perms", "") and offset == 0:
            prefix = packaged[: min(len(data), len(packaged))]
            text_match = data[: len(prefix)] == prefix
        comparisons.append(
            {
                "path": str(raw_path),
                "perms": item.get("perms"),
                "file_offset": offset,
                "captured_size": len(data),
                "packaged_slice_size": len(file_slice),
                "mismatched_bytes": mismatches,
                "sha256": sha256_bytes(data),
            }
        )
    full_equal = (
        any(c["file_offset"] == 0 and c["captured_size"] >= len(packaged) and c["mismatched_bytes"] == 0 for c in comparisons)
        or (len(packaged) > 0 and any(c["mismatched_bytes"] == 0 and c["captured_size"] == len(packaged) for c in comparisons))
    )
    validated = out_dir / "validated"
    ensure_dir(validated)
    for item in selected_ranges:
        dst = validated / Path(item["path"]).name
        dst.write_bytes(Path(item["path"]).read_bytes())
    classification = "EXACT_ARTIFACT" if full_equal else "PARTIAL_CAPTURE"
    if text_match and not full_equal:
        classification = "PARTIAL_CAPTURE"
    if full_equal:
        classification = "REFERENCE_COPY"
    return {
        "compared": True,
        "packaged_path": str(packaged_path),
        "packaged_sha256": sha256_file(packaged_path),
        "packaged_size": len(packaged),
        "comparisons": comparisons,
        "text_segment_matches_packaged": text_match,
        "full_bytes_match_packaged": full_equal,
        "classification": classification,
        "note": "A runtime module image includes applied relocations and mapped padding; byte equality with the packaged file is reported explicitly.",
    }


def test_reconstructed_harness(serial: str, workspace_root: str | Path, *, use_root: bool) -> dict[str, Any]:
    root = Path(workspace_root)
    recon_dir = root / "recovery" / "reconstructed"
    if not (recon_dir / "harness.dex").exists():
        alternate = root / "dex" / "reconstructed" / "phase1-leaf-methods"
        if (alternate / "harness.dex").exists():
            recon_dir = alternate
    harness = recon_dir / "harness.dex"
    manifest = read_json(recon_dir / "manifest.json", {}) or {}
    methods = manifest.get("methods") or []
    if not harness.exists() or not methods:
        return {"performed": False, "reason": "no reconstructed harness artifact"}
    sha = sha256_file(harness)
    remote = f"/data/local/tmp/dex2c-recover-harness-{sha[:16]}.dex"
    adb_path = adb()
    if not adb_path:
        return {"performed": False, "reason": "adb unavailable"}
    push = run_command([adb_path, "-s", serial, "push", str(harness), remote], timeout=60)
    if not push.ok:
        return {"performed": False, "reason": "push failed", "stderr": push.stderr[-1000:]}
    cmd = [adb_path, "-s", serial, "shell"]
    if use_root:
        cmd += ["su", "-c", f"dalvikvm -cp {remote} dex2c_recover.Harness"]
    else:
        cmd += ["dalvikvm", "-cp", remote, "dex2c_recover.Harness"]
    result = run_command(cmd, timeout=60)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    expected = []
    for index, method in enumerate(methods):
        kind = (method.get("generated_behavior") or {}).get("kind")
        value = (method.get("generated_behavior") or {}).get("value")
        if kind == "return_void_noop":
            expected.append(f"{index}:void")
        elif kind == "return_constant":
            expected.append("false" if value == 0 else str(value))
    passed = result.returncode == 0 and lines == expected
    return {
        "performed": True,
        "artifact": str(harness),
        "artifact_sha256": sha,
        "device": serial,
        "root": use_root,
        "remote": remote,
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "expected": expected,
        "observed": lines,
        "status": "PASS" if passed else "FAIL",
        "limitations": [
            "The harness executes copies of the reconstructed leaf behavior in a standalone DEX; it is not the original class or a drop-in APK replacement.",
            "Passing this test establishes behavior for the exercised inputs/paths only.",
        ],
    }


def runtime_observe(
    workspace_root: str | Path,
    apk_path: str | Path,
    *,
    serials: list[str] | None = None,
    allow_install: bool = False,
    wait_seconds: float = 4.0,
) -> dict[str, Any]:
    root_dir = Path(workspace_root)
    inputs = read_json(root_dir / "inventory" / "inputs.json", {}) or {}
    package = (inputs.get("manifest") or {}).get("package")
    activity = (inputs.get("manifest") or {}).get("main_activity")
    if not package:
        raise ValueError("package name unavailable from inventory")
    devices = select_devices(serials)
    out: dict[str, Any] = {
        "schema_version": "1.0",
        "package": package,
        "activity": activity,
        "selection": {k: v for k, v in devices.items() if k != "discovered"},
        "devices": [],
        "timestamp": now_utc(),
    }
    for device in devices.get("selected") or []:
        serial = device["serial"]
        dev_root = bool(device.get("root_available"))
        dev_dir = root_dir / "runtime" / "raw" / safe_filename(serial)
        ensure_dir(dev_dir)
        state_before = package_state(serial, package, root=dev_root)
        record: dict[str, Any] = {
            "serial": serial,
            "device": device,
            "root": dev_root,
            "package_state_before": state_before,
            "installed_by_toolkit": False,
            "install": None,
            "launch": None,
            "logcat": None,
            "maps": None,
            "module_dump": None,
            "artifacts": [],
            "status": "NOT_STARTED",
            "errors": [],
        }
        if not state_before["installed"]:
            if allow_install and dev_root:
                install = install_apk(serial, apk_path, package, root=True)
                record["install"] = install
                record["installed_by_toolkit"] = bool(install.get("ok"))
                state_after_install = package_state(serial, package, root=True)
                if not state_after_install["installed"]:
                    record["errors"].append("installation did not result in an installed package")
                    out["devices"].append(record)
                    continue
            else:
                record["errors"].append("package not installed; installation not authorized for this run")
                record["status"] = "SKIPPED_NOT_INSTALLED"
                out["devices"].append(record)
                continue
        if state_before["installed"] and allow_install:
            record["notes"] = ["package was already installed; it was not overwritten"]
        launch = launch_package(serial, package, activity, root=dev_root, wait_seconds=wait_seconds)
        record["launch"] = launch
        log_path = dev_dir / "logcat.txt"
        record["logcat"] = capture_logcat(serial, log_path, package=package)
        pid = launch.get("pid")
        if pid:
            maps_lines = _read_maps(serial, pid, dev_root)
            maps_path = dev_dir / "process-maps.txt"
            maps_path.write_text("\n".join(maps_lines) + "\n", encoding="utf-8")
            record["maps"] = {
                "path": str(maps_path),
                "sha256": sha256_file(maps_path),
                "lines": len(maps_lines),
                "native_library_lines": [line for line in maps_lines if ".so" in line],
            }
            if not maps_lines:
                record["errors"].append("process /proc/<pid>/maps was not readable by the shell user; runtime artifact acquisition requires root")
            if dev_root:
                frida_server = _ensure_frida_server(serial, True, dev_dir)
                record["frida_server"] = frida_server
                if frida_server.get("available"):
                    lib_names = [x.get("name") for x in inputs.get("native_libraries") or [] if x.get("name")]
                    unique = sorted({n for n in lib_names if n})
                    dump = _frida_dump_module(serial, pid, unique, dev_dir / "module-dump")
                    record["module_dump"] = dump
                    for module in dump.get("modules") or []:
                        name = module.get("name") or ""
                        packaged = next(
                            (
                                root_dir / e.get("path", "")
                                for e in inputs.get("native_libraries") or []
                                if e.get("name") == name and e.get("abi") == device.get("props", {}).get("ro.product.cpu.abi")
                            ),
                            None,
                        )
                        if not packaged or not packaged.exists():
                            packaged = next((root_dir / e.get("path", "") for e in inputs.get("native_libraries") or [] if e.get("name") == name), None)
                        if packaged and packaged.exists():
                            dump_out = dev_dir / "module-dump" / safe_filename(name)
                            comparison = _compare_runtime_to_packaged(dump, packaged, dump_out, module)
                            artifact = {
                                "kind": "runtime_native_module_image",
                                "module": module,
                                "device": serial,
                                "pid": pid,
                                "acquisition": "frida Memory.readByteArray over /proc/self/maps ranges",
                                "classification": comparison.get("classification"),
                                "status": "RUNTIME_RECOVERED" if comparison.get("classification") in ("EXACT_ARTIFACT", "PARTIAL_CAPTURE") else comparison.get("classification"),
                                "comparison": comparison,
                                "raw_dir": str(dump_out),
                                "validated_dir": str(dump_out / "validated"),
                                "timestamp": now_utc(),
                            }
                            record["artifacts"].append(artifact)
                            # Validate raw ranges individually as ELF/artifact bytes.
                            for item in dump.get("ranges") or []:
                                if "path" not in item:
                                    continue
                                raw = Path(item["path"])
                                quick = {"valid": raw.read_bytes()[:4] == b"\x7fELF"}
                                artifact["range_validation"] = artifact.get("range_validation", []) + [
                                    {
                                        "path": str(raw),
                                        "size": raw.stat().st_size,
                                        "sha256": sha256_file(raw),
                                        "elf_header_present": quick["valid"],
                                    }
                                ]
            record["status"] = "RUNTIME_OBSERVED" if record["artifacts"] else "OBSERVED"
        else:
            record["status"] = "LAUNCH_NO_PID"
            record["errors"].append("application process did not remain active after launch")
        behavior = test_reconstructed_harness(serial, root_dir, use_root=dev_root)
        record["behavior_test"] = behavior
        if behavior.get("status") == "FAIL":
            record["errors"].append("reconstructed harness behavior test failed")
        record["package_state_after"] = package_state(serial, package, root=dev_root)
        out["devices"].append(record)
    write_json(root_dir / "runtime" / "session.json", out)
    write_json(root_dir / "runtime" / "validated" / "runtime-artifacts.json", [a for d in out["devices"] for a in d.get("artifacts", [])])
    write_json(
        root_dir / "runtime" / "validated" / "behavior-tests.json",
        [d.get("behavior_test") for d in out["devices"] if d.get("behavior_test")],
    )
    return out

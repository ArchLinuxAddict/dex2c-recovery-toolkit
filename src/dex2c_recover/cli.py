"""Command-line interface for dex2c-recover.

The public CLI exposes the reusable analysis pipeline: static APK analysis,
authorized runtime observation, validation, reporting, and device discovery.
"""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path
from typing import Any

from . import __version__
from .pipeline import Pipeline
from .runtime import select_devices
from .util import eprint, read_json, stable_json


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--apk", required=True, help="Dex2C-protected APK to analyze (required)")
    parser.add_argument("--out", required=True, help="Analysis workspace/output directory")
    parser.add_argument("--force", action="store_true", help="Re-run stages even if completed for this input")
    parser.add_argument("--ghidra", choices=["auto", "on", "off"], default="auto", help="Ghidra decompilation policy")
    parser.add_argument("--abi", action="append", dest="abis", help="Analyze only these native ABIs (repeatable)")
    parser.add_argument("--max-reconstruct", type=int, default=100, help="Maximum supported leaf methods to translate")


def _add_runtime(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime", choices=["none", "auto", "required"], default="auto", help="Runtime observation policy")
    parser.add_argument("--allow-install", action="store_true", help="Install the APK on a rooted device only when the package is absent")
    parser.add_argument("--device", action="append", dest="devices", help="Restrict runtime observation to this ADB serial (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dex2c-recover",
        description="Static and authorized runtime analysis of Dex2C-protected APKs, with evidence-backed recovery and validation",
    )
    parser.add_argument("--version", action="version", version=f"dex2c-recover {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Static standalone analysis and reporting")
    _add_common(analyze)

    all_cmd = sub.add_parser("all", help="Full static analysis plus authorized runtime observation")
    _add_common(all_cmd)
    _add_runtime(all_cmd)

    runtime = sub.add_parser("runtime", help="Observe/acquire runtime evidence from an existing workspace")
    runtime.add_argument("--apk", required=True)
    runtime.add_argument("--out", required=True)
    _add_runtime(runtime)

    validate = sub.add_parser("validate", help="Validate DEX/ELF artifacts in an existing workspace")
    validate.add_argument("--apk", required=True)
    validate.add_argument("--out", required=True)
    validate.add_argument("--force", action="store_true")

    report = sub.add_parser("report", help="Regenerate reports and provenance from an existing workspace")
    report.add_argument("--apk", required=True)
    report.add_argument("--out", required=True)
    report.add_argument("--test-results", help="Optional pytest/JUnit-style JSON to include")

    devices = sub.add_parser("devices", help="Discover connected ADB devices dynamically")
    devices.add_argument("--json", action="store_true", help="Emit JSON")

    return parser


def _print_result(result: dict[str, Any], quiet: bool = False) -> None:
    if quiet:
        return
    print(stable_json(result))


def _validate_apk(path: str) -> Path:
    apk = Path(path)
    if not apk.exists():
        raise ValueError(f"APK path does not exist: {apk}")
    if not apk.is_file():
        raise ValueError(f"APK path is not a regular file: {apk}")
    if not apk.stat().st_size:
        raise ValueError(f"APK file is empty: {apk}")
    try:
        with apk.open("rb") as fh:
            if fh.read(2) != b"PK":
                raise ValueError(f"input is not a ZIP/APK file: {apk}")
        if not zipfile.is_zipfile(apk):
            raise ValueError(f"input ZIP/APK is truncated or invalid: {apk}")
    except PermissionError as exc:
        raise ValueError(f"APK is not readable: {apk}") from exc
    return apk


def _validate_out(path: str) -> Path:
    out = Path(path)
    if out.exists() and not out.is_dir():
        raise ValueError(f"output path exists and is not a directory: {out}")
    return out


def _validate_test_results(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise ValueError(f"test-results file does not exist: {p}")
    return read_json(p, {}) or {}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "devices":
            info = select_devices()
            if args.json:
                print(stable_json(info))
            else:
                for dev in info.get("selected") or []:
                    props = dev.get("props") or {}
                    print(
                        f"{dev.get('serial')} state={dev.get('state')} root={dev.get('root_available')} "
                        f"model={props.get('ro.product.model')} android={props.get('ro.build.version.release')} "
                        f"abi={props.get('ro.product.cpu.abi')}"
                    )
                if not info.get("selected"):
                    print("No authorized ADB devices found.")
            return 0

        apk = _validate_apk(args.apk)
        out = _validate_out(args.out)

        if args.command == "analyze":
            pipeline = Pipeline(
                apk,
                out,
                force=args.force,
                ghidra=args.ghidra,
                runtime="none",
                abis=args.abis,
                max_reconstruct=args.max_reconstruct,
                log=lambda m: eprint(m),
            )
            _print_result(pipeline.run_static(command="analyze"))
            return 0

        if args.command == "all":
            pipeline = Pipeline(
                apk,
                out,
                force=args.force,
                ghidra=args.ghidra,
                runtime=args.runtime,
                allow_install=args.allow_install,
                serials=args.devices,
                abis=args.abis,
                max_reconstruct=args.max_reconstruct,
                log=lambda m: eprint(m),
            )
            if args.runtime == "required":
                selected = select_devices(args.devices)
                if not selected.get("rooted") and not selected.get("unrooted"):
                    raise RuntimeError("runtime=required but no authorized ADB devices were found")
            _print_result(pipeline.run_all(command="all"))
            return 0

        if args.command == "runtime":
            pipeline = Pipeline(
                apk,
                out,
                runtime=args.runtime,
                allow_install=args.allow_install,
                serials=args.devices,
                ghidra="off",
                log=lambda m: eprint(m),
            )
            result = pipeline.stage("runtime", pipeline.stage_runtime, force=True)
            pipeline.stage_report(command="runtime")
            _print_result(result)
            return 0

        if args.command == "validate":
            pipeline = Pipeline(apk, out, force=args.force, ghidra="off", log=lambda m: eprint(m))
            _print_result(pipeline.stage("validation", pipeline.stage_validation))
            return 0

        if args.command == "report":
            test_results = _validate_test_results(args.test_results)
            pipeline = Pipeline(apk, out, ghidra="off", log=lambda m: eprint(m))
            command = "report" + (f" --test-results {args.test_results}" if args.test_results else "")
            _print_result(pipeline.stage_report(command=command, test_results=test_results))
            return 0

        parser.error(f"unsupported command {args.command}")
    except ValueError as exc:
        eprint(f"error: {exc}")
        return 2
    except Exception as exc:
        eprint(f"error: {exc}")
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

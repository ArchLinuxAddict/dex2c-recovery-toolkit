from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from dex2c_recover.elfs import analyze_elf
from dex2c_recover.environment import _candidate_paths, _first_existing
from dex2c_recover.validation import validate_dex


def test_synthetic_dex_assembles_and_validates(tmp_path: Path) -> None:
    smali_jar = _first_existing(_candidate_paths()["smali"])
    if not smali_jar:
        pytest.skip("smali unavailable")
    src = tmp_path / "fixture.smali"
    src.write_text(
        """.class public Ldex2c_recover/Fixture;
.super Ljava/lang/Object;
.method public static answer()I
    .registers 1
    const/16 v0, 42
    return v0
.end method
.method public static noop()V
    .registers 0
    return-void
.end method
""",
        encoding="utf-8",
    )
    dex = tmp_path / "fixture.dex"
    result = subprocess.run(
        ["java", "-jar", str(smali_jar), "assemble", str(src), "-o", str(dex)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    validation = validate_dex(dex, run_external=True)
    assert validation["valid"] is True


@pytest.mark.skipif(shutil.which("gcc") is None, reason="host gcc unavailable")
def test_synthetic_native_elf_exports_and_stripping(tmp_path: Path) -> None:
    src = tmp_path / "fixture.c"
    src.write_text(
        """
#include <jni.h>
JNIEXPORT jint JNICALL Java_demo_Native_add__II(JNIEnv *env, jclass cls, jint a, jint b) {
    (void)env; (void)cls; return a + b;
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved; return 0x00010006;
}
""",
        encoding="utf-8",
    )
    # Minimal JNI declarations avoid depending on Android NDK headers.
    header = tmp_path / "jni.h"
    header.write_text(
        """
typedef void *JNIEnv; typedef void *jclass; typedef void *JavaVM;
typedef int jint;
#define JNIEXPORT __attribute__((visibility("default")))
#define JNICALL
""",
        encoding="utf-8",
    )
    so = tmp_path / "libfixture.so"
    compile_result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-I", str(tmp_path), "-o", str(so), str(src)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    info = analyze_elf(so, abi="x86_64")
    assert info["valid"]
    assert info["jni_onload"]["name"] == "JNI_OnLoad"
    names = {x["name"] for x in info["jni_exports"]}
    assert "Java_demo_Native_add__II" in names
    assert info["stripped"] is False
    stripped = tmp_path / "libfixture-stripped.so"
    shutil.copy2(so, stripped)
    subprocess.run(["strip", str(stripped)], check=True, timeout=60)
    stripped_info = analyze_elf(stripped, abi="x86_64")
    assert stripped_info["stripped"] is True
    assert "Java_demo_Native_add__II" in {x["name"] for x in stripped_info["jni_exports"]}

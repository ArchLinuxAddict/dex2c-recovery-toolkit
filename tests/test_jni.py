from __future__ import annotations

from dex2c_recover.jni import (
    JNIENV_FUNCTIONS,
    jni_long_name,
    jni_short_name,
    jnienv_name_for_index,
    jnienv_name_for_offset,
    mangle_for_jni,
    method_class_params,
    normalize_descriptor,
)


def test_mangle_exact_dex2c_rules() -> None:
    assert mangle_for_jni("com/example/Foo") == "com_example_Foo"
    assert mangle_for_jni("a_b") == "a_1b"
    assert mangle_for_jni("Lx;") == "Lx_2"
    assert mangle_for_jni("[I") == "_3I"
    assert mangle_for_jni("ü") == "_000fc"


def test_jni_long_name_omits_return_type() -> None:
    name = jni_long_name(
        "Ln3/g;",
        "hidden",
        "(Landroid/content/pm/PackageManager;Ljava/lang/String;I)Ljava/lang/Object;",
    )
    assert name == "Java_n3_g_hidden__Landroid_content_pm_PackageManager_2Ljava_lang_String_2I"
    assert jni_short_name("Ln3/g;", "hidden") == "Java_n3_g_hidden"


def test_descriptor_helpers() -> None:
    ret, params = method_class_params("(IJ[Ljava/lang/String;)V")
    assert ret == "V"
    assert params == ["I", "J", "[Ljava/lang/String;"]
    assert normalize_descriptor("(I J)V") == "(IJ)V"


def test_jni_env_offsets_match_native_disassembly() -> None:
    # ARM64/libstub generated code uses [env, #0xc8] for NewLocalRef,
    # [env, #0x30] for FindClass, and [env, #0x6b8] for RegisterNatives.
    assert jnienv_name_for_index(6) == "FindClass"
    assert jnienv_name_for_offset(0x30) == "FindClass"
    assert jnienv_name_for_index(25) == "NewLocalRef"
    assert jnienv_name_for_offset(0xC8) == "NewLocalRef"
    assert jnienv_name_for_index(215) == "RegisterNatives"
    assert jnienv_name_for_offset(215 * 8) == "RegisterNatives"
    assert jnienv_name_for_offset(228 * 8) == "ExceptionCheck"
    assert len(JNIENV_FUNCTIONS) >= 229

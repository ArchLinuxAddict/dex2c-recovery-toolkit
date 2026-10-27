"""JNI naming and JNIEnv function-table helpers."""
from __future__ import annotations

import re

# JNIEnv function table order (JNINativeInterface).  Indices are actual table
# indices; the first four entries are reserved.  Parsed from OpenJDK jni.h and
# cross-checked against the Android NDK header.  Android functions after the
# classic set are intentionally omitted because their ABI-specific offsets are
# only useful when the table is known to include them.
JNIENV_FUNCTIONS: list[str] = [
    "reserved0", "reserved1", "reserved2", "reserved3",
    "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod",
    "FromReflectedField", "ToReflectedMethod", "GetSuperclass",
    "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew",
    "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError",
    "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef",
    "DeleteLocalRef", "IsSameObject", "NewLocalRef", "EnsureLocalCapacity",
    "AllocObject", "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass",
    "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV",
    "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV",
    "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV",
    "CallByteMethodA", "CallCharMethod", "CallCharMethodV", "CallCharMethodA",
    "CallShortMethod", "CallShortMethodV", "CallShortMethodA", "CallIntMethod",
    "CallIntMethodV", "CallIntMethodA", "CallLongMethod", "CallLongMethodV",
    "CallLongMethodA", "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA",
    "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA",
    "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA",
    "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV",
    "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod",
    "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA",
    "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV",
    "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod",
    "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV",
    "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod",
    "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV",
    "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod",
    "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV",
    "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod",
    "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA",
    "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField",
    "GetCharField", "GetShortField", "GetIntField", "GetLongField",
    "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField",
    "SetByteField", "SetCharField", "SetShortField", "SetIntField",
    "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID",
    "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA",
    "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA",
    "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA",
    "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA",
    "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA",
    "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA",
    "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA",
    "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA",
    "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA",
    "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA",
    "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField",
    "GetStaticByteField", "GetStaticCharField", "GetStaticShortField",
    "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField",
    "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField",
    "SetStaticByteField", "SetStaticCharField", "SetStaticShortField",
    "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField",
    "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars",
    "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength",
    "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength",
    "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
    "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray",
    "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray",
    "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements",
    "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements",
    "GetFloatArrayElements", "GetDoubleArrayElements",
    "ReleaseBooleanArrayElements", "ReleaseByteArrayElements",
    "ReleaseCharArrayElements", "ReleaseShortArrayElements",
    "ReleaseIntArrayElements", "ReleaseLongArrayElements",
    "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements",
    "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion",
    "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion",
    "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion",
    "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion",
    "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion",
    "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives",
    "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion",
    "GetStringUTFRegion", "GetPrimitiveArrayCritical",
    "ReleasePrimitiveArrayCritical", "GetStringCritical",
    "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef",
    "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress",
    "GetDirectBufferCapacity", "GetObjectRefType",
]


def jnienv_name_for_index(index: int) -> str | None:
    if 0 <= index < len(JNIENV_FUNCTIONS):
        return JNIENV_FUNCTIONS[index]
    return None


def jnienv_name_for_offset(offset: int, pointer_size: int = 8) -> str | None:
    if pointer_size <= 0 or offset < 0 or offset % pointer_size:
        return None
    return jnienv_name_for_index(offset // pointer_size)


def mangle_for_jni(value: str) -> str:
    """Exact Dex2C/ART-style JNI mangling."""
    out: list[str] = []
    for ch in value:
        if ("A" <= ch <= "Z") or ("a" <= ch <= "z") or ("0" <= ch <= "9"):
            out.append(ch)
        elif ch in (".", "/"):
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        else:
            out.append("_0%04x" % ord(ch))
    return "".join(out)


def normalize_descriptor(descriptor: str) -> str:
    return re.sub(r"\s+", "", descriptor or "")


def split_descriptor(descriptor: str) -> tuple[str, str]:
    descriptor = normalize_descriptor(descriptor)
    if not descriptor.startswith("(") or ")" not in descriptor:
        return "", descriptor
    index = descriptor.index(")")
    return descriptor[1:index], descriptor[index + 1 :]


def jni_short_name(class_descriptor: str, method_name: str) -> str:
    cls = class_descriptor
    if cls.startswith("L") and cls.endswith(";"):
        cls = cls[1:-1]
    return "Java_" + mangle_for_jni(cls) + "_" + mangle_for_jni(method_name)


def jni_long_name(class_descriptor: str, method_name: str, descriptor: str) -> str:
    params, _ = split_descriptor(descriptor)
    return jni_short_name(class_descriptor, method_name) + "__" + mangle_for_jni(params)


def is_jni_export(name: str) -> bool:
    return name.startswith("Java_") or name == "JNI_OnLoad"


def possible_export_names(class_descriptor: str, method_name: str, descriptor: str) -> list[str]:
    return [
        jni_long_name(class_descriptor, method_name, descriptor),
        jni_short_name(class_descriptor, method_name),
    ]


def parse_long_export(name: str) -> dict[str, str] | None:
    """Best-effort structural parse; class/method split is ambiguous.

    The authoritative mapping in this toolkit is computed by generating the
    expected mangled name from every DEX method.  This parser is only used for
    diagnostics and registration-table evidence.
    """
    if not name.startswith("Java_") or "__" not in name:
        return None
    left, params = name.split("__", 1)
    left = left[len("Java_") :]
    return {"symbol": name, "class_and_method": left, "mangled_params": params}


def export_name_from_signature(class_descriptor: str, method_name: str, descriptor: str, *, long: bool = True) -> str:
    return jni_long_name(class_descriptor, method_name, descriptor) if long else jni_short_name(
        class_descriptor, method_name
    )


def jni_type_for_descriptor(descriptor: str) -> str:
    descriptor = normalize_descriptor(descriptor)
    if descriptor in ("V", "Z", "B", "S", "C", "I", "J", "F", "D"):
        return {
            "V": "void", "Z": "jboolean", "B": "jbyte", "S": "jshort",
            "C": "jchar", "I": "jint", "J": "jlong", "F": "jfloat", "D": "jdouble",
        }[descriptor]
    if descriptor == "Ljava/lang/String;":
        return "jstring"
    if descriptor.startswith("["):
        return "jarray"
    return "jobject"


def method_class_params(descriptor: str) -> tuple[str, list[str]]:
    params, ret = split_descriptor(descriptor)
    out: list[str] = []
    i = 0
    while i < len(params):
        start = i
        while params[i] == "[":
            i += 1
        if params[i] == "L":
            end = params.index(";", i)
            i = end + 1
        else:
            i += 1
        out.append(params[start:i])
    return ret, out


def call_args_for_method(descriptor: str, *, instance: bool) -> int:
    _, params = method_class_params(descriptor)
    count = 1 if instance else 0
    for item in params:
        count += 2 if item in ("J", "D") else 1
    return count

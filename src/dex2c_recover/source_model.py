"""Source-confirmed Dex2C transformation model.

Facts in this module are summaries of the upstream Dex2C implementation and
are attributed to the recorded repository revision.  No upstream source code
is copied into this toolkit.
"""

SOURCE_REVISION = {
    "repository": "https://github.com/codehasan/dex2c",
    "commit": "2af11db9af7d813d5bc86c883459c1c3efe0896b",
    "commit_date": "2026-02-10T04:12:05+05:30",
    "commit_subject": "Refactor: Work in temp directory instead of modifying project/ directly",
    "inspected_at": "2026-10-26",
}

SOURCE_CONFIRMED_FACTS = [
    {
        "topic": "selection",
        "fact": "Methods are selected by filter rules: plain rules are whitelists, '!' rules are keep/blacklists, '=' rules require a full method-name match; annotated classes/methods are also selected.",
        "source": "dcc.py MethodFilter filter/annotation handling",
    },
    {
        "topic": "exclusions",
        "fact": "Constructors are not excluded in general, but <clinit>, native methods, conflicting overloads with identical parameter lists and differing return types, and methods named like an existing native method are not transformed.",
        "source": "dcc.py MethodFilter.should_compile",
    },
    {
        "topic": "dex_representation",
        "fact": "Each selected method gains the native access flag and its Dalvik code body is removed; the class, fields, access flags (apart from native), descriptor, and prototype remain.",
        "source": "dcc.py native_class_methods; loader/DccApplication.smali",
    },
    {
        "topic": "native_generation",
        "fact": "Each selected method becomes a C++ JNI function with the ART long JNI name Java_<mangled-class>_<mangled-method>__<mangled-parameters>, compiled into the configured native module (default libstub.so).",
        "source": "dex2c/writer.py; dex2c/util.py",
    },
    {
        "topic": "registration",
        "fact": "By default generated functions are exported as JNI symbols. Dynamic registration emits JNINativeMethod arrays and calls RegisterNatives from JNI_OnLoad.",
        "source": "dcc.py dynamic registration; project/jni/nc/Dex2C.cpp",
    },
    {
        "topic": "loader",
        "fact": "The default loader class contains a <clinit> that calls System.loadLibrary(\"stub\") and native <init>/initDcc methods.",
        "source": "loader/DccApplication.smali; dcc.py",
    },
    {
        "topic": "runtime_helpers",
        "fact": "Generated functions use shared C++ helpers for class/method/field resolution, casts, exceptions, bit conversions, and JNIEnv function-table calls.",
        "source": "project/jni/nc/Dex2C.h; Dex2C.cpp",
    },
    {
        "topic": "parameters_returns",
        "fact": "Java parameters and returns use JNI types; wide Dalvik parameters occupy two register words; instance JNI functions receive JNIEnv* and the receiver jobject.",
        "source": "dex2c/writer.py; dex2c/util.py",
    },
    {
        "topic": "objects_fields_methods",
        "fact": "Field/method/class identities are resolved through d2c_resolve_* helpers and cached; object, array, string, cast, and call operations lower to JNIEnv calls.",
        "source": "dex2c/writer.py; dex2c/opcode_ins.py",
    },
    {
        "topic": "limitations",
        "fact": "Compilation failures are caught per method and reported; unsupported instruction/type combinations are skipped rather than represented.",
        "source": "dcc.py compile_dex",
    },
    {
        "topic": "artifacts_remaining",
        "fact": "After protection the APK contains modified DEX files with native declarations (no code for transformed methods), the loader class, and generated native libraries per selected ABI.",
        "source": "dcc.py dcc_main",
    },
]

# Target-specific observations are intentionally not part of the public toolkit.
OBSERVED_APK_FACTS: list[str] = []

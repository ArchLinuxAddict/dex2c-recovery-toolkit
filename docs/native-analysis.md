# Native/JNI analysis

## ELF inventory

For each native library the toolkit records:

- ABI, architecture, ENDIAN, ELF type, stripped state
- SONAME and imported libraries
- `JNI_OnLoad` and exported `Java_*` symbols
- `JNINativeMethod` registration tables
- `RegisterNatives` call sites
- strings relevant to classes/methods/loaders

## JNI name mapping

Dex2C static-export mode uses the ART long name:

```text
Java_<mangled-class>_<mangled-method>__<mangled-parameters>
```

The return type is not part of the long name. `_`, `;`, `[`, and non-ASCII
characters are escaped. Dynamic registration is correlated through
`JNINativeMethod` arrays and class/member strings.

## Discovery vs mapping

Discovery identifies likely transformed methods from multiple independent
signals. Mapping connects a candidate to an implementation. A native
declaration alone is not proof of Dex2C transformation; pre-existing native
methods and loader infrastructure are classified separately.

## Confidence

Mappings retain confidence and alternatives. Ambiguous dynamic registrations
remain `AMBIGUOUS` rather than being promoted to confirmed mappings.

## Function analysis

Mapped functions record instruction counts, JNIEnv table calls, call edges,
control-flow blocks, and disassembly provenance. Ghidra pseudocode is optional
and is not treated as source.

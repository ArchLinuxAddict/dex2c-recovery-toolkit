# Limitations

## Evidence classes

- **Exact recovery** — an artifact is genuinely present and independently
  validated against an authoritative supplied reference. The public toolkit
  labels such artifacts as supplied-artifact recovery, not original source.
- **Behavioral reconstruction** — generated Dalvik represents selected observed
  or inferred behavior. It is not the original instruction sequence.
- **Partial reconstruction** — only some behavior/operations are represented.
- **Native-only analysis** — native implementation details are analyzed without
  a complete translated DEX.
- **Unresolved** — insufficient evidence for a defensible translation.

## What cannot be concluded

- A valid DEX does not prove semantic correctness.
- A passing finite test does not prove universal equivalence.
- A mapped JNI function does not reveal original register allocation, debug
  metadata, exception tables, or exact instruction ordering.
- Ghidra pseudocode is not original source.
- A method count does not measure recovery quality.

## Technical limitations

- Only a small side-effect-free leaf subset is translated.
- Dynamic registration, stripped libraries, and ambiguous overloads can block
  mapping.
- Embedded artifacts are inventoried but not treated as authoritative original
  code.
- Runtime observation is optional and device-dependent; unrooted devices expose
  less evidence.
- External tools vary by version and availability.
- The public release does not include target-specific Phase IV–VII campaign
  drivers; those findings are sanitized in the companion lab.

## Research result context

The companion lab records one specific campaign's findings (103 behavioral,
8 partial, 225 native-only, 0 exact at final closure). Those are findings from
that target and evidence set, not universal toolkit capabilities.

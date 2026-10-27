# Validation

## Structural DEX validation

`validate_dex` checks:

- DEX magic and version
- header/file size
- Adler-32 checksum
- SHA-1 signature
- header size and endian tag
- string/type/proto/method/class table bounds
- data section bounds
- instruction decoding
- optional external dexdump/baksmali disassembly

A structurally valid DEX is not labeled behaviorally equivalent.

## ELF validation

`validate_elf` checks ELF magic/class/endianness, section/program bounds,
architecture guess, and external `readelf`/`objdump` availability.

## Workspace validation

`validate_workspace` validates all supplied DEX/ELF artifacts and recovered
artifacts, then writes `validation/dex.jsonl`, `validation/elf.jsonl`, and
`validation/summary.json`.

## Runtime comparison

Optional runtime observation can capture authorized process evidence. A
finite comparison establishes behavior only for tested inputs. It is not proof
of universal equivalence.

## Evidence discipline

| Check | Establishes |
|---|---|
| DEX parses | structural validity |
| External disassembler accepts DEX | structural validity |
| Generated method runs on a fixture | behavior for that fixture |
| Native-vs-generated comparison | behavior for tested inputs |
| Same SHA-256 | artifact identity, not semantic correctness |
| Original artifact present | exact supplied-artifact recovery, if independently validated |

# SPEC-022 - Bounded SH parser-candidate dataflow

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 013
- Related questions: RQ-033, RQ-036, RQ-037, RQ-038

## Purpose

This specification defines the evidence required to distinguish an on-media
format constant from a coincidental constant in firmware code. It records the
corrected result for the former `0x220` candidate without claiming the complete
function or component owner.

## Bounded block rule

A block may be selected only when:

- all seed references are exact PC-relative SH literal loads;
- a nearby documented save/prologue sequence exists;
- the end is bounded by the first referenced literal-pool address;
- no execution or unconstrained recursive disassembly is used;
- unknown instructions remain explicit.

For the registered CD1/CD3 pair, the selected block is 212 bytes and all 106
aligned instructions decode under the supported Renesas encodings. Raw block
hash and normalized call topology are identical across releases.

## Register-slice contract

The backward slice supports only:

- PC-relative longword loads;
- register-to-register moves;
- signed immediate moves and additions;
- documented call clobber boundaries;
- an SH delayed-call argument instruction.

Unsupported writes terminate a slice. Branch merging is not guessed.

## Corrected `0x220` result

| Evidence | Result |
|---|---|
| literal destination | `r4` |
| shared call | `JSR @r10` |
| pointer argument | `r5`, fixed base + `0x1A` |
| alternative at same pointer | `0x204` |
| post-call status | `r0` immediately tested |
| additive use of `0x220` | not found |
| pointer use of `0x220` | not found |
| FLDB stride 36 in block | not found |
| sector size 2,048 in block | not found |
| FLDB marker in block | not found |

Classification:

`DISPROVED_FOR_SESSION012_REFERENCE_PAIR`

This classification rejects only the identified pair as an FLDB-directory
offset consumer. It does not reject the existence of a different parser.

## Publication contract

Public reports may contain file-relative offsets, relative pointer deltas,
instruction counts, normalized hashes, fixed numeric format constants and
confidence states. They must not contain firmware bytes, instruction bytes,
absolute memory-mapped addresses, raw strings, local paths or extracted data.

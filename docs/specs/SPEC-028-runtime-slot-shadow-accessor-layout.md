# SPEC-028 - Runtime-slot and shadow-accessor layout

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 018-019
- Related questions: RQ-046, RQ-050, RQ-051, RQ-053, RQ-054, RQ-055

## Purpose

Define how Phoenix may expand a confirmed zero-tail record run, correlate its
active call targets with direct entries in another release and search for a
static writer without converting structural evidence into runtime semantics.

## Tail-slot census

Each of the five Session 018 records contains one in-image pointer and three
zero 32-bit words. All 15 zero-tail words are tested as file-relative targets.
A word is active under the narrow Session 019 model only when at least one
adjacent PC-relative `MOV.L`/same-register `JSR` candidate selects its runtime
address.

The CD1 instance has three active and 12 inactive words:

| Record / tail word | Exact words | PC-relative loads | Adjacent calls |
|---|---:|---:|---:|
| 1 / 1 | 286 | 287 | 286 |
| 2 / 0 | 302 | 303 | 286 |
| 4 / 1 | 209 | 341 | 337 |

Zero on-disk contents are not decoded as instructions.

## Cross-version shadow-member rule

For each active CD1 slot, Phoenix indexes the fixed 16-word normalized
call-site signatures against all CD3 adjacent literal calls. A dominant CD3
target is then evaluated in the Session 018 reverse direction, preserving the
existing 90% consensus and 32-unique-context promotion gate.

The linked Session 017 accessor provides one structural translation anchor.
For a selected CD3 target, the candidate CD1 static body is:

```text
left_candidate = left_anchor + (right_target - right_anchor)
```

Body identity requires the complete bounded target body, through its first
return and delay slot, to be byte-identical at the translated CD1 offset. The
body bytes are never published; only width, hash, occurrence count and offset
relationships may be reported.

## Session 019 instance

The three active slots select three entries in one compact CD3 cluster. The
translated CD1 offsets contain byte-identical bodies of 16, 22 and 40 bytes.
None of the three translated CD1 targets has a direct adjacent literal call.

| Member | Reverse consensus | Status | Slot-to-CD1-body delta |
|---|---:|---|---:|
| 0 | 266 / 288 (92.3611%) | CONFIRMED bounded mapping | -368 |
| 1 | 8 / 305 (2.6230%) | structural candidate | -360 |
| 2 | 302 / 342 (88.3041%) | PROBABLE, below fixed gate | -352 |

The equal cross-version relative positions and exact body identity confirm a
static shadow cluster. Only the first slot-to-direct-member mapping passes the
fixed call-family promotion gate.

## Branch-feasibility probe

For each selected slot, Phoenix tests whether a signed 12-bit SuperH branch
from the slot could reach the translated CD1 body and whether a branch plus
delay slot fits before the record end. All three arithmetic probes pass.

This is feasibility evidence only. The on-disk words are zero, no instruction
encoding is reported, and no branch veneer or trampoline is asserted.

## Direct-writer gate

The writer census seeds bounded linear traces from:

- PC-relative long loads under runtime-base, METAINFO-flash and raw-file models;
- file-relative `MOVA` addresses.

It follows register copies and constant add/sub operations for at most 64
instructions, recognizes direct/displaced/pre-decrement stores and stops at
calls, branches or returns. It does not model GBR, memory-loaded bases,
helper-mediated copies or branch dominance.

The CD1 census evaluated 235,864 syntactic address seeds and found zero stores
whose computed destination lies inside the five-record run. This is
`NOT_FOUND_UNDER_BOUNDED_PC_RELATIVE_ADDRESS_MODEL`, not proof that no runtime
writer exists.

## Exact source/destination-pair gate

The five pointer targets and three active slots are tested as exact encoded
words under runtime, raw and METAINFO-flash destination models within a fixed
32-byte neighborhood. No candidate pair exists. Encoded relocation tables,
section-relative records, loader metadata and runtime-created structures remain
outside this model.

## Semantics boundary

The following status is allowed:

`HYPOTHESIS_STRENGTHENED_BY_SHADOW_LAYOUT`

It means that runtime patch, overlay or linkage behavior explains more
evidence than in Session 018. It does not name a mechanism. Promotion requires
an independently identified writer/loader chain or a controlled runtime
observation.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, aggregate counts,
context thresholds, body hashes/widths, address-model names and evidence
statuses. They must not contain firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

# SPEC-021 - Firmware parser constant contract

- Version: 0.2
- Maturity: DRAFT
- Evidence: Sessions 012-013
- Related questions: RQ-026, RQ-029, RQ-033, RQ-034

## Purpose

This specification defines how exact constants from the confirmed FLDB layout
are searched in big-endian SH-3 code without inferring unsupported function
semantics.

## Scan model

The scanner visits every aligned 16-bit instruction once. For a documented
PC-relative `MOV.L`, it computes the literal-pool address and accepts a candidate
only when the complete 32-bit big-endian value equals one of:

| Constant ID | Value | Media meaning | Firmware result |
|---|---:|---|---|
| `fldb-directory-offset` | `0x220` | fixed FLDB table offset | DISPROVED for traced pair |
| `fldb-record-size` | 36 | fixed FLDB record width | BOUNDED AMBIGUOUS |
| `logical-sector-size` | 2,048 | ISO logical block/payload alignment | BOUNDED AMBIGUOUS |

`MOV.W` and signed-immediate counts are retained as bounded diagnostics. They do
not promote a relation because small constants are common and SH immediates are
signed.

## Cross-version pairing and correction

Windows are paired only when their relocation-normalized decoded instruction
shape hashes match. For `0x220`, two window pairs have known-instruction ratios
above 0.5 and both references share one literal-pool word in each release.

Session 012 correctly established structural pairing and classified numeric
coupling as probable. Session 013 decoded the entire bounded body and showed
that `0x220` is passed in `r4` as an expected value while `r5` points to a fixed
memory-mapped location. `0x204` is passed to the same call at the same pointer.
The pair is therefore not an FLDB offset consumer.

Current status: `DISPROVED_FOR_SESSION012_REFERENCE_PAIR`.

The actual parser remains unidentified; no conclusion is made about unrelated
code elsewhere in the image.

## Required promotion evidence

Parser status may become confirmed only after a bounded, reproducible chain
establishes at least:

1. input buffer origin or optical-read result;
2. accesses consistent with the FLDB header offsets;
3. directory stepping or bounds consistent with 36-byte records;
4. control flow that rejects or consumes the validated structure;
5. equivalent evidence in both firmware releases or a justified version delta.

Until then the parser edge is `NOT_CONFIRMED`, the sector ABI is `OPEN`, and
dynamic compatibility is `NOT_ESTABLISHED`.

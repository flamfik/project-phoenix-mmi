# SPEC-019 - Navigation payload family structures

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 012
- Related questions: RQ-022, RQ-029, RQ-030, RQ-031, RQ-035

## Scope

This specification defines publication-safe structural invariants observed at
the beginning of all 3,599 FLDB payloads. It does not define routing,
coordinates, geography, compression or runtime ownership.

## Family classification

Each record is assigned a generated suffix class by the private FLDB name
field. A candidate family header is accepted only when its fixed signature
occurs at offset zero and family-specific length or directory invariants pass.
All registered records pass the offset-zero signature test.

No registered payload starts with ELF, gzip, SQLite 3, xz or ZIP under the
tested fixed signatures.

## Big-endian B/V directory

The shared header is followed by:

| Offset | Width | Field | Status |
|---:|---:|---|---|
| `0x10` | 4 | directory length, big-endian | CONFIRMED |
| `0x14` | 1 | reserved/padding | CONFIRMED zero |
| `0x15` | 1 | directory version | CONFIRMED value 1 |
| `0x16` | 2 | record count, big-endian | CONFIRMED |
| `0x18` | variable | fixed-width records | CONFIRMED |

B records are 16 bytes; V records are 12 bytes. The common validated prefix is:

| Record offset | Width | Field | Status |
|---:|---:|---|---|
| `0x00` | 4 | tag/type-like value | CONFIRMED STRUCTURE, semantics open |
| `0x04` | 4 | payload-relative offset | CONFIRMED |
| `0x08` | 4 | range size | CONFIRMED |
| `0x0C` | 4 | B-only auxiliary value | CONFIRMED PRESENCE, semantics open |

Validation requires the exact directory-length formula, non-zero count,
monotonic offsets, non-overlapping in-bounds ranges and first data at or after
the table end.

## Other length/header models

- ORT/PLZ/POI/RAS classes: big-endian field at `0x10` equals payload size minus
  20 in all 49 instances.
- XAH class: big-endian header span at `0x10` is 140 bytes.
- GDB class: big-endian header span at `0x04` is 32 bytes.
- XB1C/XB7 classes: masked update header and big-endian total-size field at
  `0x04`, matching all four payloads.

The names are format IDs only; their semantic expansion is not asserted.

## Speech index/data split

All eight SM5 payloads declare text-index and binary-data sizes whose sum equals
the enclosing payload size. Numeric rows in the text index describe only
in-bounds ranges into the declared binary-data area. Raw text, tokens and binary
data are private and excluded from reports.

## Publication contract

Reports may contain family IDs, counts, sizes, offsets, strides, invariant
statuses, entropy and hashes of analytical outputs. They must not contain source
bytes, names, raw headers, metadata strings, timestamps, opaque values, local
paths or extracted resources.

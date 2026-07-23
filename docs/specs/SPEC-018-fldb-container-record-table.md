# SPEC-018 - FLDB container and fixed record table

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 011
- Related questions: RQ-022, RQ-029, RQ-030, RQ-031

## Scope

This specification defines the confirmed outer FLDB header and record-table
layout found in the registered Session 011 artifact. Names and payload bytes are
not publication material. Inner payload grammars and firmware consumers are
outside the confirmed scope.

## Header

All integers are little-endian.

| Offset | Width | Field | Status |
|---:|---:|---|---|
| `0x00` | 4 | directory offset | CONFIRMED |
| `0x04` | 4 | variant | CONFIRMED STRUCTURE, semantics open |
| `0x08` | 4 | Unix timestamp | CONFIRMED |
| `0x0C` | 4 | entry count | CONFIRMED |
| `0x10` | 4 | record size | CONFIRMED |
| `0x14` | 4 | `FLDB` magic | CONFIRMED |

For all seven registered containers:

- directory offset is `0x220`;
- record size is 36 bytes;
- the table fits inside the outer member.

## Directory record

| Offset | Width | Field | Status |
|---:|---:|---|---|
| `0x00` | 4 | payload offset | CONFIRMED |
| `0x04` | 4 | payload size | CONFIRMED |
| `0x08` | 24 | NUL-padded ASCII internal name | CONFIRMED STRUCTURE, private |
| `0x20` | 4 | opaque field | CONFIRMED PRESENCE, semantics open |

## Validation invariants

A candidate is structurally confirmed only if:

- header and complete directory table are in bounds;
- record width equals 36 bytes;
- every name field is non-empty printable ASCII with NUL padding;
- every payload range is in bounds;
- every payload offset is 2,048-byte aligned;
- physical payload ranges do not overlap;
- the first payload begins at the next sector boundary after the table;
- aggregate padding is non-negative.

A raw `FLDB` occurrence alone is not sufficient.

## Registered-artifact aggregate

- containers: 7;
- records: 3,599;
- inner payload bytes: 2,567,005,806;
- overlapping ranges: 0;
- duplicate case-folded names: 0;
- dominant suffix class: `suffix-xac`, 3,462 records.

Suffix-family profiles are `PROBABLE_FROM_SUFFIX_FAMILY`, never confirmed
payload semantics.

## Opaque field

CRC32/IEEE and Adler-32 did not match the four-byte field on the bounded,
deterministic first/middle/last sample where payload size permitted reading.
This is a bounded negative for two algorithms only. Endianness, seeded CRCs,
hash truncation, offsets, type IDs and table-level integrity remain open.

## Publication contract

Public output may contain:

- generated member IDs;
- offsets, sizes, counts and structural status;
- suffix classes;
- computed hashes and entropy aggregates;
- fixed public marker IDs and counts.

It must not contain:

- outer or internal names;
- payload or firmware bytes;
- raw metadata strings;
- raw opaque-field values;
- local paths;
- extracted database resources.

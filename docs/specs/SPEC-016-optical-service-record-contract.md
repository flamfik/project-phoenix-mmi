# SPEC-016 - Optical-service record contract

- Version: 0.1
- Maturity: ALPHA
- Evidence: Sessions 009 and 010
- Related questions: RQ-022, RQ-023, RQ-026, RQ-027

## Purpose

This specification describes stable CD-ROM service/event and route-data record
neighborhoods without claiming a decoded class layout or an optical map format.

## Relocation-normalized neighborhood

For each fixed anchor, Phoenix SDK reads `0x80` bytes on each side. Every
four-byte-aligned big-endian value inside the confirmed runtime-linked image
range is replaced by the fixed token `PTR!` before hashing. The report records
the raw-window hash, normalized hash, entropy and pointer count, but no bytes or
runtime pointer values.

Cross-release equality requires equal normalized hashes at the same anchor
ordinal. It demonstrates a stable record neighborhood whose in-image addresses
were relocated; it does not prove a vtable, RTTI record or class descriptor.

## Current inventory

Both releases expose the same 13 focused anchors:

| Category | Anchors |
|---|---:|
| Navigation data | 1 |
| Optical service | 9 |
| Route data | 3 |

Nine of 13 neighborhoods are identical after runtime-pointer normalization.
This includes both route-data records and five optical-service neighborhoods.
Four optical neighborhoods have the same pointer counts but changed non-pointer
content, so the contract is stable but not byte-uniform across all records.

Status: `CONFIRMED_CROSS_VERSION_RELOCATED_RUNTIME_ADDRESS_NEIGHBORHOODS`.

## Explicitly unresolved

- exact record/class field schema;
- event dispatcher and queue topology;
- sector or logical-block request ABI;
- route-data consumer;
- link from the route-data records to CD-ROM services;
- map-media filesystem and database schema.

The future map ISO may validate the medium side of this contract. It must not
be used to retroactively promote a firmware edge unless the consumer or dispatch
path is also demonstrated.

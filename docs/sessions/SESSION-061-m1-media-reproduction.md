# Session 061 - M1 media and inventory reproduction

- Date: 2026-07-29
- Objective: independently reproduce the registered three-disc identity and
  Session 001 aggregate inventory.
- Mode: read-only ISO 9660 traversal; no member extraction or execution.
- Status: COMPLETE, REPRODUCED.

## Result

All three images match the registered byte size and SHA-256 identity. Their
primary volume identifiers, 2,048-byte logical block size and Session 001
aggregate counts reproduce exactly:

| Disc | Files | Directories | Payload bytes |
|---|---:|---:|---:|
| CD1 | 215 | 332 | 148,185,748 |
| CD2 | 93 | 199 | 95,351,480 |
| CD3 | 285 | 437 | 192,171,275 |
| Total | 593 | 968 | 435,708,503 |

The extension census also reproduces: 375 BIN, 154 HEX, 45 LOD, 10 YIM,
6 SW and 3 METAINFO/TXT members.

## M1 consequence

The foundational media and inventory claim is no longer only historical.
Another researcher can replay it from the registered artifacts with one
read-only command.

## Deliverables

- SPEC-069;
- RQ-221-RQ-224;
- `m1-media-reproduction.public.json`;
- operational graph v53.

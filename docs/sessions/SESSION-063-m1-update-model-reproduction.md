# Session 063 - M1 update-model reproduction

- Date: 2026-07-29
- Objective: reproduce METAINFO topology, payload resolution and the staged
  CD1-to-CD3 EEPROM dependency.
- Mode: read-only descriptor parsing and registered-media correlation.
- Status: COMPLETE.

## Result

The three descriptors reproduce 706 sections, 59 device-family declarations,
589 payload records, 40 links and 15 option records. Every payload record
resolves by declared name and size within the registered three-disc set.

Primary ISO 9660 directory names use Level 1 aliases in part of CD1 and CD3.
Resolution therefore preserves two explicit paths: exact declared name and
deterministic 8.3 alias plus declared size.

| Disc descriptor | Records | Local payloads | Payloads on another disc |
|---|---:|---:|---:|
| CD1 | 213 | 189 | 24 |
| CD2 | 92 | 92 | 0 |
| CD3 | 284 | 284 | 0 |

The 24 CD1 declarations absent from CD1 resolve on CD3. This confirms a
cross-disc package dependency directly from descriptor-to-media evidence.
Separately, the CD1 EEPROM target version/CRC pair exactly intersects the CD3
source pair, reproducing the staged migration chain.

## Boundaries

The result does not identify `MetafileChecksum`, prove every update-policy
branch or authorize replaying the update. It documents the package topology
needed by M1.

## Deliverables

- SPEC-071;
- RQ-230-RQ-234;
- `m1-update-model-reproduction.public.json`;
- operational graph v55.

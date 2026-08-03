# Session 057 - LOD shifted-grid reuse

- Date: 2026-07-29
- Objective: verify that the Session 048 shared-content result is not an
  artifact of one block size or grid origin.
- Mode: read-only exact-content comparison; hashes remain private.
- Status: COMPLETE, CONFIRMED.

## Method

Block sizes 128, 256, 512 and 1,024 were tested at four fixed origins: zero,
one quarter, one half and three quarters of the block width.

## Result

All twenty grids retain content shared by all five LOD sources:

| Block size | Shared-all range across origins |
|---:|---:|
| 128 | 69-70 |
| 256 | 34-36 |
| 512 | 14-16 |
| 1024 | 6-7 |

Exact reuse therefore persists across both scale and origin. This is a content
relationship only; it does not identify records or executable semantics.

## Deliverables

- SPEC-065;
- RQ-207-RQ-209;
- `lod-grid-reuse.public.json`;
- shifted-grid reuse analyzer.

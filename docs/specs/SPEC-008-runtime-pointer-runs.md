# SPEC-008 - Post-cluster runtime pointer runs

- Version: 0.2
- Maturity: ALPHA
- Evidence: Sessions 005-006, registered CD1/CD3 principal images
- Related questions: RQ-003, RQ-013, RQ-015

## Detection model

Phoenix scans each byte alignment for runs of at least three consecutive big-endian 32-bit values in the half-open range `0x0C000000`-`0x0D000000`. This range was selected empirically for the post-cluster region. A matching value is not sufficient to prove pointer semantics.

## Cross-version signature

Both releases contain four runs with the count signature `[21, 9, 3, 36]`.

| Run | CD1 offset | CD3 offset | Offset delta | Value delta mode | Support |
|---:|---:|---:|---:|---:|---:|
| 0 | `0x0000` | `0x0000` | 0 | `0x4F0DC` | 20/21 |
| 1 | `0x080C` | `0x0810` | +4 | `0x4F30C` | 9/9 |
| 2 | `0x0D74` | `0x0D7C` | +8 | `0x4EE14` | 2/3 |
| 3 | `0x13B0` | `0x13C4` | +20 | `0x4E050` | 36/36 |

Offsets are relative to the post-cluster area. The cumulative `0, +4, +8, +20` offset growth shows that the 20-byte release delta is distributed across the region rather than being one leading or trailing insertion.

## Interpretation

Session 006 confirms the bounded mapping `file_offset = value - 0x0C000000`. All 69 entries are four-byte aligned and map inside both principal images; one value maps exactly to the confirmed image entry.

Run 0 contains a confirmed relocated 256-byte block made of 16 consecutive 16-byte records. Twenty table entries, including duplicates, use the dominant `0x4F0DC` release delta and map to byte-identical target records. This confirms pointer/target semantics for that subset.

Runs 1 and 3 map in bounds but have no exact 4/16/64-byte target-window matches across releases. Run 2 contains the confirmed image-entry anchor plus two unresolved targets. Their semantic record types remain `PROBABLE`.

`NOT CONFIRMED`: target owners and the record semantics of runs 1-3 remain unknown. No target maps to the browser-resource island, and address mapping alone cannot distinguish executable code from ordinary data.

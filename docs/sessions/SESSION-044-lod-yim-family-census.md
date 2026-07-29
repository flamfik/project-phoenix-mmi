# Session 044 - LOD/YIM family census

- Date: 2026-07-29
- Objective: establish a content-deduplicated census of the legacy `.LOD`
  and `.YIM` families before attempting any decoder.
- Mode: read-only static analysis of hash-verified update media.
- Status: COMPLETE.

## Numbering note

The repository ends at Session 042. Session 043 was proposed but never
executed or committed. Session 044 therefore records that gap explicitly and
uses Session 042 as its evidence parent; it does not invent retroactive
Session 043 results.

## Corpus

| Family | Members | Member bytes | Unique contents | Unique bytes |
|---|---:|---:|---:|---:|
| LOD | 45 | 105,952,725 | 5 | 11,772,525 |
| YIM | 10 | 247,564 | 5 | 123,782 |
| Total | 55 | 106,200,289 | 10 | 11,896,307 |

Every unique content occurs on both CD1 and CD3. Each LOD language payload is
reused by nine component paths; each YIM screen is reused by two paths.

## Results

### S044-01 - Two format families are confirmed

All five YIM contents have a strict `XIM2` envelope at the same offset. The
five LOD contents have no recognized outer magic and do not satisfy the
validated Intel HEX, Motorola S-record or XIM2 models.

### S044-02 - Extension is a valid first-stage discriminator

No content appears under both extensions. Content deduplication and
cross-disc membership are deterministic.

### S044-03 - No payload was exported

Only ISO member paths, sizes, aggregate entropy/filler ratios and conservative
format classifications enter the public report.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S044-01 | CONFIRMED | The corpus contains five unique LOD and five unique YIM contents. |
| S044-02 | CONFIRMED | YIM has an independently validated XIM2 envelope; LOD remains opaque. |
| S044-03 | CONFIRMED | CD1/CD3 repetitions reduce to ten unique contents. |

## Deliverables

- `legacy_cycle.LegacyPayloadInput`;
- narrow LOD/YIM member filter;
- content-deduplicated census;
- publication-safe report;
- operational graph v36.

## Next step

Session 045 validates every observed YIM length and geometry field without
interpreting the two leading integrity fields.

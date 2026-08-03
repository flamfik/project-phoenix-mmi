# SPEC-013 - Navigation and storage marker bands

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 009
- Related questions: RQ-008, RQ-009, RQ-010, RQ-019, RQ-022

## Purpose

This specification defines how Phoenix SDK turns printable-record evidence into publication-safe, cross-version analytical bands. It does not define a vendor module format.

## Fixed vocabulary

Every marker has a stable identifier and one of two categories: `navigation` or `storage`. The vocabulary is declared in source before an artifact is analyzed. Arbitrary records and surrounding strings are never copied into public reports.

The vocabulary covers navigation/routes/destinations/guidance/map/position/GPS/waypoint/street/POI and CD-ROM/DVD/dosFs/filesystem/mount/sector/volume/directory/TFFS/CBIO/`BLK_DEV`/FAT/`CD001` families.

## Record model

One matched printable record produces:

- file offset;
- decoded length and encoding;
- one or more fixed marker identifiers;
- one or more fixed categories;
- a private equality key used only during local comparison.

The record text and private equality key are absent from public output.

## Cluster model

Records are sorted by file offset. A cluster continues while the next record begins no more than `0x4000` bytes after the previous record. Public candidate clusters require at least three records.

A cluster is evidence of marker proximity only. It is never labeled as an executable segment or module.

## Cross-version band model

A record may participate only when its private equality key is unique in each release. Paired records are sorted by the CD1 offset. A band continues only when:

- both left and right offsets remain monotonic;
- both next-record gaps are at most `0x4000`;
- the band contains at least three pairs.

Band fields include both ranges, pair count, fixed marker/category histograms, relocation-delta range and the count of paired records with bounded code references in both releases.

Structural status is `CONFIRMED_ORDERED_CROSS_VERSION_MARKER_BAND`. Semantic status remains `PROBABLE_*_REGION`.

## Code-coupling model

For each marker-record offset `O`, the scanner searches aligned big-endian words equal to:

```text
0x0C000000 + O
```

Each literal word is inspected for exact PC-relative SH-3 `MOV.L` users within the bounded decoder window. Only exact instruction/literal arithmetic is accepted.

This confirms code coupling to the record. It does not recover indirect calls or prove the whole marker band is executable code.

## Session 009 instance

- CD1: 1,193 matched records, 40 candidate clusters, 63 PC-relative referrers.
- CD3: 1,175 matched records, 43 candidate clusters, 28 PC-relative referrers.
- Comparison: 25 ordered bands, 15 constant-delta bands.
- Navigation subsystem presence: `CONFIRMED_CROSS_VERSION_NAVIGATION_SUBSYSTEM_EVIDENCE`.
- Exact navigation boundary: `PARTIAL_MULTIPLE_RELOCATED_MARKER_BANDS`.

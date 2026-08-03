# Session 033 - Bounded section-reorder descriptor search

- Date: 2026-07-28
- Objective: test whether the two support zones surrounding the Session 032
  section reorder are described by a bilateral static
  `source/destination/length` table.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the declared closed descriptor grammar.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes and the Session 003
principal-image hashes. It extracts only the two principal members into an
operating-system temporary directory and removes them after analysis.

The search is seeded only by `RZ-012` and `RZ-013`, which bound `RB-015`.
Phoenix does not enumerate arbitrary whole-image triples, execute code, patch
firmware, export resources, repack an image or interact with a vehicle.

## Closed search model

Session 033 tests:

- big-endian records of 12 bytes;
- big-endian records of 16 bytes with a closed trailing-flag set;
- all six permutations of `source`, `destination` and `length`;
- raw file, METAINFO flash and confirmed runtime-link address models;
- exact zone starts, ends and lengths;
- zone envelopes derived by fixed alignment to 4, 256 and 4,096 bytes;
- copy lengths from 4 bytes through 4 MiB;
- syntactic in-bounds SuperH `MOV.L` forms resolving to a candidate table.

A candidate can be promoted only when:

1. at least two adjacent records use one record grammar and one address-model
   pair;
2. both support zones contribute a closed seed;
3. source and destination intervals are each non-overlapping;
4. the records cover both complete support zones;
5. the table has a syntactic PC-relative reference form;
6. a CD1/CD3 table pair has equal normalized geometry.

Static geometry would still be only probable descriptor evidence. The
reference census is not a whole-image code gate, and neither it nor the table
geometry proves execution or copy behavior.

## Results

### S033-01 - Exact marker-zone endpoints are not stored under the tested models

Neither release contains an exact encoded start or end of either support zone
under the raw, flash or runtime-link model.

The exact length of `RZ-012` occurs twice in each image. The exact length of
`RZ-013` does not occur. These scalar matches are seeds only and are not
interpreted as descriptors.

### S033-02 - The aligned seed census is reproducible

| Measurement | CD1 | CD3 |
|---|---:|---:|
| Boundary seed variants tested | 28 | 28 |
| Scalar length variants tested | 8 | 8 |
| Seed occurrences | 2,083 | 4,606 |
| Seed variants with at least one occurrence | 23 | 26 |
| Bounded record decode attempts | 223,112 | 393,616 |
| Valid seeded single-record interpretations | 1,750 | 3,896 |

High occurrence counts are expected for aligned scalar lengths such as 4 KiB.
They are retained as a false-positive control and cannot pass without both
zone-coverage and bilateral gates.

### S033-03 - Multi-record shapes exist but none covers both zones

The closed decoder finds:

- 438 multi-record interpretations in CD1;
- 604 multi-record interpretations in CD3;
- zero coherent two-zone candidates in either release;
- zero PC-relative referenced promoted candidates;
- zero bilateral descriptor pairs.

Most interpretations are 12-byte raw-to-raw numeric runs. Their existence does
not establish a table: none simultaneously covers `RZ-012` and `RZ-013` with
non-overlapping source/destination geometry.

Therefore:

```text
coherent_reorder_descriptor_table = CLOSED_BOUNDED_NEGATIVE
exact_section_boundary            = OPEN
loader_transform                  = OPEN
```

This closes only the declared grammar. It does not exclude:

- a different record width or field encoding;
- an indirect or compressed table;
- memory-loaded or computed references;
- metadata outside the principal image;
- ordinary compile/link-time section placement with no runtime relocation
  table at all.

## Interpretation

The Session 032 reorder remains confirmed, but Session 033 finds no evidence
that it is implemented by a simple internal copy/relocation table tied to the
two marker zones.

The least-assumptive current model is that the observed cross-release reorder
may be a link-layout change. A loader transform remains possible but is not
supported by this search.

## Operational graph v26

Graph v26 contains 54 nodes and 66 edges. It adds:

- a confirmed node for the two bounded reorder-zone seeds;
- a bounded-negative node and edge for the tested bilateral descriptor-table
  model.

It does not add a loader, copy or map-media edge.

## Phoenix SDK 0.31 deliverable

Session 033 adds:

- closed zone-boundary and aligned-envelope seed generation;
- three explicit address models;
- 12/16-byte permutation-aware descriptor decoding;
- coherent interval and two-zone coverage gates;
- one-pass syntactic PC-relative reference indexing;
- bilateral normalized-geometry pairing;
- compact candidate histograms and publication-safe reports;
- operational graph v26;
- six new unit tests.

The complete suite contains 152 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S033-01 | CLOSED, BOUNDED NEGATIVE | No exact zone endpoint is encoded under the three tested models. |
| S033-02 | CONFIRMED, REPRODUCIBLE | Fixed aligned seeds and record attempts reproduce for both registered images. |
| S033-03 | CLOSED, BOUNDED NEGATIVE | No multi-record candidate covers both reorder zones; no bilateral table passes. |
| S033-04 | OPEN | Exact section boundaries, link layout and any external or indirect loader metadata remain unresolved. |

## Next step

Session 034 should stop assuming a descriptor grammar. It should build a
bounded maximal byte-identity block map around `RB-015` using fixed-size
content hashes, extend only exact matches and locate transition envelopes on
both sides of the reorder. This can test the compile/link-layout explanation
and narrow exact section boundaries without inventing loader metadata.

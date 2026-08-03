# Session 053 - embedded XIM2 census

- Date: 2026-07-29
- Objective: test whether validated XIM2 resources occur inside the CD1 and
  CD3 principal MMI images.
- Mode: bounded static scan and private RLE validation; no resource export.
- Status: COMPLETE, CONFIRMED.

## Confirmed result

Both main images contain exactly:

- 84 strict XIM2 envelopes;
- 84 unique encoded contents;
- 84 unique decoded contents;
- 15 raster geometries;
- 790,484 decoded bytes in aggregate.

Every accepted record closes its length, reserved-area, geometry and bounded
RLE contracts. Bare `XIM2` byte occurrences that fail these contracts are
rejected.

## Cross-version comparison

The complete validated set is identical by both encoded and decoded content
between MMI 5150 (CD1) and MMI 5570 (CD3). One of the five standalone YIM
contents has an exact encoded and decoded counterpart in each main image, and
the codec set is the same.

This confirms a physical link between external YIM update members and the
embedded display-resource layer. It does not yet identify the loader or
renderer routine.

## Publication boundary

No offsets, bytes, decoded rasters, content hashes or extracted resources are
stored in the repository.

## Deliverables

- SPEC-061;
- RQ-194-RQ-197;
- `embedded-xim2-census.public.json`;
- strict embedded-XIM2 scanner in Phoenix SDK.

# SPEC-048 - registered component provenance

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 007, 017, 030, 032, 033, 038-039
- Related questions: RQ-137-RQ-143

## Purpose

Define a closed audit that tests the fixed Session 038 component only against
independently registered bilateral evidence.

## Input gate

The input must:

- use `phoenix-mmi.run-gap-topology-comparison/v1`;
- reproduce both principal-image hashes;
- retain `STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON`;
- contain exactly one promoted 240-byte target component;
- retain an open exact section boundary;
- load exactly the declared schemas from Sessions 007, 017, 030, 032 and 033;
- reproduce the principal-image hash in every source registry.

## Evidence families

The fixed normalizer accepts:

- Session 007 reference targets, reference-word locations and descriptor
  anchors;
- Session 017 producer/dispatch lineage locations;
- Session 030 literal-pool storage and strict pool-successor code;
- Session 032 direct-link code anchors and relocation support zones;
- Session 033 promoted bilateral reorder descriptors.

An empty registered family remains part of the report. New whole-image
discoveries may not be inserted after viewing a result.

## Interval model

Every evidence item is a bilateral pair of half-open file intervals. Point
evidence is represented as `[offset, offset + 1)`.

For target interval `T` and evidence interval `E`:

```text
intersection(T, E) = true              when the half-open intervals overlap
distance(T, E) = gap between intervals otherwise
```

The bilateral distance is the greater of the CD1 and CD3 distances.

## Frozen classes

```text
both intersect                     BILATERAL_EXACT_INTERSECTION
no bilateral intersection, <= 64  BILATERAL_ADJACENT
distance <= 4096                   BILATERAL_NEAR
distance > 4096                    OUTSIDE_FROZEN_NEIGHBORHOOD
```

RZ-012 is the tested mapping. RZ-013 is evaluated independently as the fixed
negative control.

## Owner gate

A semantic-owner promotion requires:

1. exact bilateral intersection;
2. an explicit owner or dataflow edge already promoted by the source session;
3. support from at least two independent evidence families.

Code-location, literal-pool, support-zone or reorder-bracket evidence without
an explicit edge is structural context only.

## Session 039 result

- nine registered families;
- 81 bilateral structural pairs;
- zero prior explicit owner-edge pairs;
- zero RZ-012 exact intersections;
- zero RZ-012 adjacent pairs within 64 bytes;
- zero RZ-012 near pairs within 4 KiB;
- nearest RZ-012 pair: support zone at 74,281 bytes;
- zero corresponding RZ-013 matches at every frozen class;
- entire CD1 component contained in `RB-015`;
- semantic owner, exact section boundary and loader mechanism: open.

## Interpretation boundary

The bounded negative applies only to the named prior registries. It cannot
exclude:

- encoded or computed references;
- indirect runtime registration;
- metadata outside the principal image;
- unexamined update payloads;
- externally supplied loader/link information;
- ordinary compile/link placement without an internal descriptor.

## Publication contract

Reports may contain hashes, generated IDs, file-relative intervals, family
names, counts, fixed thresholds, distances and evidence statuses.

They must not contain firmware bytes, component bytes, instruction bytes,
mnemonic names, raw strings, pointer values, absolute runtime addresses,
local paths, extracted resources or map payloads.

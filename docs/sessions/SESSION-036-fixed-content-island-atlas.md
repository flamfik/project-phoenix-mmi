# Session 036 - Fixed 4 KiB content-island atlas

- Date: 2026-07-28
- Objective: test whether the unchanged `RB-015` envelope contains multiple
  local content families under the two prior relocation deltas.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the declared fixed 4 KiB two-grid atlas.

## Safety boundary

The runner verifies the registered ISO hashes, principal-image hashes and the
Session 035 bounded-negative input state. It extracts only the two principal
members into an operating-system temporary directory and removes them after
analysis.

The analyzer reads only:

```text
CD1 [7,832,267, 7,979,108)
CD3 under delta +61,136
CD3 under delta -7,488,776
```

No new delta search, whole-image scan, adaptive threshold, instruction
execution, firmware modification, repacking or vehicle operation is
performed.

## Frozen atlas contract

The contract was fixed before inspecting the artifact result:

- primary non-overlapping tiles: 4,096 bytes from the envelope origin;
- control tiles: the same size, shifted by 2,048 bytes;
- terminal partial tile: accepted only when at least 2,048 bytes;
- exact-word support: at least `1/8` of aligned four-byte words;
- byte support: at least `1/16` of bytes and 16 distinct equal values;
- repeated word-difference candidate: at least 16 unequal words, eight
  occurrences and `1/8` share, plus byte support;
- distribution-only morphology: entropy delta at most `0.25` bits and byte
  histogram total variation at most `0.125`.

Distribution similarity is never content identity. Repeated word differences
remain anonymous and are never labeled relocations without independent
evidence.

## Results

### S036-01 - The primary atlas is almost entirely unresolved

The primary grid contains 36 tiles:

| Assignment | Count |
|---|---:|
| `LEFT_FAMILY` | 1 |
| `RIGHT_FAMILY` | 0 |
| `BILATERAL_AMBIGUOUS` | 0 |
| `UNRESOLVED` | 35 |

Thirty-five tiles are 4,096 bytes. The final admitted partial tile is 3,481
bytes and remains unresolved.

```text
primary_topology = ONE_SIDED_FAMILY_SUPPORT
```

### S036-02 - One weak RZ-012 island overlaps between both grids

Primary tile `G0000-T019` covers:

```text
[7,905,995, 7,910,091)
```

Under the `RZ-012` mapping it contains:

- 278 equal bytes of 4,096 (`6.787109%`);
- 53 distinct equal byte values;
- 36 exact four-byte words of 1,024 (`3.515625%`);
- entropy delta `0.00962885`;
- histogram total variation `0.04736328`.

The same tile under `RZ-013` contains only 30 equal bytes and zero exact
four-byte words.

The half-tile grid finds `G0800-T018`:

```text
[7,903,947, 7,908,043)
```

It contains 307 equal bytes and 39 exact words under `RZ-012`, versus 39 bytes
and zero exact words under `RZ-013`.

The two accepted tiles overlap over exactly 2,048 bytes. No other resolved
tile pair exists.

```text
grid_control = REPLICATED_SPARSE_ONE_SIDED_SUPPORT
```

This is reproducible byte-level support for one local `RZ-012` neighborhood.
It does not pass the exact-word gate and does not establish a section.

### S036-03 - Multiple interleaved 4 KiB families are not supported

The control grid contains:

| Assignment | Count |
|---|---:|
| `LEFT_FAMILY` | 1 |
| `RIGHT_FAMILY` | 0 |
| `BILATERAL_AMBIGUOUS` | 0 |
| `UNRESOLVED` | 34 |

Both grids are one-sided, contain zero assignment changes and expose no
`RZ-013` family tile.

```text
multiple_interleaved_family_model = CLOSED_BOUNDED_NEGATIVE
island_atlas = SPARSE_ONE_SIDED_SUPPORT_REPLICATED
```

This closes only the fixed 4 KiB atlas model. Smaller islands, changed code,
indirect relocation and other mappings remain outside the result.

### S036-04 - Distribution similarity is common but non-identifying

Under the `RZ-012` mapping:

- primary: 26 distribution-only tiles and nine divergent tiles;
- shifted: 25 distribution-only tiles and nine divergent tiles.

Every `RZ-013` tile is divergent on both grids.

The distribution-only tiles pass entropy/histogram morphology gates but fail
the byte and exact-word content gates. They are therefore not promoted to
content families.

### S036-05 - No repeated word-difference candidate passes

Both mappings and both grids contain zero tiles satisfying the frozen repeated
word-difference gate.

```text
repeated_word_delta_morphology = NOT_OBSERVED_UNDER_FIXED_MODEL
```

This is a bounded negative for the declared anonymous word-difference model,
not proof that relocation patches do not exist.

### S036-06 - The transition envelope remains unchanged

No new exact or continuous boundary evidence is present:

```text
[7,832,267, 7,979,108)
width = 146,841
exact_section_boundary = OPEN
```

## Operational graph v29

Graph v29 contains 60 nodes and 72 edges. It adds:

- the fixed content-island atlas;
- the sparse one-sided `RZ-012` support;
- the bounded-negative repeated word-difference result;
- no section, loader, runtime or media edge.

## Phoenix SDK 0.34 deliverable

Session 036 adds:

- strict Session 035 input and artifact-hash gates;
- fixed 4 KiB origin and half-tile grids;
- exact-byte, exact-word, entropy and histogram metrics;
- anonymous repeated unequal-word-difference census;
- conservative per-mapping and per-tile classification;
- island/run topology and spatial-overlap control;
- compact publication-safe reports;
- operational graph v29;
- nine new unit tests.

The complete suite contains 176 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S036-01 | CONFIRMED, DESCRIPTIVE | The fixed origin atlas contains 36 bounded tiles. |
| S036-02 | PARTIAL, REPLICATED | One overlapping 2 KiB neighborhood supports `RZ-012` at the byte gate only. |
| S036-03 | CLOSED, BOUNDED NEGATIVE | Multiple interleaved 4 KiB content families are not supported under either grid. |
| S036-04 | CONFIRMED, MORPHOLOGY ONLY | Distribution similarity is frequent under `RZ-012` but is not content identity. |
| S036-05 | CLOSED, BOUNDED NEGATIVE | No tile passes the anonymous repeated word-difference gate. |
| S036-06 | OPEN | The exact section boundary and layout mechanism remain unresolved. |

## Next step

Session 037 should analyze only the 2,048-byte overlap of the two accepted
`RZ-012` tiles. A fixed micro-atlas can map exact-byte runs, exact-word
positions, spacing and bounded SH/data morphology. The goal is to determine
whether the weak support is clustered structure or scattered coincidence,
without widening the envelope or lowering Session 036 gates.

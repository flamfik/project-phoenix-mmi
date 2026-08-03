# Session 042 - distributed near-homolog search

- Date: 2026-07-29
- Objective: test whether another raw or record-normalized payload retains a
  shorter distributed constellation of the Session 038 component.
- Mode: read-only static analysis; firmware and decoded payloads were never
  executed or modified.
- Status: COMPLETE for the fixed distributed model.

## Why this experiment follows Session 041

Sessions 040 and 041 found no complete 25-byte target anchor in either raw or
validated decoded payload bytes. That result does not by itself exclude a
near variant in which every long anchor has at least one changed byte.

Session 042 therefore shortens the seeds while increasing the geometry and
similarity requirements. All thresholds were fixed before the corpus scan.

## Frozen constellation

Each of the five Session 040 anchors contributes:

```text
bytes [0, 12)
bytes [13, 25)
```

The middle byte is omitted, so the two 12-byte subanchors never overlap.

| Metric | Target | Control |
|---|---:|---:|
| Subanchors | 10 | 10 |
| Parent zones | 5 | 5 |
| Distinct patterns | 6 | 10 |
| Pattern overlap between target and control | 0 | 0 |

Every subanchor passes:

```text
length = 12
distinct bytes >= 8
entropy >= 2.75 bits/byte
```

Target entropy ranges from `2.855389` to `3.584963`. Control entropy ranges
from `2.792481` to `3.584963`.

## Candidate and strong gates

A component base becomes a constellation candidate only when:

```text
exact subanchors >= 4
distinct parent zones >= 3
```

The four subanchors contribute at least 48 exact bytes at fixed relative
positions. A strong candidate additionally requires:

```text
best 240-byte similarity >= 0.60
```

against either registered CD1 or CD3 release component.

Per-unit limits are fixed at 4,096 occurrences for each subanchor and 256
constellation candidates. Any exceeded limit makes the result inconclusive.

## Corpus reproduction

The runner independently reproduces both prior corpora before searching.

### Raw domain

| Metric | Count |
|---|---:|
| Eligible members | 590 |
| Principal-image copies excluded | 4 |
| Scanned members | 586 |
| Unique units | 133 |
| Unique unit bytes | 81,647,732 |

### Record-normalized domain

| Metric | Count |
|---|---:|
| Record members | 215 |
| Unique record sources | 27 |
| Unique decoded regions | 3,109 |
| Scannable unique units | 3,012 |
| Scannable unit bytes | 3,566,108 |

All reproduced counts equal the registered Session 040 and Session 041
contracts.

## Results

### S042-01 - The constellation is independent and quality-gated

All 20 target/control subanchors pass the fixed quality gates. Six distinct
target patterns and ten distinct control patterns have zero mutual overlap.
No adaptive threshold or corpus-derived seed is used.

### S042-02 - No target seed occurs in the raw domain

Across 133 raw unique units:

```text
target subanchor occurrences       0
target seeded units                0
target constellation candidates    0
target strong units                0
```

### S042-03 - No target seed occurs in the normalized domain

Across 3,012 checksum-valid decoded units:

```text
target subanchor occurrences       0
target seeded units                0
target constellation candidates    0
target strong units                0
```

### S042-04 - Equal-geometry control is also clean

The control produces zero subanchor occurrences, seeded units, constellation
candidates and strong units in both domains.

### S042-05 - No distributed near-homolog is established

```text
distributed_near_homolog = NOT_FOUND_UNDER_FIXED_DISTRIBUTED_MODEL
cross_payload_owner = OPEN
semantic_owner = OPEN
exact_section_boundary = OPEN
runtime_loader_transform = NOT_OBSERVED
scan saturation events = 0
```

Because no individual 12-byte target subanchor occurs, the candidate,
parent-zone and similarity gates are never reached on actual payload data.

## Interpretation boundary

The bounded negative excludes a raw or validated record-normalized variant
that preserves even one registered 12-byte subanchor. It does not exclude:

- `.LOD` or `.YIM` decoded representations;
- compressed or encrypted content;
- relocation-normalized instructions with changes inside every subanchor;
- split or interleaved data;
- external loader/link material;
- runtime-created data.

## Operational graph v35

Graph v35 contains 69 nodes and 84 edges. It adds the fixed distributed
near-homolog census and one bounded-negative semantic-owner edge. It adds no
loader, runtime, section-owner or media-format edge.

## Phoenix SDK 0.40 deliverable

Session 042 adds:

- deterministic two-subanchor derivation for five parent zones;
- entropy, distinct-pattern and target/control independence gates;
- multi-anchor, multi-parent base voting;
- independent full-component similarity promotion;
- raw and record-normalized domain reproduction;
- separate per-domain evidence summaries;
- saturation guards and publication-safe candidate records;
- operational graph v35;
- eight new synthetic unit tests.

The complete suite contains 233 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S042-01 | CONFIRMED | Ten target and ten control subanchors pass all frozen gates. |
| S042-02 | CLOSED, BOUNDED NEGATIVE | No target subanchor occurs in the raw corpus. |
| S042-03 | CLOSED, BOUNDED NEGATIVE | No target subanchor occurs in validated decoded regions. |
| S042-04 | CLOSED, CONTROLLED NEGATIVE | The equal-geometry control is clean in both domains. |
| S042-05 | OPEN OUTSIDE MODEL | Unsupported and transformed representations remain unresolved. |

## Next step

Session 043 should stop shortening signatures and instead characterize the
ten unsupported `.LOD`/`.YIM` contents. The next decoder must begin with a
formal header/length/integrity census and independent format evidence. No
payload reconstruction should occur until those gates are defined.

# Session 040 - cross-payload homolog search

- Date: 2026-07-29
- Objective: determine whether the Session 038 component has an exact
  geometry homolog in another payload on the three MMI 5570 update discs.
- Mode: read-only static analysis; firmware and payloads were never executed
  or modified.
- Status: COMPLETE for the fixed raw-payload signature model.

## Safety boundary

The runner verifies all three ISO hashes, both principal-image hashes and the
Session 038/039 input contracts. It reads eligible members directly from the
ISO extents. Only the two principal images are extracted into a temporary
private directory for the existing `BinaryReader` hash gate.

No payload, component, signature or extracted-resource bytes are written to
the publication reports.

## Frozen signature

The signature uses all five Session 038 exact runs having length 25 bytes:

| ID | Relative offset | Length | Distinct bytes | Entropy |
|---|---:|---:|---:|---:|
| `SIG-01` | 2 | 25 | 22 | 4.403856 |
| `SIG-02` | 32 | 25 | 14 | 3.452879 |
| `SIG-03` | 104 | 25 | 23 | 4.483856 |
| `SIG-04` | 140 | 25 | 23 | 4.483856 |
| `SIG-05` | 196 | 25 | 22 | 4.403856 |

Every position passes the predeclared quality gate:

```text
distinct bytes >= 8
entropy >= 2.5 bits/byte
```

The five positions contain three distinct byte patterns and cover 125 of the
240 component bytes. A candidate must reproduce all five anchors at exactly
the same relative offsets.

A strong candidate additionally requires at least `75%` full-component byte
similarity to either the CD1 or RZ-012-mapped CD3 component.

## Negative control

The control is the first 240 bytes of the prior Session 038 overlap:

```text
CD1 [7,905,995, 7,906,235)
```

It is non-overlapping with the target. Five control anchors are read at the
same relative offsets and under the same length and quality gates. None of
their patterns equals a target pattern.

This prevents an attractive isolated high-entropy match from being promoted
without equal-geometry discrimination.

## Corpus

The fixed corpus accepts members:

```text
extensions: BIN, HEX, LOD, YIM, SW
minimum size: 240 bytes
discs: CD1, CD2, CD3
```

Corpus totals:

| Metric | Count |
|---|---:|
| Eligible members | 590 |
| Eligible bytes | 435,574,832 |
| Principal-image copies excluded by SHA-256 | 4 |
| Scanned members | 586 |
| Scanned member bytes | 384,285,768 |
| Unique payload contents | 133 |
| Unique payload bytes | 81,647,732 |
| Duplicate-content groups | 102 |

Per disc:

| Disc | Eligible | Principal copies excluded | Scanned |
|---|---:|---:|---:|
| CD1 | 214 | 2 | 212 |
| CD2 | 92 | 0 | 92 |
| CD3 | 284 | 2 | 282 |

Content is deduplicated by complete SHA-256 before signature scanning. Member
multiplicity is retained separately and cannot create false independent
support.

## Results

### S040-01 - Signature and control gates pass

All five target and five control anchors pass length, entropy and distinct-byte
gates. Target/control pattern overlap is zero.

```text
signature_contract = CONFIRMED_FIXED_FIVE_ANCHOR_GEOMETRY
control_contract = CONFIRMED_INDEPENDENT_EQUAL_GEOMETRY
```

### S040-02 - Principal-image copies are excluded

Two byte-identical principal copies occur on CD1 and two on CD3. All four are
excluded by full content SHA-256, not by filename. The target therefore cannot
match itself through a duplicated hardware-index path.

### S040-03 - No target anchor occurs in another unique payload

Across 133 unique non-principal contents:

```text
first target anchor occurrences     0
five-anchor geometry matches        0
strong component matches            0
scan saturation events              0
```

Because even the first 25-byte anchor is absent, no later geometry or
similarity promotion is possible under this model.

### S040-04 - The equal-geometry control is also clean

```text
first control anchor occurrences    0
control geometry matches            0
strong control matches              0
```

The bounded negative is therefore not caused by a control collision or a
limit-exhausted scan.

### S040-05 - No raw cross-payload homolog is established

```text
cross_payload_homolog = NOT_FOUND_UNDER_FIXED_SIGNATURE_MODEL
cross_payload_owner = OPEN
semantic_owner = OPEN
exact_section_boundary = OPEN
runtime_loader_transform = NOT_OBSERVED
```

The result excludes a contiguous raw homolog carrying the five registered
anchors in the declared corpus. It does not exclude encoded, compressed,
transformed, split or non-contiguous forms.

## Operational graph v33

Graph v33 contains 67 nodes and 80 edges. It adds:

- the fixed cross-payload homolog census;
- one bounded-negative edge from that census to the open semantic owner;
- no runtime, loader, section-owner or media-format edge.

## Phoenix SDK 0.38 deliverable

Session 040 adds:

- five-anchor target and equal-geometry control derivation;
- entropy and distinct-pattern gates;
- direct ISO-member corpus filtering;
- principal-image content-identity exclusion;
- SHA-256 content deduplication with member multiplicity;
- exact anchor-geometry and full-component similarity tests;
- fixed saturation guards;
- publication-safe corpus reports;
- operational graph v33;
- ten new unit tests.

The complete suite contains 216 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S040-01 | CONFIRMED | Five target and five control anchors pass the frozen quality and independence gates. |
| S040-02 | CONFIRMED | Four principal-image members are excluded by complete content identity. |
| S040-03 | CLOSED, BOUNDED NEGATIVE | No target first-anchor, geometry or strong match occurs in 133 unique raw payloads. |
| S040-04 | CLOSED, CONTROLLED NEGATIVE | The equal-geometry control has zero hits and the scan never saturates. |
| S040-05 | OPEN OUTSIDE MODEL | Encoded or transformed homologs and semantic ownership remain unresolved. |

## Next step

Session 041 should test format-normalized payloads. `HEX`, `LOD` and related
members may encode flash bytes rather than store them contiguously in their
disc representation. Each decoder must first validate record syntax,
addresses, lengths and checksums; only then may the same frozen target/control
signature be searched in reconstructed address-order data. Decoded bytes must
remain private.

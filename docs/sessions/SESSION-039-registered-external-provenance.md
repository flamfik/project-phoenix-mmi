# Session 039 - registered external provenance

- Date: 2026-07-28
- Objective: test whether an independently registered reference, descriptor
  or relocation family identifies the owner of the Session 038 component.
- Mode: read-only static audit of prior evidence; firmware was never executed
  or modified.
- Status: COMPLETE for the frozen registered-family model.

## Safety boundary

The runner verifies both ISO hashes, both principal-image hashes, the complete
Session 038 component contract and every input-report schema and artifact
hash. It does not search firmware for a new pointer, descriptor, string,
instruction, marker, checksum or byte pattern.

Only already published bilateral evidence from Sessions 007, 017, 030, 032
and 033 is normalized. No firmware or resource bytes are published.

## Frozen contract

The target remains the single Session 038 component:

```text
CD1 [7,906,542, 7,906,782)      240 bytes
```

The paired CD3 intervals are derived only from the prior fixed deltas:

```text
RZ-012: [7,967,678, 7,967,918)
RZ-013: [  417,766,   418,006)  negative control
```

Distance classes were fixed before the artifact run:

- exact: both registered intervals intersect the paired component;
- adjacent: maximum bilateral distance at most 64 bytes;
- near: maximum bilateral distance at most 4,096 bytes;
- outside: anything farther away.

Semantic-owner promotion requires exact bilateral intersections from two
independent families already carrying explicit owner/dataflow edges. A
support-zone, bracket, literal-pool or code-location coincidence alone cannot
assign ownership.

## Registered evidence

The normalizer produced 81 bilateral pairs:

| Family | Pairs |
|---|---:|
| Session 007 reference targets | 13 |
| Session 007 reference-word locations | 3 |
| Session 007 descriptor anchors | 1 |
| Session 017 descriptor-producer lineage | 8 |
| Session 030 literal-pool storage | 4 |
| Session 030 pool-successor code | 2 |
| Session 032 direct-link code anchors | 27 |
| Session 032 relocation support zones | 23 |
| Session 033 reorder descriptors | 0 |

None of the 81 pairs had an explicit semantic owner edge promoted by its
source session. Structural pairs were retained because exact intersection
would still provide useful component provenance.

## Results

### S039-01 - Session 038 component replays exactly

Both principal-image hashes, the stable-skeleton classification, component
ID, start, end and 240-byte span pass the input gate.

```text
component_contract = REPLAYED_SESSION038_STABLE_SKELETON
```

### S039-02 - The component is inside the reorder bracket only

The entire CD1 interval lies inside the registered `RB-015` bracket:

```text
[7,832,261, 8,015,784)
```

This establishes file-layout context, not continuous mapping or ownership.

```text
reorder_bracket_context =
  CONFIRMED_REORDER_BRACKET_CONTEXT_ONLY
```

### S039-03 - No RZ-012 registered pair reaches the component

Across all 81 pairs:

```text
bilateral exact       0
bilateral <= 64 B     0
bilateral <= 4 KiB    0
```

The nearest registered pair is the `RZ-012` support-zone interval. Its
bilateral distance is 74,281 bytes. It is a constant-delta marker band and
therefore contextual even if it were closer.

```text
registered_external_provenance =
  NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES
```

### S039-04 - RZ-013 remains a clean negative control

The control also has zero exact, adjacent and near pairs. Its nearest
registered interval is the `RZ-013` support zone, 109,002 bytes away.

```text
negative_control_owner_edge = NOT_FOUND
```

The result does not depend on choosing whichever prior relocation family is
closest.

### S039-05 - Semantic ownership remains open

There is no exact registered structural intersection and no previously
promoted owner edge. The correct conclusion is:

```text
registered_owner_edge = NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES
semantic_owner = OPEN
exact_section_boundary = OPEN
runtime_loader_transform = NOT_OBSERVED
```

This is a bounded negative over a named, reproducible registry. It does not
prove that the component is unreferenced: encoded, computed, external,
unregistered and runtime-created references are outside the model.

## Operational graph v32

Graph v32 contains 66 nodes and 78 edges. It adds:

- the frozen registered-provenance audit;
- an explicit open semantic-owner node;
- one bounded-negative provenance-to-owner edge;
- no media, runtime, loader or section-owner edge.

## Phoenix SDK 0.37 deliverable

Session 039 adds:

- strict schema and cross-report hash gates;
- normalization of nine prior evidence families;
- half-open bilateral interval distance analysis;
- fixed exact, 64-byte and 4-KiB proximity classes;
- independent-owner-family promotion policy;
- RZ-013 negative-control evaluation;
- publication-safe reports;
- operational graph v32;
- ten new unit tests.

The complete suite contains 206 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S039-01 | CONFIRMED | The Session 038 target and artifact identity replay exactly. |
| S039-02 | CONFIRMED, CONTEXT ONLY | The component is fully inside `RB-015`; no continuous mapping or owner follows. |
| S039-03 | CLOSED, BOUNDED NEGATIVE | None of 81 registered pairs is exact, adjacent or within 4 KiB under RZ-012. |
| S039-04 | CLOSED, CONTROLLED NEGATIVE | RZ-013 also has no registered provenance edge. |
| S039-05 | OPEN | Semantic owner, exact section boundary and loader mechanism remain unresolved. |

## Next step

The prior-registry audit is complete and the 2 KiB region must not be split
again without independent evidence. A later session should seek genuinely
new provenance outside the principal-image microanalysis, for example an
independently registered homolog in another update payload or external
link/loader material. Any such search must use fixed minimum signature
lengths and an unrelated-payload negative control before inspecting results.

# Session 032 - Relocation-anchor breakpoints

- Date: 2026-07-27
- Objective: build a sparse whole-image relocation support model from prior
  confirmed code/data anchors and re-evaluate the Session 031 pool pairs
  without widening its local search.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the declared Session 005/008/009/015/030/031 evidence.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes and the Session 003
principal-image hashes. It extracts only the two principal members into a
temporary directory and removes them after analysis.

Session 032 accepts only:

- direct-link bilateral code anchors confirmed by Session 015;
- the byte-identical resource and bitmap regions from Sessions 005 and 008;
- constant-delta ordered marker bands confirmed by Session 009;
- the complete literal pools and generated pair identities from Sessions 030
  and 031.

No global arbitrary code search, adaptive threshold, unobserved-gap
interpolation, firmware execution, resource publication, repacking or vehicle
operation was performed.

## Evidence gates

### Direct-link code anchor

Every prior anchor is decoded again in both principal images with the original
384-byte bounded-code policy. Both releases must pass independently.

Equal normalized shape is recorded but is not required: a direct runtime
pointer and bilateral code gates establish two exact file targets without
proving runtime equivalence.

### Exact data region

Both declared regions must reproduce:

- their prior offsets and lengths;
- identical raw bytes across CD1/CD3;
- the previously published SHA-256.

Only these two regions support continuous byte mapping.

### Code plateau

A local code plateau requires:

- at least two distinct direct-link anchors;
- one identical relocation delta;
- no intervening different-delta direct anchor;
- at most 65,536 bytes between adjacent anchors.

Mapping is confirmed at the anchor points only. Bytes between them are not
interpolated.

### Breakpoint bracket

Two non-overlapping support zones with different deltas bound a change. The
exact breakpoint is not asserted. A decrease in right-side order creates a
section-reorder bracket rather than a monotonic change bracket.

## Confirmed findings

### S032-01 - Direct-link code anchors form 15 delta families

All 27 prior code pairs pass revalidation in both releases:

- 27 direct-link bilateral code anchors;
- 15 distinct relocation deltas;
- three pairs with equal normalized instruction shape;
- six local equal-delta code plateaus.

| Plateau | Delta | Anchors | Left span | Maximum anchor gap |
|---|---:|---:|---:|---:|
| CP-001 | -13,128 | 2 | 308 | 308 |
| CP-002 | 322,920 | 3 | 1,024 | 584 |
| CP-003 | 322,516 | 2 | 44 | 44 |
| CP-004 | 323,060 | 2 | 28 | 28 |
| CP-005 | 325,100 | 5 | 836 | 468 |
| CP-006 | 325,104 | 4 | 588 | 320 |

The nearby `325100` and `325104` plateaus prove that even a four-byte delta
change must be retained; they are not merged.

### S032-02 - Two exact data intervals reproduce byte-for-byte

| Region | Source | Length | Relocation delta | Status |
|---|---:|---:|---:|---|
| DR-001 | Session 005 core bundle | 15,260 | -326,412 | byte-identical |
| DR-002 | Session 008 bitmap region | 71,245 | 323,804 | byte-identical |

Together they cover 86,505 confirmed continuously mapped bytes.

### S032-03 - Marker bands add independent layout support

Fifteen constant-delta marker bands contain 405 paired markers. Three
cross-class agreements occur inside the fixed 131,072-byte proximity gate:

- two `-13128` marker bands agree with the two-anchor CP-001 code plateau;
- one `323396` marker band agrees with one direct-link code anchor.

These agreements support the deltas across independent evidence classes, but
do not fill the gaps between marker and code offsets.

### S032-04 - The sparse model contains 23 zones and 19 brackets

The combined evidence yields:

- 23 support zones;
- 18 monotonic delta-change brackets;
- one section-reorder bracket.

The reorder is bounded in CD1 between file offsets `7,832,261` and `8,015,784`
(width 183,523 bytes). The corresponding CD3 support moves backward from the
late-image region to the early-image region. This is direct structural evidence
that CD1/CD3 are not related by one monotonic insertion/deletion map.

The exact reorder boundary and loader mechanism remain open.

### S032-05 - Pool delta equality does not establish target identity

None of the eight unique Session 031 link pairs:

- exactly matches a prior direct-link code anchor;
- falls inside either exact data interval at equal relative offset;
- is covered by a confirmed marker band;
- lies inside an equal-delta code plateau suitable even for provisional
  interpolation.

Two pairs, LP-001 and LP-004, share delta `323440` with direct anchor CA-016.
Their underlying target identities differ, so their status is:

```text
DELTA_FAMILY_ONLY_NOT_IDENTITY
```

The remaining six have no prior anchor coverage.

Therefore:

```text
whole_image_relocation_support_model =
  CONFIRMED_AT_DECLARED_ANCHORS_AND_REGIONS

continuous_universal_file_map = NOT_ESTABLISHED
original_handoff_callee = OPEN
```

## Operational graph v25

Graph v25 contains 52 nodes and 64 edges:

- 42 confirmed nodes;
- four probable nodes;
- three open nodes;
- nine bounded-negative edges;
- one disproved edge.

It adds the revalidated direct-link anchor registry, relocation support zones
and pool reconciliation. No new edge is drawn from a pool delta to the original
handoff registration path.

## Phoenix SDK 0.30 deliverable

Session 032 adds:

- prior-evidence schema gates and raw revalidation;
- direct-link code-anchor registry;
- exact data interval verification;
- code plateau and cross-class support builders;
- monotonic and section-reorder breakpoint brackets;
- exact identity versus delta-only pool reconciliation;
- operational graph v25;
- a hash-gated runner and six new unit tests.

The complete suite contains 146 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S032-01 | CONFIRMED, BILATERAL CODE | All 27 prior direct-link code pairs revalidate and form 15 delta families. |
| S032-02 | CONFIRMED, BYTE-EXACT | Two regions reproduce 86,505 identical mapped bytes. |
| S032-03 | CONFIRMED, CROSS-CLASS STRUCTURAL | Three marker/code agreements independently support two deltas. |
| S032-04 | CONFIRMED, BOUNDED STRUCTURAL | Twenty-three zones bound 18 monotonic changes and one section reorder. |
| S032-05 | CLOSED, BOUNDED NEGATIVE | Zero pool pairs match an exact prior anchor; two share only a delta family. |
| S032-06 | OPEN | Continuous mapping, exact section boundaries, loader transform and original handoff callee remain unresolved. |

## Next step

Session 033 should investigate the section-reorder bracket first. A bounded
search for copy/relocation descriptors must be seeded by the two support zones
on either side of that bracket and must require multiple records with coherent
source, destination and length geometry. If no descriptor table passes, the
result should remain bounded negative rather than expanding to arbitrary
whole-image tuples.

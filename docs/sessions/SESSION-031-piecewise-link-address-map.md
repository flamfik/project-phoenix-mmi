# Session 031 - Piecewise link-address/file-layout map

- Date: 2026-07-27
- Objective: classify the values stored in the two Session 030 literal pools
  and test whether bounded, cross-release code anchors establish any piece of
  a link-address/file-layout map.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the ten registered pool entries.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes and the Session 003
principal-image hashes. It extracts only the two principal members into a
temporary directory and removes them after analysis.

The search is restricted to:

- the two literal-pool pairs confirmed by Session 030;
- equal word ordinals and equal use roles across CD1/CD3;
- indirect-control literals for code-anchor testing;
- one correction variable in the fixed range `-2048..+2048` bytes, step two;
- an independently fixed structural relocation delta;
- a 128-byte decoded window at each strict candidate.

No global entry search, adaptive radius increase, firmware execution,
resource extraction, repacking or vehicle operation was performed.

Raw pointer values and absolute runtime addresses remain private. Public
reports contain generated pair IDs, aggregate deltas, file-relative candidate
offsets, structural hashes and counts only.

## Mapping model

Session 030 fixes the pool-layout relocation:

```text
structural_delta = 322532 bytes
```

For one paired literal value:

```text
link_delta = right_link_offset - left_link_offset
relative_file_correction = structural_delta - link_delta

left_file  = left_link_offset  + common_correction
right_file = right_link_offset + common_correction
             + relative_file_correction
```

Only `common_correction` is searched. Every candidate therefore preserves the
confirmed CD1/CD3 file-layout delta instead of scanning both images
independently.

A candidate is a bilateral code anchor only when:

1. both offsets pass the strict exact-entry gate;
2. both bounded windows pass the code gate;
3. both windows are fully decoded;
4. their normalized instruction shapes are equal.

A relocation family needs at least two distinct link pairs with one common
correction before it can become a confirmed map piece. Repeated occurrences of
the same pair do not count as independent anchors.

## Confirmed findings

### S031-01 - The pools contain five relocation families

The ten pool-entry occurrences reduce to eight unique CD1/CD3 link pairs. All
link offsets fall inside their respective principal image, but they do not
share one cross-release relocation delta.

| Family | Link delta | Relative file correction | Occurrences | Unique pairs | Role |
|---|---:|---:|---:|---:|---|
| LF-001 | -7,487,820 | 7,810,352 | 1 | 1 | indirect control |
| LF-002 | -326,212 | 648,744 | 1 | 1 | argument |
| LF-003 | 322,528 | 4 | 1 | 1 | indirect control |
| LF-004 | 323,440 | -908 | 4 | 2 | indirect control |
| LF-005 | 324,492 | -1,960 | 3 | 3 | indirect control |

This closes a single cross-release link-delta model for the tested pools. It
does not disprove that each release uses a loader- or section-dependent
runtime map.

### S031-02 - Bounded strict entries do not become bilateral anchors

Seven unique indirect-control pairs were eligible. Across 14,343 fixed
correction candidates:

- 68 candidate pairs passed the strict exact-entry gate in both releases;
- zero also passed the complete bilateral code-anchor gate;
- no relocation family obtained a selected common correction.

The argument-only LF-002 family was retained in the delta atlas but was not
searched as code.

Status:

```text
cross_release_link_delta_atlas = CONFIRMED
piecewise_link_to_file_map = NOT_ESTABLISHED
actual_runtime_callee = OPEN
```

### S031-03 - The simple constant-correction model is bounded negative

The most populated families, LF-004 and LF-005, provide two and three
independent pairs respectively. Even these families have zero equal
fully-decoded code shapes inside the declared correction range.

Therefore no constant correction may be promoted for the tested pools. The
result is bounded to:

- the seven indirect-control pairs;
- the structural-delta-preserving equation above;
- the fixed `±2048`-byte range;
- strict SuperH entry/code shapes.

It does not exclude section tables, relocation records, loader-created
addresses, encoded descriptors, wider non-local transforms or runtime patching.

## Operational graph v24

Graph v24 contains 49 nodes and 60 edges:

- 40 confirmed nodes;
- four probable nodes;
- two open nodes;
- nine bounded-negative edges;
- one disproved edge.

It adds a confirmed structural link-delta atlas and a separate unestablished
piecewise file-map node. The edge from that map toward runtime owner ingress
remains open.

## Phoenix SDK 0.29 deliverable

Session 031 adds:

- private pool-value dereference with publication-safe output;
- cross-release link-pair deduplication and relocation-family grouping;
- a structural-delta-preserving bounded correction solver;
- strict bilateral code-anchor and independence gates;
- operational graph v24;
- a hash-gated runner and five new unit tests.

The complete suite contains 140 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S031-01 | CONFIRMED, BILATERAL STRUCTURAL | Ten occurrences form eight unique link pairs and five relocation families. |
| S031-02 | CLOSED, BOUNDED NEGATIVE | Seven control pairs produce 68 bilateral strict entries but zero complete code anchors inside `±2048` bytes. |
| S031-03 | NOT ESTABLISHED | No tested family satisfies the two-independent-anchor gate for a file-map piece. |
| S031-04 | OPEN | Runtime callee identity and loader/section address transformation remain unresolved. |

## Next step

Session 032 should derive mapping breakpoints from already verified bilateral
code and data anchors across the principal images, not widen the Session 031
radius. A whole-image relocation-anchor census can test for monotonic sections,
piece boundaries and linker/loader tables, then re-evaluate the seven pool
targets against independently learned pieces.

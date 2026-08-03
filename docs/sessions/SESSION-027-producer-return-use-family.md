# Session 027 - Producer return-use family

- Date: 2026-07-27
- Objective: classify every exact static use of the Session 026 producer
  target and test bounded implementation or registration paths.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the exact target-pointer model.

## Safety boundary

The runner verifies registered ISO hashes and Session 003 principal-image
hashes. It follows only exact runtime-pointer words for the single producer
target pair registered by Session 026. Temporary principal-image members are
removed after analysis.

The pointer census is syntactic. Owner windows are prologue-backed analysis
anchors, not asserted function boundaries, and linear result flow does not
prove branch dominance.

## Confirmed findings

### S027-01 - The complete exact-pointer topology is call-only

Per release, the producer target has:

| Evidence | Count |
|---|---:|
| Exact aligned target words | 17 |
| PC-relative load references | 18 |
| Adjacent literal-load/`JSR` references | 7 |
| Data-only aligned target words | 0 |
| Direct `BSR` targets | 0 |

All 18 PC-relative references are used as indirect control targets in both
images. One literal-pool word has two referrers. No exact target pointer is
used as an argument, memory base or static registration record.

Classification:

```text
static_target_registration_evidence =
  BOUNDED_NEGATIVE_CALL_LITERAL_MODEL
```

This does not exclude encoded, copied, computed or runtime-created
registration.

### S027-02 - Eighteen bilateral return flows are stable

All 18 call pairs share the producer relocation delta and pass:

- co-relocated literal, referrer, call and owner offsets;
- equal owner normalized shape;
- bilateral owner code gates;
- equal producer arguments;
- equal following-call and returned-object contracts.

They occupy 17 unique exact code-gated owner pairs because one owner contains
two producer calls.

Result-use classes:

| Class | Count |
|---|---:|
| Returned-object dynamic dispatch | 15 |
| Return forwarded as `r5` to a static helper | 2 |
| Null test without another linear call | 1 |

### S027-03 - The returned object exposes a regular dispatch grid

Fifteen dynamic dispatches use nine target fields:

| Target field | Occurrences |
|---:|---:|
| 28 | 5 |
| 36 | 1 |
| 44 | 2 |
| 52 | 2 |
| 60 | 1 |
| 68 | 1 |
| 76 | 1 |
| 84 | 1 |
| 92 | 1 |

Every target field is paired with a 16-bit receiver-adjustment field at
`target - 4`. The target fields form a contiguous eight-byte grid from `28`
through `92`.

Ten dispatches retain unavailable `r6` provenance. Five preserve complete
`r4`/`r6` provenance:

- the four Session 025 candidates;
- one new field-`60` / adjustment-`56` context with `r6 = ENTRY:r6`.

The new context has an exact bilateral code-gated owner shape, but its dynamic
target is still unresolved and is not linked to a selected owner.

### S027-04 - Two code-gated static handoffs remain inconclusive

Two producer results are forwarded as `r5` to co-relocated static helper
targets. Both target pairs pass bounded code gates, but:

- neither pair has equal normalized target shapes;
- no modeled direct read of entry `r5` occurs before overwrite or call
  clobber;
- unknown instructions occur before that terminal point;
- no registration store is established.

They remain structural handoff candidates, not confirmed consumers, writers
or registration functions.

### S027-05 - Producer implementation remains open

Session 026's producer target windows remain unvalidated as code. Session 027
finds code-gated caller wrappers and two code-gated handoff helpers, but no
bilateral implementation body or selected-owner registration edge.

## Operational graph v20

Graph v20 contains 44 nodes and 52 edges: 36 confirmed nodes, four probable
nodes, two open nodes and eight bounded-negative edges. It adds the bilateral
return-use family, its confirmed producer edge and one bounded-negative static
pointer-registration edge.

## Phoenix SDK 0.25 deliverable

Session 027 adds:

- `phoenix_mmi.producer_return_family`;
- complete exact target-pointer use classification;
- 18-flow bilateral correlation;
- returned-object dispatch-grid analysis;
- static handoff and entry-`r5` limits;
- operational graph v20;
- a hash-gated runner and eight unit tests.

The complete suite contains 114 tests.

## Next step

Session 028 should focus on the new field-`60` candidate and the two static
handoff preludes. Add only documented SuperH instruction families needed to
resolve their unknown operations, then require a bilateral modeled read/store
from returned `r5` or a concrete selected-owner pointer before promoting any
registration path.

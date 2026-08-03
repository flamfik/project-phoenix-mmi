# Session 029 - Local runtime-pointer-prefix handoff mapping

- Date: 2026-07-27
- Objective: replace prologue proximity with a deterministic local mapping
  test for the two Session 027 static handoff target pairs.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the two registered handoff pairs and one registered
  producer negative-control pair.

## Session 030 correction

Session 030 proves that each registered target lies inside a complete
PC-relative literal pool. The Session 029 “prefix” is the suffix of that pool,
and the code at its end is only a structural successor. No runtime target edge
to that successor is established.

Accordingly, the entry-`r5` result below applies only to the adjacent
successor bodies, not to the unresolved handoff callees. The registration
disproof is withdrawn outside those bodies. See Session 030 and SPEC-039.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes and the Session 003
principal-image hashes. It extracts only the two principal members into an
operating-system temporary directory and deletes them after analysis.

The analysis is restricted to:

- the two static handoff target pairs registered by Session 027;
- the one producer target pair registered by Session 026 as a negative
  control;
- at most eight aligned words at each registered target;
- a fixed `0x180`-byte direct intraprocedural window after a validated
  correction.

No general executable scan, arbitrary forward search, firmware execution,
resource extraction, repacking or vehicle operation was performed.

## Mapping rule

At each registered handoff target, Phoenix counts the maximal leading run of
aligned 32-bit words in the bounded runtime range. The first word outside that
range is tested as the corrected entry.

The correction is accepted only when:

1. the prefix is non-empty and ends before the eight-word bound;
2. the corrected entry passes the Session 028 strict exact-entry gate;
3. its bounded body is fully decoded and passes the code gate;
4. the CD1/CD3 bodies have equal normalized shapes and call/return counts;
5. both handoff pairs share one corrected relocation delta.

This is a deterministic local rule. It is not a forward search for a nearby
prologue and does not establish a universal runtime-to-file mapping.

## Confirmed findings

### S029-01 - Both handoff pairs have bounded pointer prefixes

| Flow | CD1 prefix | CD3 prefix | Corrected-entry delta |
|---:|---:|---:|---:|
| 12 | 3 words / 12 bytes | 4 words / 16 bytes | 322,532 bytes |
| 13 | 2 words / 8 bytes | 3 words / 12 bytes | 322,532 bytes |

CD3 contains exactly one additional prefix word in both pairs. Advancing by
the complete local prefix, and by no additional search distance, produces the
corrected candidate entry.

### S029-02 - Corrected entries form two bilateral code families

All four corrected entries:

- pass the strict exact-entry and bounded-code gates;
- decode with a known-instruction ratio of `1.0`;
- contain one bounded return;
- match their counterpart's normalized body shape.

Flow 12 contains two resolved static calls per release. Flow 13 contains one.
The two pairs share the same corrected-entry relocation delta. Function
boundaries and runtime equivalence are not asserted.

### S029-03 - Entry `r5` is unused by both callee families

A direct intraprocedural CFG was evaluated from every corrected entry. Delay
slots are applied before their transfer, calls are not followed, and `r5` is
treated as caller-saved after a call.

All four CFGs are complete under that model:

- zero reachable unknown instructions;
- zero external or indirect transfers;
- zero reads of entry `r5`;
- one return after entry `r5` has been overwritten or call-clobbered.

The two former `RETURN_FORWARDED_TO_STATIC_HELPER` flows are therefore refined
to:

```text
CALL_RETURN_PRESENT_IN_UNUSED_ENTRY_R5
```

For these two exact callee families, a registration or object-consumer path
through entry `r5` is `DISPROVED`. This result does not disprove other
computed, dynamic or unregistered paths.

## Bounded-negative and open findings

### S029-04 - The producer is a negative control

The Session 026 producer target pair begins with zero runtime-range prefix
words. No correction is applied and no forward entry search is performed. Its
previous invalid/low-known target result therefore remains unchanged.

Status:

```text
session026_producer_prefix_correction = NOT_APPLICABLE
```

### S029-05 - The physical prefix mechanism remains open

The observed words have runtime-pointer-range geometry, but Phoenix has not
identified a loader record, section directory, relocation table or vendor
format that owns them. The following remain open:

- physical loader or section semantics;
- a universal runtime-to-file mapping;
- returned-object type and writer;
- selected-owner target linkage;
- actual FLDB parser, sector-read ABI and optical-buffer ownership.

## Operational graph v22

Graph v22 contains 46 nodes and 56 edges:

- 38 confirmed nodes;
- four probable nodes;
- two open nodes;
- nine bounded-negative edges;
- two disproved edges.

It adds one confirmed bilateral structural-family node and a deliberately
scoped disproved registration edge for the two corrected callees.

## Phoenix SDK 0.27 deliverable

Session 029 adds:

- a bounded maximal runtime-pointer-prefix counter;
- deterministic corrected-entry validation;
- bilateral normalized-shape and relocation gates;
- delay-slot-aware direct CFG entry-`r5` liveness;
- a registered producer negative control;
- operational graph v22;
- a hash-gated runner and seven new unit tests.

The complete suite contains 128 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S029-01 | CONFIRMED, BOUNDED STRUCTURAL | Both registered handoff pairs begin with deterministic runtime-pointer prefixes; CD3 has one additional word in each pair. |
| S029-02 | CONFIRMED, BILATERAL STRUCTURAL | Prefix-corrected entries are fully decoded, shape-equal per pair and share one corrected relocation delta. |
| S029-03 | DISPROVED, BOUNDED | None of the four corrected callees reads entry `r5` on any modeled path; these two families do not consume or register that argument. |
| S029-04 | CLOSED, BOUNDED NEGATIVE | The Session 026 producer has no applicable prefix correction and is not forward-scanned. |
| S029-05 | OPEN | No loader/section format or universal mapping has been established. |

## Next step

Session 030 should investigate who references or constructs the registered
prefixes and whether their count/placement belongs to a reproducible section,
relocation or function-descriptor grammar. Promotion requires a cross-version
record layout and an independently identified consumer; matching pointer
ranges alone are insufficient.

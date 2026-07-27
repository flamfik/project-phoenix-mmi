# Session 026 - Immediate CALL_RETURN producer family

- Date: 2026-07-27
- Objective: identify the calls that produce `CALL_RETURN` for the four
  Session 025 dispatch candidates.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the four registered candidates.

## Safety boundary

The runner verifies registered ISO hashes and Session 003 principal-image
hashes, extracts only the two principal members into temporary storage and
deletes them after analysis. It follows only the four Session 025 candidates.
The whole-image scan is limited to literal-backed calls to the single resolved
producer target on each side.

## Confirmed findings

### S026-01 - One producer-reference pair supplies all four candidates

For every candidate, the target and adjusted receiver slices cross the same
immediately preceding call. Each call is an indirect `JSR` whose register is
loaded from an in-image literal. All four calls resolve to one target per
release.

All bilateral gates pass:

- equal producer instruction and byte position inside each paired owner;
- equal target expression and owner-relative target displacement;
- equal producer arguments `r4` through `r7`;
- equal returned-object field geometry.

The producer arguments are stable in all four families:

```text
r4 = ENTRY:r4
r5 = ENTRY:r5
r6 = CONST:0
r7 = ENTRY:r7
```

### S026-02 - The target-specific call family is 7/7

The resolved target has seven literal-backed call references in each image.
Sorted bilateral pairs all:

- share one file-offset relocation delta;
- have equal relocation-normalized call-site contexts;
- include the four Session 025 producer calls.

This is a target-specific syntactic census, not a complete executable map or
proof of runtime equivalence.

### S026-03 - Returned-object dispatch geometry is stable

The four candidates retain the same bilateral grammar:

```text
target field = receiver-adjustment field + 4
```

Observed target fields are `28`, `36` and `44` (twice); adjustment fields are
`24`, `32` and `40`. This confirms one stable structural return-object grammar,
not its class, type or owner.

### S026-04 - The resolved target is not yet a validated code entry

The paired target windows do not have equal normalized shapes and neither side
passes the bounded code gate. Phoenix therefore does not label the targets as
functions and does not assert runtime equivalence.

Still open:

- returned-object type, creator and writer;
- producer-target semantics;
- registration of any dynamic target to a selected Session 021 owner;
- unique owner-entry caller and semantic subsystem identity.

## Operational graph v19

Graph v19 contains 43 nodes and 50 edges: 35 confirmed nodes, four probable
nodes, two open nodes and seven bounded-negative edges. It adds the confirmed
producer-reference family and its structural edge to the four Session 025
dispatch candidates.

## Phoenix SDK 0.24 deliverable

Session 026 adds:

- `phoenix_mmi.call_return_producer`;
- immediate preceding-call correlation;
- producer target and `r4`-`r7` tracing;
- returned-object geometry validation;
- target-specific literal-call census;
- operational graph v19;
- a hash-gated runner and six unit tests.

The complete suite contains 106 tests.

## Next step

Session 027 should analyze the seven producer-call contexts as a bounded
family, classify the three non-promoted return uses and search for a
code-gated implementation or registration path without promoting the current
unvalidated target windows.

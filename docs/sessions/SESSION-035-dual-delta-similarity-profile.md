# Session 035 - Dual-delta similarity profile

- Date: 2026-07-28
- Objective: test whether the remaining `RB-015` envelope contains one
  reproducible change of dominance between the two prior relocation deltas.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the declared fixed-window, two-delta model.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes and the Session 003
principal-image hashes before analysis. It extracts only the two principal
members into an operating-system temporary directory and removes them after
the run.

The analyzer reads:

- only CD1 `[7,832,267, 7,979,108)`;
- only the corresponding CD3 range under delta `+61,136`;
- only the corresponding CD3 range under delta `-7,488,776`.

It performs no whole-image search, new-delta discovery, adaptive threshold,
code execution, instruction decoding, repacking, resource extraction for
publication or vehicle operation.

## Frozen profile contract

The contract was fixed before the result was inspected:

- window sizes: 256, 512 and 1,024 bytes;
- step: 128 bytes;
- primary grid offset: zero;
- control grid offset: 64 bytes;
- minimum exact-byte match: `1/16` of a window;
- minimum winning advantage: `1/32` of a window;
- at least four distinct byte values must support the winning mapping
  exclusively.

Each window is classified as:

```text
LEFT_DELTA_DOMINANT
RIGHT_DELTA_DOMINANT
AMBIGUOUS
```

The model succeeds only if every window size contains one forward
left-to-right dominance change, no reverse change, the crossing bands
intersect, and the half-step grid reproduces that positive topology.

## Results

### S035-01 - The primary profiles are sparse and non-monotonic

| Window | Windows | Left | Right | Ambiguous | Forward | Reverse | Result |
|---:|---:|---:|---:|---:|---:|---:|---|
| 256 | 1,146 | 67 | 12 | 1,067 | 8 | 7 | multiple/reversed |
| 512 | 1,144 | 62 | 3 | 1,079 | 1 | 1 | multiple/reversed |
| 1,024 | 1,140 | 45 | 0 | 1,095 | 0 | 0 | one-sided only |

No tested scale produces one forward change. Most windows are ambiguous and
the isolated dominant windows do not form a stable monotonic transition.

### S035-02 - The half-step grid reproduces the negative topology

| Window | Windows | Left | Right | Ambiguous | Forward | Reverse | Result |
|---:|---:|---:|---:|---:|---:|---:|---|
| 256 | 1,145 | 71 | 12 | 1,062 | 6 | 6 | multiple/reversed |
| 512 | 1,143 | 62 | 3 | 1,078 | 1 | 1 | multiple/reversed |
| 1,024 | 1,139 | 45 | 0 | 1,094 | 0 | 0 | one-sided only |

The counts vary slightly, as expected after shifting overlapping windows, but
all three scale classifications remain the same.

```text
grid_control = REPLICATED_BOUNDED_NEGATIVE
```

### S035-03 - The single-transition model is closed only within scope

The predeclared model expected one stable change from the `RZ-012` delta to the
`RZ-013` delta. Both grids reject that topology.

```text
single_dominance_change_model = CLOSED_BOUNDED_NEGATIVE
similarity_transition = NOT_LOCATED_UNDER_FIXED_MODEL
```

This does not prove that no section boundary exists. It disproves only one
monotonic transition detectable by the declared exact-byte ratios, window
sizes, step and two known mappings.

### S035-04 - Session 034 remains authoritative

No new bound is promoted:

```text
[7,832,267, 7,979,108)
width = 146,841
```

The exact section boundary remains open. The result is compatible with
multiple interleaved content islands, version-specific replacement, patched
relocations, or an unmodeled layout mechanism. It does not distinguish these
possibilities.

## Operational graph v28

Graph v28 contains 58 nodes and 70 edges. It adds:

- the fixed two-delta similarity profile;
- the bounded-negative single-transition result;
- no exact section boundary, loader, runtime or media edge.

## Phoenix SDK 0.33 deliverable

Session 035 adds:

- strict Session 034 input and artifact-hash gates;
- fixed multi-scale two-delta window profiling;
- exact-byte, exclusive-byte and exact-word metrics;
- low-information distinct-value gate;
- dominance-run and crossing topology summaries;
- half-step grid control;
- bounded-negative finalization without threshold tuning;
- compact publication-safe report generation;
- operational graph v28;
- eight new unit tests.

The complete suite contains 167 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S035-01 | CONFIRMED, DESCRIPTIVE | All three primary fixed-window profiles were measured under the frozen contract. |
| S035-02 | CONFIRMED, REPLICATED NEGATIVE | The half-step grid reproduces the same per-scale failure topology. |
| S035-03 | CLOSED, BOUNDED NEGATIVE | One monotonic dual-delta dominance change is not supported under the tested model. |
| S035-04 | OPEN | The exact section boundary and mechanism remain unresolved. |
| S035-05 | UNCHANGED | The Session 034 envelope remains the narrowest supported bound. |

## Next step

Session 036 should stop treating `RB-015` as one simple change point. A fixed
4 KiB island atlas can classify exact-byte, exact-word, entropy and
relocation-patch morphology under the same two deltas. Its purpose should be
to test whether the envelope contains multiple content families, not to tune
the failed Session 035 thresholds.

# Session 037 - RZ-012 2 KiB micro-island

- Date: 2026-07-28
- Objective: determine whether the replicated Session 036 `RZ-012` overlap is
  clustered structure or scattered byte coincidence.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the declared fixed 2 KiB micro-atlas.

## Safety boundary

The runner verifies the registered ISO hashes, principal-image hashes and the
Session 036 sparse replicated input state. It derives the overlap from the two
published tile IDs rather than accepting a new range from the command line.
The two principal members exist only in an operating-system temporary
directory during analysis.

The analyzer reads exactly:

```text
CD1 [7,905,995, 7,908,043)                 2,048 bytes
CD3 at the prior RZ-012 mapping             2,048 bytes
CD3 at the prior RZ-013 negative mapping    2,048 bytes
```

No new delta search, envelope scan, adaptive threshold, instruction execution,
firmware modification, repacking or vehicle operation is performed.

## Frozen contract

The contract was fixed before inspecting the artifact result:

- eight 256-byte bins from phase zero;
- the same bins shifted by 128 bytes as a grid-origin control;
- natural absolute 2-byte and 4-byte alignment;
- exact-byte runs reported without their byte values;
- equality enrichment: at least four times the `RZ-013` count and at least 64
  additional bytes;
- spatial cluster: at least 64 covered equal bytes and at least half of them
  in two adjacent bins, independently in both phases;
- decoder-mnemonic enrichment: at least twice the control, at least 32
  additional pairs and at least 64 pairs;
- structured signal: phase-stable cluster, an exact run of at least eight
  bytes, or at least `1/8` naturally aligned exact words.

Decoder output is used only as anonymous morphology. It cannot establish code,
an ABI, an instruction boundary or execution.

## Results

### S037-01 - The 2 KiB overlap is derived and reproducible

The primary and shifted Session 036 tiles intersect at:

```text
[7,905,995, 7,908,043)
length = 2,048
```

The geometry and both principal-image hashes pass the strict input gate.

### S037-02 - RZ-012 equality is strongly enriched over RZ-013

| Mapping | Equal bytes | Ratio |
|---|---:|---:|
| `RZ-012` | 236 | 11.523438% |
| `RZ-013` negative control | 15 | 0.732422% |

The difference is 221 bytes and the count ratio is approximately `15.73`.
Both exceed the frozen `4x` and `+64` gates.

```text
byte_equality_enrichment = CONFIRMED_UNDER_FIXED_CONTROL
```

### S037-03 - Equality is clustered and stable across phase

For phase zero, 212 of 236 equal bytes (`89.830508%`) fall in the strongest
adjacent-bin pair. For phase `+128`, 213 of the 230 covered equal bytes
(`92.608696%`) fall in its strongest pair.

The negative control remains distributed in both phases:

- phase zero: 7 of 15 in its strongest pair;
- phase `+128`: 6 of 13 in its strongest pair.

```text
RZ-012 spatial topology = CLUSTERED_PHASE_STABLE
RZ-013 spatial topology = DISTRIBUTED_PHASE_STABLE
micro-island correspondence = STRUCTURED_CORRESPONDENCE_SUPPORTED
```

This confirms a bounded structured file-content correspondence, not ownership
of a section.

### S037-04 - Exact runs and natural units support local structure

`RZ-012` contains:

- 53 exact-byte runs;
- 24 runs of at least two bytes;
- ten runs of at least four bytes;
- seven runs of at least eight bytes;
- a maximum run of 25 bytes;
- 207 bytes inside runs of at least two bytes;
- 92 naturally aligned exact halfwords of 1,023 eligible;
- 32 naturally aligned exact words of 511 eligible.

`RZ-013` has a maximum run of three bytes, one exact halfword and zero exact
words. No raw run bytes, word values or mnemonic names are published.

### S037-05 - SH decoder morphology does not pass promotion

Anonymous same-known-mnemonic counts are:

| Mapping | Count |
|---|---:|
| `RZ-012` | 238 |
| `RZ-013` negative control | 126 |

The difference is 112, but the ratio is `1.888889`, below the frozen `2x`
gate.

```text
sh_decoder_morphology = NOT_ESTABLISHED
code_region_asserted = false
```

The result deliberately makes no code or execution claim.

### S037-06 - The exact section boundary remains open

The clustered correspondence lies inside the prior 2 KiB overlap, but
microbin edges are sampling boundaries and exact-run endpoints are local
equality endpoints. Neither is a section boundary.

```text
authoritative envelope = [7,832,267, 7,979,108)
exact_section_boundary = OPEN
runtime_loader_transform = NOT_OBSERVED
```

## Operational graph v30

Graph v30 contains 62 nodes and 74 edges. It adds:

- the bounded `RZ-012` micro-island correspondence;
- the anonymous SH decoder-morphology result marked `NOT_CODE_PROOF`;
- no runtime, loader, exact-boundary or media edge.

## Phoenix SDK 0.35 deliverable

Session 037 adds:

- strict derivation of the 2 KiB overlap from Session 036;
- exact-byte run profiling;
- natural aligned halfword and word equality;
- two-phase 256-byte microbins;
- a fixed `RZ-013` negative-control enrichment gate;
- anonymous SH decoder morphology;
- publication-safe comparison and disc reports;
- operational graph v30;
- ten new unit tests.

The complete suite contains 186 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S037-01 | CONFIRMED | The only replicated Session 036 overlap is exactly 2,048 bytes. |
| S037-02 | CONFIRMED, CONTROLLED | `RZ-012` exact-byte equality exceeds the fixed `RZ-013` control gate. |
| S037-03 | CONFIRMED, BOUNDED STRUCTURAL | The equality is clustered under both fixed bin phases. |
| S037-04 | CONFIRMED, DESCRIPTIVE | Exact runs and naturally aligned units support local correspondence. |
| S037-05 | CLOSED, BOUNDED NEGATIVE | Anonymous decoder-mnemonic enrichment does not reach the `2x` gate. |
| S037-06 | OPEN | Exact section ownership, boundary and layout mechanism remain unresolved. |

## Next step

Session 038 should preserve this 2 KiB boundary and test the internal cluster
with a fixed run-gap topology: merge exact runs only across predeclared small
gaps, compare the resulting skeleton with `RZ-013`, and test whether the
repeated 25-byte run lengths reflect stable record fields or coincidental fragments.
It must not infer semantics from repeated lengths or widen the search.

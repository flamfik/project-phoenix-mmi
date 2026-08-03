# Session 038 - RZ-012 run-gap topology

- Date: 2026-07-28
- Objective: determine whether the clustered Session 037 exact runs form a
  stable local skeleton or a periodic record grammar.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the declared fixed 2 KiB run-gap model.

## Safety boundary

The runner verifies the registered ISO hashes, principal-image hashes and the
complete Session 037 input contract. It derives the same 2 KiB overlap and
recomputes both exact-run lists before any topology classification.

The analyzer reads exactly:

```text
CD1 [7,905,995, 7,908,043)                 2,048 bytes
CD3 at the prior RZ-012 mapping             2,048 bytes
CD3 at the prior RZ-013 negative mapping    2,048 bytes
```

No new delta search, surrounding-window scan, adaptive threshold, instruction
execution, firmware modification, repacking or vehicle operation is
performed.

## Frozen contract

The contract was fixed before inspecting the artifact result:

- primary bridge: merge exact runs only when the intervening unequal gap is
  at most one byte;
- relaxed control: repeat with gap cap two;
- promoted component: at least 64 bytes span, four runs, 64 equal bytes and
  `75%` equality coverage;
- single-byte skeleton: at least four gaps, every gap exactly one byte;
- fixed gap-stride gate: at least five events, four dominant strides and
  `75%` dominant share;
- phase-lattice gate: periods 4-64, at least three cycles in the component,
  four phase-supported events and `75%` share;
- repeated-run record gate: at least four runs of one length, three spacings
  and `75%` dominant-spacing share.

A repeated length or attractive period is never a record grammar without its
independent spacing gate.

## Results

### S038-01 - Session 037 exact runs replay exactly

Both freshly computed run lists match the published Session 037 start, end and
length tuples. The analyzer rejects any changed list or principal-image hash.

### S038-02 - One RZ-012 component is control-distinguished

The primary `gap <= 1` model produces exactly one promoted `RZ-012` component:

```text
[7,906,542, 7,906,782)
span = 240 bytes
```

It contains:

- 30 exact runs;
- 211 equal bytes;
- 29 unequal gap bytes;
- 29 gaps, every one byte long;
- equality coverage `87.916667%`.

`RZ-013` produces zero promoted components.

```text
run_gap_topology =
  CONTROL_DISTINGUISHED_SINGLE_BYTE_GAP_SKELETON
```

The component represents file-content correspondence with sparse singleton
differences. It is not assigned to code, data, a resource or a section.

### S038-03 - The component is stable under the relaxed gap cap

Repeating the analysis with `gap <= 2` preserves the dominant component start,
end and equal-byte count.

```text
gap_cap_control = STABLE_AT_CAPS_1_AND_2
```

The result is therefore not an artifact of choosing the narrowest accepted
gap cap.

### S038-04 - No fixed gap-stride record lattice passes

There are 29 gap events and 28 inter-event strides. The dominant stride is
four bytes:

```text
count = 12
share = 42.857143%
```

The strongest tested phase lattice also uses period four:

```text
support = 18 of 29
share = 62.068966%
```

Both are below the frozen `75%` gate.

```text
fixed_stride_record_model = NOT_ESTABLISHED
```

### S038-05 - Repeated run lengths do not establish records

Two multi-byte lengths occur at least four times:

| Run length | Occurrences | Dominant start spacing | Spacing share |
|---:|---:|---:|---:|
| 3 | 12 | 4 | 36.363636% |
| 25 | 5 | 30 | 25.000000% |

For the 25-byte runs, all four start spacings are different; the reported
dominant value wins only the deterministic tie-break. Neither candidate
reaches `75%`.

```text
repeated_run_record_model = NOT_ESTABLISHED
```

The repeated 25-byte length is therefore a descriptive feature, not evidence
of a 25-byte field or record.

### S038-06 - The micro-island now has a stable structural model

The controlled result supports:

```text
micro_island_structural_model =
  STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON
```

This closes the Session 037 micro-island question at the declared structural
level. The result does not identify why the singleton bytes differ.

The following remain open outside this microanalysis:

- semantic owner and field meanings;
- compile/link placement versus a loader transform;
- exact section boundary;
- runtime execution.

The Session 034 envelope remains authoritative:

```text
[7,832,267, 7,979,108)
```

## Operational graph v31

Graph v31 contains 64 nodes and 76 edges. It adds:

- the stable `RZ-012` run-gap skeleton;
- the bounded-negative fixed-period result;
- no semantic-owner, section, loader, runtime or media edge.

## Phoenix SDK 0.36 deliverable

Session 038 adds:

- strict replay of Session 037 exact-run geometry;
- fixed one-byte run bridging and two-byte control;
- conservative component promotion;
- gap and run-length histograms;
- direct-stride and phase-lattice tests;
- repeated-run spacing validation;
- publication-safe reports;
- operational graph v31;
- ten new unit tests.

The complete suite contains 196 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S038-01 | CONFIRMED | Both exact-run lists and artifact hashes replay Session 037. |
| S038-02 | CONFIRMED, CONTROLLED STRUCTURAL | One 240-byte `RZ-012` singleton-gap component is absent under `RZ-013`. |
| S038-03 | CONFIRMED, REPLICATED | Gap caps one and two preserve the dominant component. |
| S038-04 | CLOSED, BOUNDED NEGATIVE | No fixed gap-stride record lattice reaches the frozen gate. |
| S038-05 | CLOSED, BOUNDED NEGATIVE | Repeated run lengths lack stable start spacing. |
| S038-06 | CLOSED, STRUCTURAL | The 2 KiB micro-island has a stable sparse-singleton-difference model. |

## Next step

The bounded microanalysis is complete. A later session should not subdivide
these 2 KiB further without independent evidence. The next useful direction
is external provenance: search only independently registered reference or
descriptor families for an owner of the 240-byte component, while retaining
the exact section boundary as open.

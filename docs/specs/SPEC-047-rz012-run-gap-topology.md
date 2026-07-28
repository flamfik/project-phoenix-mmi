# SPEC-047 - RZ-012 run-gap topology

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 036-038
- Related questions: RQ-127-RQ-137

## Purpose

Define a controlled exact-run topology for the single clustered 2 KiB
`RZ-012` micro-island.

## Input gate

The input must:

- use `phoenix-mmi.micro-island-comparison/v1`;
- reproduce both principal-image hashes;
- retain `STRUCTURED_CORRESPONDENCE_SUPPORTED`;
- retain `CONFIRMED_UNDER_FIXED_CONTROL` byte enrichment;
- retain `CLUSTERED_PHASE_STABLE`;
- retain an exact 2 KiB overlap;
- retain an open exact section boundary.

Fresh `RZ-012` and `RZ-013` exact-run tuples must equal the Session 037 tuples
before the model may run.

## Read boundary

Only the prior CD1 overlap and its two prior CD3 mappings may be read. New
delta discovery, neighboring-window reads, whole-image scans and adaptive
thresholds are forbidden.

## Run component

Primary components join consecutive exact runs only when:

```text
gap length <= 1 byte
```

The relaxed control repeats the model with gap length at most two bytes.

A component is promoted only when:

```text
span >= 64 bytes
run count >= 4
equal bytes >= 64
equality coverage >= 0.75
```

A singleton-gap skeleton additionally requires at least four gaps and every
gap to be exactly one byte.

## Period models

### Direct gap stride

At least five gap events are required. The dominant inter-event stride must
occur at least four times and cover at least `75%` of all strides.

### Phase lattice

Periods 4-64 are tested only when the component spans at least three cycles.
The dominant modulo phase must contain at least four events and `75%` of all
gap events.

The fixed-stride record gate requires both the direct-stride and phase-lattice
gates.

### Repeated run length

Only run lengths of at least two bytes with four occurrences are candidates.
Their start positions require at least three spacings, three equal dominant
spacings and `75%` dominant share.

No period or repeated length alone identifies a record.

## Session 038 result

- one promoted `RZ-012` component and zero `RZ-013` components;
- component span: 240 bytes;
- 30 exact runs and 29 singleton gaps;
- 211 equal and 29 unequal bytes;
- equality coverage: `87.916667%`;
- identical dominant component under gap caps one and two;
- dominant gap stride share: `42.857143%`;
- best phase-lattice share: `62.068966%`;
- repeated 3-byte run spacing share: `36.363636%`;
- repeated 25-byte run spacing share: `25%`;
- fixed-stride and repeated-run record models: not established;
- stable sparse-single-byte-difference skeleton: confirmed;
- semantic owner and exact section boundary: open.

## Interpretation boundary

The stable model describes where the two release images agree and differ
inside a bounded file-content component. It does not establish:

- a record or field layout;
- code or data;
- section ownership;
- loader behavior;
- runtime execution;
- compatibility with modified firmware.

## Publication contract

Reports may contain hashes, generated IDs, file-relative offsets, lengths,
run/gap histograms, counts, ratios, tested periods and evidence statuses.

They must not contain firmware bytes, unequal byte values, word values,
instruction bytes, mnemonic names, raw strings, pointer values, absolute
runtime addresses, local paths, map payloads or extracted resources.

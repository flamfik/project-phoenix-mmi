# SPEC-044 - Bounded dual-delta similarity profile

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 032-035
- Related questions: RQ-103, RQ-106, RQ-108, RQ-111, RQ-113-RQ-120

## Purpose

Define a non-adaptive test for one file-layout similarity transition between
the two independently established relocation deltas bounding `RB-015`.

## Input gate

The input must:

- use `phoenix-mmi.exact-block-map-comparison/v1`;
- reproduce both principal-image hashes;
- retain exact-block support for `RZ-012` and `RZ-013`;
- retain `CONFIRMED_STABLE` for the 64/128-byte seed control;
- retain an open exact section boundary;
- retain the narrowed Session 034 envelope.

## Read boundary

The analyzer may read only:

```text
CD1 [L, U)
CD3 [L + delta(RZ-012), U + delta(RZ-012))
CD3 [L + delta(RZ-013), U + delta(RZ-013))
```

It must not search for another delta or widen `[L, U)`.

## Fixed grids

The primary grid uses:

- sizes 256, 512 and 1,024 bytes;
- step 128 bytes;
- offset zero from `L`.

The control uses the same contract with offset 64 bytes. Incomplete terminal
windows are omitted rather than resized.

## Window metrics

For each of the two mappings the analyzer records:

- equal-byte count and ratio;
- number of distinct equal values;
- aligned exact four-byte word count and ratio;
- longest exact-byte run.

It also records equality exclusive to each mapping and the number of distinct
exclusive byte values. Firmware bytes are never placed in a report.

## Dominance gate

For a window of length `N`, mapping `A` dominates mapping `B` only when:

```text
equal(A) >= ceil(N / 16)
equal(A) - equal(B) >= ceil(N / 32)
distinct_exclusive_values(A) >= 4
```

Otherwise the window is ambiguous. Thresholds are fixed before inspecting the
artifact result and may not be tuned within the session.

## Scale topology

Ambiguous windows are skipped only when enumerating changes between
informative windows.

A scale passes when:

- its first informative window favors `RZ-012`;
- its last informative window favors `RZ-013`;
- exactly one forward change occurs;
- no reverse change occurs.

The primary result is multiscale only when all three scales pass and their
crossing-center bands intersect.

## Grid control

Positive stability requires the origin and half-step grids to reproduce the
multiscale result with overlapping crossing hulls.

A bounded negative is replicated when:

- both grids are `NOT_STABLE_ACROSS_WINDOW_SIZES`; and
- every corresponding scale retains the same topology classification.

Other combinations are inconclusive.

## Session 035 result

- no primary scale contains one forward-only dominance change;
- the shifted grid reproduces the same three topology classifications;
- the fixed single-transition model is a replicated bounded negative;
- the transition envelope remains `[7,832,267, 7,979,108)`;
- no exact section or runtime boundary is asserted.

## Publication contract

Public reports may contain artifact hashes, file-relative offsets, the two
prior deltas, window parameters, thresholds, counts, ratios, run bounds,
crossing-center bounds and evidence statuses.

They must not contain firmware bytes, full per-window metric samples, raw
strings, raw pointers, absolute runtime addresses, local paths, map payloads
or extracted resources.

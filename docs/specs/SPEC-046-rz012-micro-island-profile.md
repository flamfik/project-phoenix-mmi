# SPEC-046 - RZ-012 2 KiB micro-island profile

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 034-037
- Related questions: RQ-122, RQ-126-RQ-131

## Purpose

Define a fixed, controlled profile for the single 2 KiB overlap independently
accepted by both Session 036 tile grids.

## Input gate

The input must:

- use `phoenix-mmi.content-island-atlas/v1`;
- reproduce both principal-image hashes;
- retain `SPARSE_ONE_SIDED_SUPPORT_REPLICATED`;
- retain `CLOSED_BOUNDED_NEGATIVE` for multiple interleaved families;
- retain `REPLICATED_SPARSE_ONE_SIDED_SUPPORT` for the grid control;
- contain exactly one agreeing overlap pair;
- identify the primary tile as `LEFT_FAMILY`;
- retain an open exact section boundary.

The overlap is derived from the published tile IDs and fixed 4 KiB geometry.
Its required length is exactly 2,048 bytes.

## Read boundary

Only the derived CD1 overlap and the same range under the prior `RZ-012` and
`RZ-013` CD3 deltas may be read. New delta discovery, whole-image scanning
and adaptive thresholds are forbidden.

## Exact-content metrics

Each mapping records:

- equal-byte count, ratio and distinct equal-value count;
- maximal contiguous exact-byte runs and counts at lengths 2, 4 and 8;
- naturally aligned exact two-byte and four-byte units;
- 256-byte microbins at phases zero and `+128`;
- adjacent-bin concentration;
- anonymous bounded SH decoder counts.

Run offsets and file-relative alignment offsets may be reported. Raw bytes,
word values, instruction bytes and mnemonic names are forbidden.

## Equality enrichment gate

`RZ-012` equality is enriched only when:

```text
RZ012 equal bytes >= 4 * RZ013 equal bytes
RZ012 equal bytes - RZ013 equal bytes >= 64
```

`RZ-013` is a negative mapped control inherited from earlier independent
relocation evidence; it is not a random baseline.

## Spatial cluster gate

For each phase:

```text
covered equal bytes >= 64
strongest adjacent-bin pair >= 1/2 of covered equal bytes
```

Both phases must pass for `CLUSTERED_PHASE_STABLE`. Both must fail for
`DISTRIBUTED_PHASE_STABLE`; disagreement is `PHASE_SENSITIVE`.

The shifted phase covers only complete bins, so it excludes the first and last
128 bytes. Its denominator is the equality count inside that covered range.

## Structured correspondence gate

An enriched mapping is structured when any of the following holds:

- spatial topology is `CLUSTERED_PHASE_STABLE`;
- maximum exact run is at least eight bytes;
- naturally aligned exact-word ratio is at least `1/8`.

This yields:

- `STRUCTURED_CORRESPONDENCE_SUPPORTED`;
- `ENRICHED_BUT_SCATTERED`; or
- `NOT_DISTINGUISHED_FROM_CONTROL`.

These are file-content classes. They are not section, code, loader or runtime
classes.

## Decoder-morphology gate

The SH profile counts known decoder results and matching anonymous mnemonic
and flow classes at natural two-byte alignment. Mnemonic enrichment requires:

```text
RZ012 same-known-mnemonic count >= 2 * RZ013 count
difference >= 32
RZ012 count >= 64
```

Even a passing result is `ENRICHED_NOT_CODE_PROOF`. No decoder result can
establish executable code without independent control-flow and reference
evidence.

## Session 037 result

- derived overlap: 2,048 bytes;
- `RZ-012`: 236 equal bytes, maximum exact run 25 bytes;
- `RZ-013`: 15 equal bytes, maximum exact run three bytes;
- byte equality enrichment: confirmed under the fixed control;
- `RZ-012`: clustered in both phases;
- `RZ-013`: distributed in both phases;
- exact halfwords/words: `92/32` for `RZ-012`, `1/0` for `RZ-013`;
- decoder-mnemonic ratio: `1.888889`, below the `2x` gate;
- exact section boundary: open.

## Publication contract

Reports may contain hashes, generated IDs, file-relative offsets, lengths,
prior deltas, aggregate counts, ratios and evidence statuses.

They must not contain firmware bytes, raw overlap bytes, word values,
instruction bytes, mnemonic names, raw strings, pointer values, absolute
runtime addresses, local paths, map payloads or extracted resources.

# SPEC-045 - Fixed content-island atlas

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 034-036
- Related questions: RQ-108, RQ-111, RQ-119-RQ-126

## Purpose

Define a fixed two-grid atlas for local content correspondence after a
single-transition similarity model has failed.

## Input gate

The input must:

- use `phoenix-mmi.dual-delta-similarity-comparison/v1`;
- reproduce both principal-image hashes;
- retain the replicated Session 035 bounded negative;
- retain the unchanged Session 034 envelope;
- retain an open exact section boundary;
- retain the two prior `RZ-012` and `RZ-013` deltas.

## Read boundary

Only the unchanged CD1 envelope and its two mapped CD3 ranges may be read. New
delta discovery and whole-image scanning are forbidden.

## Tile grids

Primary tiles:

```text
size = 4096
offset = 0
step = 4096
```

Control tiles use offset 2,048 with the same size and step. A terminal partial
tile is admitted only when its length is at least 2,048 bytes.

## Mapping metrics

Each tile/mapping pair records:

- equal-byte count, ratio and distinct equal-value count;
- exact aligned four-byte word count and ratio;
- source/mapped Shannon entropy and absolute delta;
- byte-histogram total variation;
- unequal-word count;
- distinct unequal-word-difference count;
- dominant unequal-word-difference count and share.

Raw bytes, raw word values and the dominant word-difference value are not
reported.

## Mapping classes

Classes are evaluated in order:

1. `EXACT_WORD_SUPPORTED`: at least `1/8` exact words and eight distinct equal
   byte values.
2. `REPEATED_WORD_DELTA_CANDIDATE`: at least 16 unequal words, eight instances
   of the dominant anonymous difference, at least `1/8` share and byte
   support.
3. `BYTE_SIMILAR_SUPPORTED`: at least `1/16` equal bytes and 16 distinct equal
   values.
4. `DISTRIBUTION_SIMILAR_ONLY`: entropy delta at most `0.25` and histogram
   total variation at most `0.125`.
5. `DIVERGENT`.

Distribution-only similarity has no content-support rank.

## Tile assignment

`LEFT_FAMILY` or `RIGHT_FAMILY` requires one mapping to have a strictly higher
content-support rank of at least byte similarity.

Equal supported ranks become `BILATERAL_AMBIGUOUS`. If neither mapping reaches
byte support, the tile is `UNRESOLVED`.

## Grid control

Resolved tile pairs are compared only when their overlap is at least 2,048
bytes.

A replicated multi-island atlas requires:

- both grids to contain multiple interleaved families;
- at least four resolved overlap pairs;
- at least `3/4` equal assignments.

One-sided topology may be reported as sparse replicated support when at least
one resolved overlapping pair agrees. It does not satisfy the multi-island
promotion gate.

## Session 036 result

- primary: one `LEFT_FAMILY`, zero `RIGHT_FAMILY`, 35 unresolved;
- shifted: one `LEFT_FAMILY`, zero `RIGHT_FAMILY`, 34 unresolved;
- the accepted tiles overlap over 2,048 bytes;
- neither accepted tile passes the exact-word gate;
- no repeated word-difference candidate exists;
- the multiple-interleaved 4 KiB model is a bounded negative;
- the exact boundary and Session 034 envelope remain unchanged.

## Publication contract

Reports may contain hashes, generated tile/island IDs, file-relative offsets,
lengths, prior deltas, aggregate counts, ratios, entropy, histogram distance,
anonymous word-difference counts and evidence statuses.

They must not contain firmware bytes, raw tile bytes, raw word values,
dominant word-difference values, raw strings, raw pointers, absolute runtime
addresses, local paths, map payloads or extracted resources.

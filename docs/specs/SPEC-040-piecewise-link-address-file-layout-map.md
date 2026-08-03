# SPEC-040 - Piecewise link-address/file-layout map

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 006, 029-031
- Related questions: RQ-098, RQ-100-RQ-103

## Purpose

Define how Phoenix may turn paired runtime-link literals into a bounded
cross-release relocation atlas and, only with independent code/data evidence,
into a piecewise file-layout map.

## Input contract

An accepted literal-pool pair must already satisfy SPEC-039:

- equal pool length;
- equal word ordinals;
- one preceding PC-relative referrer per word;
- equal relative use grammar;
- one confirmed structural file relocation delta.

Pool entries are paired by word ordinal. Duplicate value pairs are assigned one
generated pair ID and do not become independent evidence through repetition.

## Publication contract

The analyzer may publish:

- generated pair and family IDs;
- use classifications;
- occurrence and unique-pair counts;
- cross-release link deltas;
- relative file corrections;
- bounded file-relative candidate offsets;
- normalized structural hashes and gate results.

It must not publish raw pointer values, absolute runtime addresses, instruction
bytes, firmware bytes, raw strings, local paths, map payloads or extracted
resources.

## Correction equation

Given a confirmed structural relocation `D_file` and paired link offsets:

```text
D_link = right_link - left_link
D_relative = D_file - D_link

left_file  = left_link  + C
right_file = right_link + C + D_relative
```

`C` is searched in a declared, fixed, even-aligned interval. The two file
offsets are never searched independently.

## Code-anchor gate

Only a literal classified as an indirect-control target is eligible for a code
anchor. One correction candidate passes when:

- both candidate offsets are in range and instruction-aligned;
- both pass the strict exact-entry policy;
- both bounded windows pass the code gate;
- both windows have a known-instruction ratio of `1.0`;
- normalized shapes are equal.

A nearby prologue without equal complete shape is not an anchor.

## Family promotion

A relocation family is:

- `CONFIRMED_TWO_INDEPENDENT_CODE_ANCHORS` only when at least two distinct
  eligible link pairs share exactly one common passing correction;
- `PROVISIONAL_SINGLE_PAIR_OR_INCOMPLETE_FAMILY` when only one pair or an
  incomplete subset supports a unique correction;
- `AMBIGUOUS_BOUNDED_CANDIDATES` when passing corrections are non-unique;
- `BOUNDED_NEGATIVE_NO_CODE_ANCHOR` when eligible pairs have no passing
  correction;
- `NOT_APPLICABLE_NON_CONTROL_LITERAL` when no member is a control target.

A confirmed family constrains file offsets only. It does not by itself prove
runtime equivalence, semantic ownership or a particular callee.

## Session 031 result

- ten pool occurrences form eight unique link pairs;
- five cross-release relocation families are confirmed structurally;
- seven unique control pairs are code-anchor eligible;
- the fixed search evaluates 14,343 correction candidates;
- 68 pairs pass the bilateral strict-entry gate;
- zero pass the complete bilateral code-anchor gate;
- no family obtains a selected correction;
- the link-delta atlas is confirmed;
- a piecewise link/file map and actual runtime callees remain unestablished.

The result is bounded to a `±2048`-byte common correction and a 128-byte
fully-decoded SuperH shape. It does not exclude loader-created, section-relative
or wider non-local transforms.

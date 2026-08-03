# SPEC-039 - Registered-target literal-pool boundary

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 006, 027-030
- Related questions: RQ-086, RQ-090-RQ-099

## Purpose

Define how Phoenix distinguishes a function prefix from a PC-relative literal
pool containing a registered runtime-mapped target.

## Bounded run recovery

For one aligned registered target:

1. require a runtime-range word at the target;
2. extend backward and forward across contiguous runtime-range words;
3. stop after at most 16 words in either direction;
4. reject maximality when either bound is exhausted.

The report publishes file-relative boundaries, counts and target index only.
Raw pointer values are excluded.

## Literal-pool gate

A bounded run is a confirmed pool when:

- the target is a member of the maximal run;
- every word has exactly one PC-relative `MOV.L` referrer;
- every referrer precedes the pool;
- CD1/CD3 pool lengths agree;
- relative referrer offsets, loaded-register roles and modeled uses agree;
- pool starts and ends share one relocation delta.

The role signature excludes pointer values and instruction bytes.

## Pool-end successor rule

Code at the first byte after a confirmed pool may be promoted only to
`CONFIRMED_BILATERAL_STRUCTURAL_ADJACENCY` when both releases pass the strict
entry/code gates and normalized shapes agree.

It must not be called a runtime callee unless an independent inbound edge is
established. The current static inbound census includes:

- exact runtime-address word occurrences;
- PC-relative referrers to those occurrences;
- direct `BSR` targets.

A zero result excludes only those forms.

## Correction policy

When the registered target lies inside a confirmed pool:

- words between the target and pool end are a pool suffix, not a function
  prefix;
- entry-register conclusions from the adjacent successor do not apply to the
  unresolved runtime target;
- any callee, consumer or registration edge based only on adjacency must be
  withdrawn;
- loader/section metadata is disproved only for the local words proven to be
  PC-relative literals.

## Session 030 result

- two bilateral pools contain four and six words;
- every one of ten words per release has one preceding PC-relative referrer;
- relative use-role signatures agree across releases;
- every registered address occurs once as a literal feeding an indirect
  control target;
- CD3 target indices are one lower than CD1;
- pool boundaries relocate by 322,532 bytes;
- raw targets relocate by 322,528 bytes;
- the four-byte skew matches the one-word index shift;
- all four pool-end successors are equal strict code entries;
- none has an exact runtime-word reference or direct `BSR` target;
- actual handoff callees and entry-`r5` behavior remain open.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, pool counts and
indices, relative referrer offsets, use-role classes, normalized structural
hashes and evidence statuses. They must not contain firmware bytes,
instruction bytes, raw pointer values, absolute runtime addresses, raw
strings, local paths, map payloads or extracted resources.

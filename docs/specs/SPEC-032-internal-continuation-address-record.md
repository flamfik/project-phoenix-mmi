# SPEC-032 - Internal continuation and address-record contracts

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 022-023
- Related questions: RQ-064, RQ-065, RQ-066, RQ-067, RQ-068, RQ-069

## Purpose

Define a conservative method for following an address-taken location inside a
bounded owner window without converting that location into a function or
owner entry.

## Internal-label gate

Every selected address is reported relative to its registered owner start.
Phoenix decodes a maximum 128-byte window and records:

- first decoded instruction class;
- registers read before definition and before the first call;
- entry-prologue presence;
- bounded code-gate result;
- call and return counts.

Any positive relative offset remains an internal label unless independent
entry evidence exists. A decodable label or direct invocation is insufficient.

## Call contract

The enclosing call is recovered from the Session 022 use index. Phoenix traces
`r4` through `r14` and applies the delayed instruction before tracing call
arguments. Expressions are canonicalized to entry arguments, constants,
loads, additions, call returns and in-image pointers.

Preserved registers are included because an internal continuation may depend
on `r8`-`r14`; ordinary ABI arguments alone cannot describe such a target.

## Address-record helper

When the selected internal address is passed to another statically resolved
helper, Phoenix records:

- entry-`r4` long-word field geometry;
- code-gate, call, return and known-instruction metrics;
- modeled register mentions;
- a normalized fixed-word shape census.

Field values crossing branches remain path-merged and are not assigned a
single source.

## Cross-version family gate

The broad adjacent-call family reuses the fixed Session 018 gate:

- eight normalized words before the target load;
- the load and call pair;
- six normalized words after it;
- at least 90% dominant-target coverage;
- at least 32 unique opposite-release matches.

For each promoted family, `r5` is traced separately to count in-image address
arguments and unique targets. Promotion establishes only structural family
continuity; runtime equivalence and semantic purpose remain unasserted.

The selected non-adjacent use is tested independently with the same 16-word
context around its helper load.

## Session 023 status

- both Session 022 seeds are internal labels, not owner entries;
- the CD1 label is invoked with live preserved-register context;
- the CD3 label is passed as `r5` to a stack-local record helper;
- the helper writes six long-word fields at offsets
  `0, 4, 8, 12, 16, 24`;
- the broad family has 231 CD1 and 232 CD3 adjacent calls;
- every family call carries an in-image `r5` address;
- 215/232 CD3 contexts converge on one CD1 target, for 92.6724% coverage;
- the selected non-adjacent CD3 context has zero exact CD1 matches;
- landing-pad/frame/unwind registration is probable, not confirmed;
- owner-entry producer, state creator and runtime writer remain open.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, owner-relative
offsets, generated canonical expressions, normalized shape hashes, field
geometry, aggregate counts and evidence status. They must not contain firmware
or instruction bytes, absolute runtime addresses, raw strings, local paths,
map payloads or extracted resources.

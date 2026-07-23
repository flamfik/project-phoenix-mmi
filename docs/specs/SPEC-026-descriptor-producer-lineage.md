# SPEC-026 - Descriptor producer and field lineage

- Version: 0.1
- Maturity: DRAFT
- Evidence: Session 017
- Related questions: RQ-037, RQ-040, RQ-042, RQ-043, RQ-045, RQ-046,
  RQ-047, RQ-048, RQ-049

## Purpose

Define how Phoenix may extend a call-return-backed dynamic descriptor toward
its producer, accessor family and field initialization without inventing
object, vtable, method, optical or parser semantics.

## Producer-call rule

A producer candidate is the nearest preceding call in the same bounded
Session 016 context whose return may feed the registered descriptor path. The
report must include:

- producer and dispatch file-relative offsets;
- target expression and static-resolution status;
- delay-slot-aware `r4`-`r7` argument paths;
- bounded code evidence for the target;
- return expression and, when uniquely resolved, one child target;
- `function_boundary_asserted = false`;
- `path_dominance_asserted = false`.

Cross-version target promotion requires both target windows to pass the code
gate and to have equal normalized shape. Equal call position and argument
roles alone confirm only paired producer call sites.

## Field-12 accessor rule

An exact accessor occurrence must satisfy the documented eight-instruction
semantic sequence used by Session 017, including a 32-bit load from
`@(12,r4)`, bounded return and restored frame register. Occurrences may be
clustered, but cross-version cluster promotion requires:

- equal occurrence count;
- equal complete relative-gap vector;
- an explicit member ordinal for any proposed linkage.

This promotes accessor structure only. Class, owner and method semantics stay
open.

## Static descriptor census rule

The bounded static-record model interprets only:

- a signed 16-bit value at `base + 8` within `[-0x400, 0x400]`;
- an in-image big-endian 32-bit pointer at `base + 12`;
- optional direct references to the candidate base as an aligned runtime word.

Cross-version signatures may be compared only through independently accepted
optical target pairs. Raw occurrence or equal field roles do not establish
descriptor identity.

## Mixed-width initializer rule

A direct initializer candidate requires:

1. `MOV.W R0,@(disp,Rn)` writing effective offset `+8`;
2. `MOV.L Rm,@(disp,Rn)` writing effective offset `+12`;
3. the same base register;
4. at most `0x100` bytes between stores;
5. a bounded context containing both stores;
6. the independent executable-context gate to pass.

Only candidates passing all six conditions may be called code-gated direct
initializers. A zero result is bounded to this store model.

## Session 017 instance

- two paired producer call sites, one unique target pair;
- stable producer arguments `r4 = ENTRY:r4 + 8` or `+36`, `r5 = 0`;
- zero cross-version producer targets promoted because CD1 evidence fails the
  code gate and target shapes differ;
- one CD3 producer-to-field-12-accessor chain;
- 12 exact accessor occurrences per release and one paired six-member cluster;
- 20 of 31 optical target pairs with at least one matching static-record
  signature, but zero with a directly referenced candidate base in both
  releases;
- 18 paired analyzable mixed-width signatures and zero code-gated
  initializers.

The bilateral producer-to-accessor edge, actual descriptor identity, sector
ABI, buffer owner/provenance, FLDB parser and partition consumer remain open.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, normalized shape
hashes, expression paths, field widths/displacements, small constants,
aggregate counts and gate results. They must not contain firmware or
instruction bytes, runtime absolute addresses, raw strings, local paths, map
payloads or extracted resources.

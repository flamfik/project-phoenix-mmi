# SPEC-035 - CALL_RETURN producer-reference family

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 025-026
- Related questions: RQ-065, RQ-072, RQ-077-RQ-082

## Scope

This specification identifies the immediately preceding calls that supply the
shared `CALL_RETURN` root to the four Session 025 dispatches. It does not
identify a function, class, runtime-equivalent implementation or selected
owner target.

## Candidate gate

For each Session 025 candidate, Phoenix requires:

1. the published owner and consumer offsets reproduce;
2. target and `r4` slices both cross the nearest preceding call;
3. the producer target resolves in-image;
4. producer relative position, target expression, owner-relative target
   displacement and `r4`-`r7` arguments agree across releases;
5. returned-object target and receiver fields agree and retain a `+4` stride.

Only a candidate passing every bilateral condition becomes a confirmed
producer reference.

## Target-specific census

After the four candidates converge on one target per release, Phoenix may scan
only for adjacent PC-relative literal load plus `JSR` references to those exact
targets. Paired references are structural evidence when their sorted offsets
share the target relocation delta and their normalized contexts are equal.

This census remains syntactic and cannot establish executable coverage,
runtime invocation or callback registration.

## Session 026 result

- four of four candidate producer pairs pass;
- all resolve to one target per release;
- the target-specific family contains seven references per release;
- all seven bilateral contexts are normalized-equal and co-relocated;
- the four returned-object geometries use target fields `28`, `36`, `44`,
  `44`, with adjustment fields `24`, `32`, `40`, `40`;
- producer arguments are `ENTRY:r4`, `ENTRY:r5`, `CONST:0`, `ENTRY:r7`.

The target windows fail the bounded code gate and have unequal normalized
shapes. Function identity, runtime equivalence, object type/writer and
selected-owner target registration remain open.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, generated
expressions, field displacements, normalized-context hashes and aggregate
counts. They must not contain firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

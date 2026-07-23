# SPEC-033 - Owner-entry indirect-caller compatibility

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 016-017, 022-024
- Related questions: RQ-065, RQ-070, RQ-071, RQ-072, RQ-073

## Purpose

Define a conservative gate for testing a memory-loaded indirect-call contract
against the runtime entry arguments consumed by a selected owner pair.

The gate can exclude an incompatible call family. It cannot establish a
concrete target, function boundary, object type or runtime caller by shape
alone.

## Owner entry contract

Required entry arguments are derived from the Session 022 memory-base
profiles. An argument is required only when its `ENTRY:rN` root occurs in both
members of one selected owner pair.

For both current owner pairs the bilateral contract is:

```text
r4 = runtime-provided object/state root
r6 = second runtime-provided base used at +2
```

The semantic types of both arguments remain unknown. Shared use does not prove
that the two owners receive the same object instance.

## Candidate boundary

Session 024 tests only the two dynamic descriptor contracts registered by
Session 016 and refined by Session 017. They have:

- a target loaded through a `CALL_RETURN`-rooted memory path ending at field
  `12`;
- an `r4` receiver derived from the same call-return object and a field path
  containing `8`;
- delayed selector `r5 = 3`.

No arbitrary whole-image indirect-call scan is permitted by this
specification. Data regions are not decoded speculatively as code.

## Fixed signature census

Each seed call is represented by 16 normalized SH words:

- eight words before `JSR`;
- the `JSR`;
- seven words after it.

PC-relative displacements and branch displacements are normalized using the
existing Phoenix rule. Matches are anchored only on the modeled SH
`JSR @Rn` encoding. A signature match is syntactic evidence, not an executable
map or semantic target.

## Compatibility gate

A candidate remains compatible with an owner pair only when all conditions
hold in both releases:

1. target expressions are canonically equal;
2. every required owner argument has a modeled source at the call;
3. each required argument has an equal canonical expression across releases;
4. no required source contains `CALLER_SAVED_CLOBBER`, `NO_DEFINITION`,
   `DEPTH_LIMIT` or `CYCLE`;
5. an independently justified unique target family exists.

Failure of any condition is a bounded exclusion. Passing the gate would still
be structural only until the target is resolved and independently linked to
the selected owner entry.

## Session 024 status

- two registered candidate contracts were tested;
- both signatures are equal between CD1 and CD3;
- each signature occurs exactly once in each principal image;
- both candidates retain equal target and `r4` expressions;
- `r6` is `CALLER_SAVED_CLOBBER` in every tested bilateral contract;
- zero candidate/owner-pair combinations pass the argument gate;
- the Session 016 call-return/field-load family is excluded as the caller of
  the selected owners under this bounded model;
- no unique incoming caller, entry-argument producer or state creator is
  established.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, generated
canonical expressions, root classes, normalized-context counts and evidence
status. They must not contain firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

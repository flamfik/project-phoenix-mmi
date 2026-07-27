# SPEC-034 - Producer-first owner-caller candidates

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 021, 024-025
- Related questions: RQ-065, RQ-072, RQ-074, RQ-075, RQ-076,
  RQ-077, RQ-078

## Purpose

Define a bounded search for indirect-call contexts that can supply the
bilateral `r4`/`r6` owner-entry contract established in Session 024.

The result is a candidate set. Equal arguments and target expressions do not
prove that an unresolved memory-loaded call enters either selected owner.

## Registered code boundary

Session 025 reproduces the Session 021 pointer-zero owner census and decodes
only owner windows that satisfy all of these conditions:

1. the owner contains a literal-backed call to an active pointer-zero slot;
2. its bounded code gate passes;
3. its start is backed by the latest modeled `STS.L PR,@-R15` prologue;
4. its exact normalized owner shape occurs in both firmware releases.

No arbitrary raw-image instruction sweep is performed. The global
literal-call census remains syntactic and is used only to reconstruct the
previously registered owner set.

## Local producer-first gate

For every indirect `JSR @Rn` inside an admitted owner window, Phoenix traces:

- the target-register expression;
- delayed-call arguments `r4` and `r6`;
- the last preceding call;
- the closest explicit definition of each required argument;
- expression roots and memory-load paths.

A local contract passes only when:

1. the target is an unresolved memory-loaded expression;
2. both `r4` and `r6` have explicit definitions after the last preceding
   call, including the current call's delay slot;
3. neither argument contains `CALLER_SAVED_CLOBBER`, `NO_DEFINITION`,
   `DEPTH_LIMIT`, `CYCLE`, `UNSUPPORTED_WRITE` or `UNKNOWN`.

## Bilateral family gate

Contracts are grouped by:

- exact shared owner-shape SHA-256;
- relative instruction index of the indirect call.

A family is promoted as an argument-compatible structural candidate only when
both releases contain an available contract and each side converges on one
identical canonical tuple:

```text
(target expression, r4 expression, r6 expression)
```

Promotion does not establish a concrete target, runtime equivalence, function
boundary, selected-owner edge or object type.

## Session 025 status

The Session 021 registry reproduced exactly:

| Metric | CD1 | CD3 |
|---|---:|---:|
| Active pointer-zero targets | 199 | 112 |
| Active pointer-zero calls | 1,567 | 319 |
| Prologue/code-gated owners | 1,206 | 243 |
| Exact accepted owner shapes | 485 | 184 |
| Instances in 29 shared shapes | 235 | 44 |

The producer-first funnel is:

| Gate | CD1 | CD3 |
|---|---:|---:|
| Indirect `JSR` in shared owner instances | 351 | 161 |
| Unresolved memory-loaded targets | 26 | 26 |
| Explicit `r4`/`r6` after last call | 12 | 12 |
| Available `r4`/`r6` provenance | 4 | 4 |

All twelve explicit positions are bilateral. Eight are rejected for
unavailable argument provenance. Four converge on equal bilateral contracts:

- target field `28`, receiver adjustment input `24`, `r6 = 0`;
- target field `36`, receiver adjustment input `32`, `r6 = 0`;
- two contexts with target field `44`, receiver adjustment input `40`,
  `r6 = ENTRY:r7`.

Every target remains rooted in a prior call return and memory loads. No target
is linked to either selected owner entry.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, generated
canonical expressions, root classes, load displacements, shape hashes,
aggregate counts and evidence status. They must not contain firmware or
instruction bytes, absolute runtime addresses, raw strings, local paths, map
payloads or extracted resources.

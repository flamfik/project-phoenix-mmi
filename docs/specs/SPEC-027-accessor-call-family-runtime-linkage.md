# SPEC-027 - Accessor call family and zero-tail runtime slot

- Version: 0.1
- Maturity: DRAFT
- Evidence: Session 018
- Related questions: RQ-026, RQ-037, RQ-040, RQ-042, RQ-046, RQ-047,
  RQ-050, RQ-051, RQ-052

## Purpose

Define how Phoenix may pair a known accessor's literal-backed call sites
across firmware releases and classify a non-code static target without
inventing callback, trampoline, optical, parser or ABI semantics.

## Literal-call rule

A raw candidate must have adjacent big-endian SH forms:

```text
MOV.L @(disp,PC),Rn
JSR   @Rn
```

The literal must resolve to an in-image address. This is a raw census only.
Code semantics require an independently known target or a later context gate.

## Target reference profile

For one registered target the analyzer reports:

- exact and aligned word occurrences;
- exact PC-relative load references;
- adjacent same-register `JSR` count;
- distinct literal-pool occurrences used by those calls;
- aligned occurrences not used as PC-relative literals.

Only the last class may seed the direct static registration-record model.

## Cross-version context gate

The context contains eight words before the load, the load/call pair and six
words after it: 16 words total. Normalization masks only:

- PC-relative load displacements;
- direct branch/call displacements;
- conditional branch displacements;
- `MOVA` displacements.

Registers, immediates, field displacements and other opcodes remain exact.

A call family is promoted only when:

- at least 32 right-side contexts have a unique left match;
- one left target receives consensus from at least 90% of all registered
  right-side accessor calls.

Promotion means `CONFIRMED_BOUNDED_TARGET_CONVERGENCE`. It explicitly sets
`runtime_equivalence_asserted = false`.

## Zero-tail record-run rule

A structural record is exactly 16 bytes:

- one in-image 32-bit pointer at `+0`;
- twelve zero bytes at `+4`.

The selected target must fall inside the zero tail. Adjacent records are
included only while the exact grammar remains valid. The report may publish
file-relative run bounds, record count, target ordinal/offset and pointer-
target deltas. It may not label the run as executable or patched without a
specific writer or loader.

## Direct callback-record gate

A direct static callback search may proceed only from aligned target words not
used by PC-relative loads. When this data-only set is empty, the result is
`NOT_FOUND_UNDER_DIRECT_TARGET_WORD_MODEL`. Encoded, copied and runtime-created
registrations remain outside the result.

## Registered graph-intersection gate

Each Session 015 paired node is decoded with its existing bounded window. A
bilateral intersection requires:

1. the known CD3 accessor call inside the right node window;
2. at least one context-matched CD1 call inside the paired left node window.

Without both conditions no optical or navigation edge is promoted.

## Session 018 instance

- paired CD1 accessor: zero exact references;
- CD3 accessor: 288 aligned literal words, 290 PC-relative loads and 288
  adjacent calls;
- fixed context result: 179 unique, 101 ambiguous and eight unmatched calls;
- 266/288 contexts (92.3611%) converge on one CD1 target;
- dominant CD1 target: 286 literal words, 287 loads and 286 adjacent calls;
- dominant target lies at `+8` in the second of five `pointer + 12 zero`
  records; pointer-target deltas are four repetitions of `-576`;
- data-only target occurrences: zero;
- bilateral intersections with 35 registered graph nodes: zero.

Runtime patch/trampoline semantics, the specific Session 017 producer edge,
callbacks, sector ABI, optical buffer owner/provenance, FLDB parser and
partition consumer remain open.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, aggregate counts,
context dimensions, thresholds, record widths, target deltas and evidence
statuses. They must not contain firmware or instruction bytes, absolute
runtime addresses, raw strings, local paths, map payloads or extracted
resources.

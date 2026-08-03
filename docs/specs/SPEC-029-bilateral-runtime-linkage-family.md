# SPEC-029 - Bilateral runtime-linkage family

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 018-020
- Related questions: RQ-051, RQ-053, RQ-054, RQ-055, RQ-056, RQ-057,
  RQ-058

## Purpose

Define how Phoenix pairs pointer-plus-zero-tail record runs across firmware
releases, counts their syntactic use and searches bounded loader models without
promoting zero-filled data to executable code or runtime-linkage semantics.

## Record grammar

A candidate record is exactly 16 bytes:

```text
+0x00  big-endian in-image runtime pointer
+0x04  zero
+0x08  zero
+0x0C  zero
```

Records are four-byte aligned. Consecutive records form a run. This grammar is
structural only.

## Cross-version pairing gate

A right-side run is a normalized candidate for a registered left-side run only
when all of the following are equal:

- record count;
- pointer-target delta vector;
- first pointer target relative to the run start.

The pair is promoted only when exactly one right-side candidate exists.
Pointer translation is independently confirmed when the right-minus-left
translation of every pointer target equals the run-start translation.

The Session 020 instance is a unique five-record pair. The start and all five
pointer targets translate by `+324,860` bytes.

## Syntactic activity rule

Each of the three zero words in every record is tested as a file-relative
target. A word is syntactically active when an adjacent PC-relative `MOV.L`
followed by same-register `JSR` selects its runtime address.

No code gate is assigned to the zero word and no execution is implied. The
selected run changes from three active words and 909 forms in CD1 to one active
word and four forms in CD3.

## Global-family census

Phoenix reports:

- all adjacent literal/JSR forms;
- unique targets;
- targets whose four on-disk bytes are zero;
- pointer-zero runs;
- active pointer-zero runs;
- covered and uncovered zero targets;
- a call-count histogram.

The census is explicitly syntactic. It is suitable for prevalence and
release-to-release comparisons, not for asserting a global linker, callback
table or executable overlay.

## GBR writer gate

The bounded GBR model:

1. recognizes register and memory-load GBR initializers;
2. resolves only register initializers whose source is recoverable within 64
   linear instructions from a PC-relative long or `MOVA`;
3. preserves all valid runtime, raw-file and METAINFO-flash address facts;
4. scans no more than 512 following bytes;
5. accepts only byte, word or long GBR stores whose destination lies inside
   the selected run.

Memory-loaded GBR bases, branch dominance and interprocedural state are not
modeled.

## Helper-mediated destination gate

The helper model begins only at a PC-relative literal that resolves exactly
inside the selected run. It follows register copies and immediate adds for at
most 64 instructions. A candidate requires the address in `r4`-`r7` when an
indirect call uses a different register.

The helper's identity and write semantics remain unasserted even if a
candidate is found.

## Coherent copy-table gate

A record is an aligned `source, destination, length` triple. It must have:

- in-image source and destination ranges;
- different source and destination starts;
- a four-byte-aligned length from four bytes through one MiB;
- no range overflow.

A table requires at least two consecutive records and one
source-model/destination-model pair common to every record. Its start must be
selected by a PC-relative long-load reference. A writer candidate additionally
requires at least one coherent destination range to overlap the selected run.

This strict grammar rejects nearby constants that only resemble independent
triples.

## Cache-marker gate

Five exact, predefined cache-maintenance API names are searched. Generated
reports disclose only the number tested and matched; marker text and extracted
strings are excluded.

Absence applies only to exact ASCII markers. Stripped, indirect, ordinal and
inlined implementations remain open.

## Session 020 status

The bilateral run and equal translation are confirmed. All declared GBR,
helper, referenced coherent-copy and named cache-marker writer models return
zero candidates. The strongest permitted runtime statement is:

`HYPOTHESIS_STRENGTHENED_BY_BILATERAL_RESIDENT_LAYOUT`

A specific writer, loader, trampoline, patch, overlay or linkage mechanism is
not confirmed.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, translation
deltas, aggregate counts, address-model labels, bounded thresholds and
evidence statuses. They must not contain firmware or instruction bytes,
absolute runtime addresses, raw strings, local paths, map payloads or extracted
resources.

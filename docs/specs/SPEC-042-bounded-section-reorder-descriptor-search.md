# SPEC-042 - Bounded section-reorder descriptor search

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 006, 020, 032-033
- Related questions: RQ-103, RQ-106, RQ-108-RQ-111

## Purpose

Define a reproducible negative-evidence gate for static
`source/destination/length` tables near a previously confirmed cross-release
section reorder.

## Input gate

The input comparison must:

- use the Session 032 relocation-breakpoint schema;
- reproduce both principal-image hashes;
- contain exactly one `SECTION_REORDER_BRACKET`;
- identify both adjacent support zones;
- state that right-side order is non-monotonic.

## Seed grammar

For each support zone, Phoenix derives:

- exact start and end;
- start/end rounded down and up to 4, 256 and 4,096 bytes;
- exact length;
- enclosing lengths at the same three alignments.

Boundary values are encoded under only:

- raw file offset;
- METAINFO `FlashStartAddress`;
- confirmed runtime-link base.

Scalar lengths have no address base. Seed derivation is closed and independent
of firmware contents.

## Record grammar

The tested records are:

- three big-endian words in 12 bytes;
- the same three words plus one closed trailing flag in 16 bytes;
- all six field permutations;
- one source model and one destination model for the complete run;
- lengths from 4 bytes through 4 MiB, divisible by four;
- in-image source and destination intervals.

## Promotion gate

A per-release candidate requires:

- at least two adjacent valid records;
- a closed seed from each support zone;
- complete interval coverage of each zone;
- non-overlapping source intervals;
- non-overlapping destination intervals;
- at least one in-bounds syntactic PC-relative `MOV.L` form resolving to the
  table start.

A bilateral pair additionally requires equal:

- record width and field order;
- source/destination model pair;
- record count;
- length and trailing-flag vectors;
- zone coverage roles and relative coverage geometry.

Passing this gate yields `PROBABLE_BILATERAL_STRUCTURAL`, not confirmed runtime
copy semantics. The `MOV.L` census is syntactic and is not a whole-image code
or execution gate.

## Negative result

`CLOSED_BOUNDED_NEGATIVE` is valid only for the declared seeds, address models,
record widths, field permutations, flag set, length range and PC-relative
reference model.

It cannot exclude variable-width, encoded, compressed, indirect, computed or
external metadata. It also cannot distinguish an unmodeled loader from a
compile/link-time layout change.

## Session 033 result

- CD1: 223,112 bounded attempts, 1,750 valid seeded single records and 438
  multi-record interpretations;
- CD3: 393,616 bounded attempts, 3,896 valid seeded single records and 604
  multi-record interpretations;
- zero coherent two-zone candidates in either image;
- zero referenced promoted candidates;
- zero bilateral descriptor pairs.

The descriptor-table model is closed bounded-negative. The exact boundary and
mechanism remain open.

## Publication contract

Reports may contain hashes, file-relative offsets, zone IDs, generated
candidate IDs, address-model names, widths, counts, histograms, relative
geometry and evidence statuses.

They must not contain firmware bytes, instruction bytes, raw pointer values,
absolute runtime addresses, raw strings, local paths, map payloads or extracted
resources.

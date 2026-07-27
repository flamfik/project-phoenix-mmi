# SPEC-041 - Relocation-anchor zones and breakpoints

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 005, 008, 009, 015, 030-032
- Related questions: RQ-098, RQ-103-RQ-108

## Purpose

Define how Phoenix combines independently validated bilateral anchors into a
sparse file-layout model without inventing a continuous runtime/file mapping.

## Evidence classes

### Direct-link bilateral bounded code

A record or call literal already resolved by Session 015 is revalidated at its
declared CD1/CD3 file offsets. Both bounded windows must pass the code gate.

The anchor proves:

- the runtime link value resolved to the declared file offset in that release;
- both offsets contain bounded code.

It does not prove equal implementation, semantic identity or runtime
equivalence unless separately established.

### Byte-identical data region

A region is accepted only when offsets, length, raw equality and the prior
SHA-256 all agree. Mapping is continuous only inside the half-open declared
interval.

### Constant-delta ordered marker band

Every paired marker in the source band shares one relocation delta and the
source structural status is confirmed. The band supports marker positions, not
all bytes between its endpoints.

## Code plateau gate

A code plateau requires at least two consecutive direct-link anchors with:

- identical delta;
- distinct offset pairs;
- left-side gap no larger than 65,536 bytes.

The plateau confirms the delta at its anchor points. Interpolation is explicitly
false.

## Cross-class gate

A marker band and direct-link code anchor support one cross-class delta only
when:

- their relocation deltas are identical;
- the code point lies inside or no more than 131,072 bytes from the band.

Cross-class agreement strengthens the delta but does not create continuous
mapping through the gap.

## Breakpoint bracket

Adjacent non-overlapping support zones with different deltas produce a bracket:

- `MONOTONIC_DELTA_CHANGE_BRACKET` when right-side order is retained;
- `SECTION_REORDER_BRACKET` when right-side order moves backward.

The bracket reports bounds and width. It never selects an exact breakpoint.

## Pool reconciliation

Pool pairs are reconstructed privately from the Session 030 images and must
reproduce Session 031 pair IDs, deltas, roles and occurrences.

The public status precedence is:

1. exact prior direct-code pair identity;
2. exact relative position inside a byte-identical region;
3. confirmed marker-band coverage;
4. equal-delta position inside a code plateau, retained as an unpromoted
   interpolation candidate;
5. delta-family equality without pair identity;
6. no prior coverage.

Raw values and absolute runtime addresses are never published. Delta equality
alone cannot establish target identity.

## Session 032 result

- 27 direct-link code anchors revalidate;
- 15 direct-code delta families and six local plateaus are present;
- two exact data regions cover 86,505 bytes;
- 15 constant marker bands cover 405 marker pairs;
- three cross-class agreements pass;
- 23 support zones produce 19 breakpoint brackets;
- one bracket proves a section reorder;
- zero of eight pool pairs match an exact prior anchor;
- two pool pairs share only delta `323440` with one direct anchor;
- continuous mapping and loader behavior remain open.

## Publication contract

Reports may contain artifact hashes, generated IDs, file-relative offsets,
lengths, deltas, counts, structural hashes, evidence classes and gate results.
They must not contain firmware bytes, instruction bytes, raw pointer values,
absolute runtime addresses, raw strings, local paths, map payloads or extracted
resources.

# SPEC-015 - Navigation dataflow and bounded call-site windows

- Version: 0.1
- Maturity: ALPHA
- Evidence: Sessions 006, 009 and 010
- Related questions: RQ-009, RQ-022, RQ-025, RQ-026, RQ-027

## Purpose

This specification defines the strongest call/dataflow statement currently
permitted for the principal image. It separates an exact code reference from a
function name, an object-dispatch guess or a complete navigation-to-disc path.

## Fixed anchor model

Session 010 searches only a predeclared vocabulary. A match is published as an
anchor ID, category, semantic substring offset and length. The source string is
never included. Matching begins at the semantic substring because printable
extraction can absorb preceding bytes that happen to be printable.

## Exact linked-word reference

For anchor file offset `A` under the confirmed Session 006 runtime model:

```text
linked_word = big_endian_u32(0x0C000000 + A)
```

Only four-byte-aligned occurrences are accepted. A code reference exists only
when the SH-3 decoder independently computes that exact word offset for a
PC-relative `MOV.L` instruction.

## Bounded call-site window

The default analytical window is `0x40` bytes before and `0x80` bytes after the
reference. It is not a function boundary. The report contains:

- window offsets and decoded/unknown instruction counts;
- mnemonic and control-flow histograms;
- a normalized instruction-shape SHA-256;
- direct relative call targets, where decoded;
- conservative indirect-call targets.

An indirect target is resolved only for this adjacent pattern:

```text
MOV.L @(literal,PC),Rn
JSR   @Rn
```

The same register must be used and the linked target must map inside the flat
image. Non-adjacent register flow and object/vtable dispatch remain unresolved.

## Cross-release result

The internal navigation-data anchor has two PC-relative referrers in each
release. The corresponding bounded windows have equal normalized instruction
shapes. Across those two pairs, six adjacent indirect-call pairs resolve:

- three target pairs retain equal normalized target-window shapes and relocate
  by the same local navigation-region delta;
- three target pairs relocate by a second common delta into marker-adjacent
  runtime regions, but their target-window shapes differ between releases.

The second group is classified only as
`CONFIRMED_PROXIMITY_WITH_OPEN_FUNCTION_SEMANTICS`. Proximity to storage markers
does not prove a sector read, file open, allocation service or optical-manager
call.

## Required interpretation

`CONFIRMED_CROSS_VERSION_CODE_COUPLED_ROUTINE_PAIR` means that the same fixed
anchor participates in two structurally stable call-site windows in both
releases. It does not identify the function name, ABI, object owner, buffer
schema or external-media source.

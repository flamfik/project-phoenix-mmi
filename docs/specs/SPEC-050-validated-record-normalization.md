# SPEC-050 - validated record normalization

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 040-041
- Related questions: RQ-150-RQ-157

## Purpose

Define which update record containers may be converted into
address-contiguous private byte regions before repeating a firmware homolog
search.

## Global rules

- verify registered source and principal-image hashes;
- reconstruct only checksum-valid records with known address semantics;
- reject conflicting overlaps;
- never fill address gaps;
- never bridge opaque physical-envelope bytes;
- keep decoded bytes and address values private;
- preserve the Session 040 target and control without adaptation.

## Intel HEX

Every line must:

- start with a colon;
- contain an even number of ASCII hexadecimal characters;
- contain at least count, address, type and checksum fields;
- satisfy the declared byte count;
- have an eight-bit sum of zero.

Supported standard types are `0x00` through `0x05`. Data records may not
cross a 16-bit address window. Exactly one valid EOF record is required, and
no record may follow it.

Types `0x10` and `0x11` are allowed only when all conditions hold:

```text
record index = 0
count = 4
address field = 0
occurrence count = 1
checksum valid
```

Their payload is opaque metadata. It does not modify address state and is not
included in decoded bytes.

## Motorola S-record

Each accepted record must:

- begin at a physical line boundary;
- use ASCII `S` plus a supported numeric type;
- contain an even hexadecimal body;
- satisfy its byte count;
- satisfy the one's-complement checksum.

Data types `S1`, `S2` and `S3` and matching termination types `S9`, `S8` and
`S7` are recognized.

Decoded data records may be joined only when:

- decoded addresses are exactly contiguous;
- the physical gap is exactly one LF or one CRLF sequence.

Any invalid candidate or opaque envelope material splits the decoded region.
One matching final termination record is mandatory.

## Unsupported binary containers

`.LOD` and `.YIM` receive no decoder until independent structural evidence
defines their header, record lengths, address model and integrity checks.
Their raw bytes are not rescanned by this normalization stage.

## Search inheritance

Every decoded region of at least 240 bytes is searched with the unchanged
five-anchor target and equal-geometry control from SPEC-049. Thresholds and
saturation limits are inherited without modification.

## Session 041 result

- 215 members and 27 unique source contents;
- 16 fully validated Intel HEX contents;
- one partially validated Motorola S-record source;
- ten unsupported `.LOD`/`.YIM` contents;
- 3,109 unique decoded regions;
- 3,012 scannable regions;
- 3,570,586 unique decoded bytes;
- zero target and control first-anchor occurrences;
- zero geometry, strong or saturated results.

## Interpretation boundary

The result cannot exclude:

- unsupported `.LOD` or `.YIM` content;
- compressed or encrypted data;
- relocation-normalized variants;
- split data whose gaps have unknown semantics;
- externally supplied loader/link material;
- runtime-created content.

## Publication contract

Reports may contain artifact hashes, source sizes, extensions, format and
record counts, checksum status, decoded-region sizes and counts, entropy,
ratios and conservative classifications.

They must not contain firmware, payload, decoded-region, component or
signature bytes; signature or decoded-payload hashes; raw strings;
instruction bytes; mnemonic names; pointer values; address values; absolute
runtime addresses; local paths; extracted resources or map payloads.

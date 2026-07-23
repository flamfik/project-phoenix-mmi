# SPEC-017 - Navigation optical volume

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 011
- Related questions: RQ-022, RQ-026, RQ-028

## Scope

This specification describes only the outer optical-volume structure of the
registered Session 011 navigation artifact. It does not authenticate the image,
define FLDB payload semantics or establish vehicle compatibility.

## Descriptor sequence

The validated sequence is:

| Sector | Type | Meaning |
|---:|---:|---|
| 16 | 1 | Primary Volume Descriptor |
| 17 | 2 | Supplementary Volume Descriptor with Joliet `%/E` escape |
| 18 | 255 | Volume Descriptor Set Terminator |

The logical block size is 2,048 bytes. Both-endian numeric fields must agree;
disagreement is a parse failure.

## Topology invariants for the registered artifact

- declared volume blocks: 1,255,395;
- artifact and declared volume size: 2,571,048,960 bytes;
- root files: seven;
- root subdirectories: zero;
- first file extent: sector 25;
- outer extents: contiguous;
- final extent end: declared end of volume;
- UDF recognition markers: not detected in sectors 16-255.

Outer names are private research data. Public reports expose generated member
IDs and only `db` / `db-underscore` suffix classes.

## Provenance rule

The volume identifier is published only as a hash, parsed pattern and timestamp
candidate. System/application identifiers are published only as hashes or fixed
authoring-family markers.

An authoring-tool marker or plausible timestamp is not evidence of an original
OEM master. The registered image remains `UNVERIFIED_LOCAL_RESEARCH_ARTIFACT`.

## Parser requirements

An implementation must:

1. read only;
2. enforce sector bounds;
3. validate descriptor identifiers and versions;
4. validate both-endian volume fields;
5. avoid extracting members during inventory;
6. omit names, raw identifiers and local paths from public output.

Reference implementation: `phoenix_mmi.iso9660` and
`phoenix_mmi.map_media`.

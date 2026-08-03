# SPEC-089 - Font candidate validation

- Version: 1.0
- Maturity: BETA
- Evidence: Session 081
- Related questions: RQ-311-RQ-314

TrueType/OpenType candidates require a valid SFNT search header, unique
aligned bounded tables, the `cmap`, `head`, `maxp` and `name` tables, and the
canonical `head` magic. Four TrueType containers satisfy this contract in
both principal images. Consumer and glyph semantics are not established.

# SPEC-079 - Generic structural diff

- Version: 1.0
- Maturity: BETA
- Evidence: Session 071
- Related questions: RQ-271-RQ-274

Schema `phoenix-mmi.structural-diff/v1` compares JSON-compatible mappings,
ordered lists and scalar values recursively. Paths use JSON Pointer escaping.
Keys are traversed in lexical order and arrays in ordinal order.

Changed scalar values are omitted and represented by truncated SHA-256
digests. A reported change is structural evidence only, not a semantic claim.

# SPEC-077 - Normalized parser result

- Version: 1.0
- Maturity: BETA
- Evidence: Session 069
- Related questions: RQ-263-RQ-266

Schema `phoenix-mmi.parse-result/v1` contains parser and family identifiers,
classification, validation state, source and consumed sizes, ordered regions,
diagnostics and deterministic metrics.

Regions expose offset, optional decoded address, size, digest and role.
Decoded bytes are opt-in and excluded by publication defaults. LOD parsing is
bounded structural topology only and leaves record, address and integrity
models false.

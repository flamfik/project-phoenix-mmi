# SPEC-064 - LOD fill topology

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 056
- Related questions: RQ-204-RQ-206

## Contract

Runs are selected with frozen thresholds: zero at least 4,096 bytes and
`0xFF` at least 128 bytes. No threshold is retuned per language.

## Result

All five sources expose the same `FF -> ZERO -> ZERO` sequence and therefore
four structural regions. Region semantics and address relationships are not
assigned.

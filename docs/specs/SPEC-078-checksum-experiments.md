# SPEC-078 - Declarative checksum experiments

- Version: 1.0
- Maturity: BETA
- Evidence: Session 070
- Related questions: RQ-267-RQ-270

An experiment has a unique ID, named algorithm, explicit region ID, offset,
length and optional expected value. Regions outside the input fail closed.
Results are `MATCH`, `NO_MATCH` or `OBSERVED`.

The v1 algorithm set is CRC32/IEEE, Adler-32 and SUM16. The framework neither
assigns unknown vendor algorithms nor changes the blocked status of YIM
integrity and METAINFO `MetafileChecksum`.

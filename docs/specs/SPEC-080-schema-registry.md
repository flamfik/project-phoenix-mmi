# SPEC-080 - Schema registry

- Version: 1.0
- Maturity: BETA
- Evidence: Session 072
- Related questions: RQ-275-RQ-278

The registry maps exact schema IDs to required fields and optional strict
validators. Unknown schemas and absent schema fields fail closed. Validation
returns a stable result with schema ID, validity and errors.

V1 registers artifact manifest, parse-result, checksum-experiment and
structural-diff schemas. Validation confirms structure and invariants, not the
truth of research conclusions.

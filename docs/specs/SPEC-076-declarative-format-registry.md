# SPEC-076 - Declarative format registry

- Version: 1.0
- Maturity: BETA
- Evidence: Session 068
- Related questions: RQ-259-RQ-262

Rules have stable IDs, families, categories, priorities, confidence classes,
optional extensions and magic constraints, minimum sizes and named
validators. Evaluation order is priority descending and rule ID ascending.

Positive complex formats require structural validation. LOD suffix routing
returns `OPAQUE_ROUTED` and cannot be promoted to decoded status. Registry
serialization is schema `phoenix-mmi.format-registry/v1`.

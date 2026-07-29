# SPEC-103 - Phoenix UI information architecture

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 094
- Related questions: RQ-366-RQ-370

The Session 094 schema contains five ordered screens and 16 ordered,
focusable entries. `home` is the only root. Communication, media, navigation
and settings are synthetic section screens reached through four explicit,
acyclic navigation edges.

Screen and entry identifiers are unique, labels use original
`phoenix.*` tokens, and every non-root screen is reachable from its declared
parent. Only `STATIC_ORIGINAL` and `SYNTHETIC` data sources are allowed.
Service bindings, layout geometry and reducer behavior are prohibited at this
stage.

The schema is an original host prototype and must not be described as a
reconstruction of the MMI firmware menu.

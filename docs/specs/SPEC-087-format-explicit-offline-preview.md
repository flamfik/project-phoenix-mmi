# SPEC-087 - Format-explicit offline preview

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 079
- Related questions: RQ-303-RQ-306

Offline preview accepts a decoded 16-bit raster, validated dimensions and an
explicit candidate layout. It emits bounded PPM bytes into a private output
area. Public reports contain only dimensions, candidate names and counts.

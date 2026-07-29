# SPEC-109 - UI quality gate

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 100
- Related questions: RQ-391-RQ-395

The host quality gate contains eight independent criteria covering viewport
bounds, focus visibility, text and focus contrast, minimum target size,
complexity, asset provenance, renderer safety and repeated-run determinism.
All 16 base focus states must render exactly one focus indicator.

Passing the gate establishes only the declared offline-prototype invariants.
It must not be used as evidence for target performance, display quality,
driver distraction requirements or vehicle suitability.

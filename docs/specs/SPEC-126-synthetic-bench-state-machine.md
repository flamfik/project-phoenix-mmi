# SPEC-126 - Synthetic bench state machine

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 117
- Related questions: RQ-464-RQ-467

The pure state machine enforces ordered identity, electrical, recovery, risk
and capture gates before a power-candidate state. Normal flow ends sealed;
abort flow removes the power candidate and enters an immutable abort-locked
state. The model has no hardware I/O and proves control logic only.

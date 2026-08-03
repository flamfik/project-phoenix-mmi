# SPEC-072 - M1 evidence traceability

- Version: 0.1
- Maturity: BETA
- Evidence: Session 064
- Related questions: RQ-235-RQ-238

## Contract

The audit requires the declared Session, SPEC and RQ identifier sets, a
documented Session 043 gap, parseable publication-safe JSON and all newcomer
entrypoints.

The output subtree `research/milestones/m1` is excluded from its own input
corpus. This prevents a report-count feedback loop and makes reruns
deterministic.

Missing files, unexpected gaps or invalid JSON fail the M1 documentation gate.

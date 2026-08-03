# SPEC-094 - Bounded IPC evidence

- Version: 1.0
- Maturity: BETA
- Evidence: Session 086
- Related questions: RQ-331-RQ-334

Fixed VxWorks message-queue, semaphore, event and watchdog probes are tested
with identifier boundaries and exact address-reference checks. A negative
probe result is retained explicitly and does not prove IPC absence.

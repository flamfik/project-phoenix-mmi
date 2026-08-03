# SPEC-081 - Unified read-only CLI

- Version: 1.0
- Maturity: BETA
- Evidence: Session 073
- Related questions: RQ-279-RQ-282

The CLI dispatches `manifest`, `classify`, `parse`, `checksum`, `diff`,
`validate` and legacy `analyze`. New direct artifact reads use the SDK safety
limit. Commands return zero on success and two for handled validation or input
errors.

No command mutates a source, builds update media, installs artifacts, executes
firmware or communicates with a vehicle.

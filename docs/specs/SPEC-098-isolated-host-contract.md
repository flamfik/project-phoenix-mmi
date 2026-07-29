# SPEC-098 - Isolated host runtime contract

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 090
- Related questions: RQ-347-RQ-350

The host harness is a deterministic metadata FIFO with bounded per-service
queues. It retains no payload bytes and provides no clock, thread, filesystem,
network, CAN/MOST or vehicle interface. It is not a firmware emulator.

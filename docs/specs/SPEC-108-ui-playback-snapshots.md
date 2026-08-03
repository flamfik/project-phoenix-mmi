# SPEC-108 - UI playback and snapshots

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 099
- Related questions: RQ-387-RQ-390

The playback engine applies a fixed sequence of 19 abstract actions to the pure
reducer and hashes the resulting 19 SVG snapshots. Sequence numbers are
monotonic, all five model screens are visited and the aggregate playback
fingerprint must be identical across repeated runs.

Playback requires no filesystem, network, firmware, vehicle or protected
service. Snapshot order and hashes validate host determinism only; they do not
establish physical input mapping or target timing.

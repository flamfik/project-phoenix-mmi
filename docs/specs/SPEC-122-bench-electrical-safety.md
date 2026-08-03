# SPEC-122 - Bench electrical safety

- Version: 1.0
- Maturity: ALPHA
- Evidence: Session 113
- Related questions: RQ-448-RQ-451

Power planning requires regulated current limiting, an independent cutoff,
source fuse, verified polarity, one documented ground reference and visible
measurement. Pinout, voltage, current and fuse values must come from an
authoritative device-specific reference; the SDK refuses guessed numeric
values and never authorizes power.

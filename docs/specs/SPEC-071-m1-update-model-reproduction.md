# SPEC-071 - M1 update-model reproduction

- Version: 0.1
- Maturity: BETA
- Evidence: Sessions 002 and 063
- Related questions: RQ-230-RQ-234

## METAINFO model

Sections are separated into common metadata, device families, payload records,
links and options. A payload resolves only when its declared size agrees with:

1. an exact declared filename on the same disc;
2. the deterministic ISO 9660 Level 1 8.3 alias on the same disc; or
3. either representation on another registered disc.

No fuzzy name or size-only match is accepted.

## Dependency model

CD1 contains 213 payload declarations: 189 resolve locally and 24 resolve only
on CD3. CD2 and CD3 resolve all 92 and 284 declarations locally. The CD1 EEPROM
target version/CRC pair equals a CD3 EEPROM source pair.

This establishes package-level cross-disc staging. It does not specify the
complete updater state machine or checksum algorithm.

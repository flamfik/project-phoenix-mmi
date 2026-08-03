# SPEC-069 - M1 registered-media reproduction

- Version: 0.1
- Maturity: BETA
- Evidence: Sessions 001 and 061
- Related questions: RQ-221-RQ-224

## Contract

The M1 media gate accepts exactly three locally held ISO 9660 artifacts. Each
must match its registered filename, byte size and SHA-256 before inventory
evidence is used.

The replay must reproduce primary volume identifier, 2,048-byte logical block
size, file count, directory count, payload-byte sum and extension census.

## Safety

No member bytes, source paths, source hashes or extracted resources enter the
public report. Artifact hashes remain in the pre-existing artifact register.

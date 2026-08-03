# SPEC-052 - legacy LOD/YIM census

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 041-044
- Related questions: RQ-157, RQ-166-RQ-168

## Contract

- accept only `.LOD` and `.YIM` members of at least 60 bytes;
- verify source ISO size and SHA-256 against the artifact register;
- deduplicate by private content hash;
- publish source IDs, member paths, sizes and aggregate morphology only;
- never publish source hashes, raw headers or payload bytes.

## Result

The 55 members reduce to five unique LOD and five unique YIM contents. YIM is
identified by a validated XIM2 envelope. LOD remains opaque.

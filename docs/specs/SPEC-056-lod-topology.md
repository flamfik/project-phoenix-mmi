# SPEC-056 - LOD opaque topology

- Version: 0.1
- Maturity: DRAFT
- Evidence: Session 048
- Related questions: RQ-178-RQ-180

## Measurements

- source size, entropy and zero/`ff` ratios;
- longest zero and `ff` runs;
- all-source common prefix/suffix;
- aligned all-source equality;
- private 256-byte content-block set intersections.

Block hashes never enter public output. A common block is reuse evidence, not
a record or section boundary.

## Decoder gate

A decoder requires independent record length, address and integrity
relationships. Session 048 does not satisfy that gate.

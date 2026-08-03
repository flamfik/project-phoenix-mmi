# SPEC-058 - integrated firmware evidence model

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 001-042, 044-050
- Related questions: RQ-184-RQ-187

## Evidence rule

Every model layer must retain its confidence and unresolved edges. Structural
format validation cannot assign a runtime owner, and a read-only decoder
cannot imply safe encoding or installation.

## Model layers

- update media and METAINFO selection;
- distributed device payloads;
- main MMI SuperH image;
- validated addressed record containers;
- XIM2 display assets;
- opaque LOD speech payloads;
- navigation media and partial runtime consumer graph.

## Gate

M1 remains partial and mutation readiness remains false until integrity,
section and ownership gaps are independently closed.

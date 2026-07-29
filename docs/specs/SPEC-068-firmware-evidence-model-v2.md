# SPEC-068 - firmware evidence model v2

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 001-060
- Related questions: RQ-216-RQ-220

## Evidence rule

Physical containment, exact content equality, structural alignment and package
role remain separate claims. None can assign a renderer, speech decoder or
safe writer without direct evidence.

## Model additions

- strict embedded XIM2 resource set in both principal images;
- exact partial link from standalone YIM to embedded XIM2;
- explicit unresolved YIM write-integrity layer;
- repeatable LOD fill topology;
- shifted-grid and aligned-region LOD reuse;
- rejected three-byte record promotion.

## Gate

Operational graph v52 has 86 nodes and 101 edges.
`milestone_m1 = PARTIAL_NOT_COMPLETE` and
`safe_mutation_ready = false`.

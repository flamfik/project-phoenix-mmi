# Session 087 - Static resource consumer matrix

- Date: 2026-07-29
- Objective: test exact resource/font addresses for bounded code references.
- Status: COMPLETE; M4-X3 PASS; operational graph v79.

One of 84 CD1 resources has ten exact address-word occurrences; none has a
PC-relative code referrer. CD3 has no exact resource-address word under the
same model. None of the four validated font containers in either image has an
exact address word or code referrer.

This establishes a reproducible negative consumer search. It does not identify
a renderer, resource lifecycle or font consumer.

Authoritative report:
`research/milestones/m4/session087/resource-consumer-matrix-summary.json`.

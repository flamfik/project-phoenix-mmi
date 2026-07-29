# SPEC-074 - M2 Analysis Toolkit foundation

- Version: 0.1
- Maturity: BETA
- Evidence: M1 closure and Session 066
- Related questions: RQ-243-RQ-250

## Capability registry

Every capability has a stable ID, workstream, status, probe type, target,
evidence, limitation and optional target session.

Allowed states:

- `IMPLEMENTED` - a usable read-only capability whose probe must exist;
- `PARTIAL` - a bounded capability whose probe must exist;
- `MISSING` - a required capability with no implementation probe;
- `BLOCKED` - evidence exists, but a required algorithm or contract is
  unresolved.

A probe is either one importable Python symbol, one repository-relative file,
or an explicit absence. Local absolute paths never enter the report.

## Entry gate

M2 requires a valid M1 closure with `milestone_m1 = COMPLETE` and
`safe_mutation_ready = false`. Every declared implemented or partial
capability must match its probe.

## Exit gate

Eight frozen criteria map to Sessions 067-074. A criterion passes only after
all of its required capabilities have status `IMPLEMENTED`. Partial, missing
and blocked states never pass by interpretation.

## Graph

Graph delta v58 adds `m2-analysis-toolkit` and
`m2-capability-baseline`. It authorizes read-only tooling development only.

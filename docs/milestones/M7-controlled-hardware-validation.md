# Milestone M7 - Controlled Hardware Validation

Status: **AWAITING_BENCH_EVIDENCE**

Entry evidence: Session 110, operational graph v102

## Mission

Define a recoverable, read-only bench environment, evidence capture contract,
stop conditions and signed risk review before any observation of real MMI
hardware. M7 readiness does not authorize firmware installation, mutation,
Component Protection work or vehicle communication.

## Completed preparation route

- Session 111: fail-closed scope, prerequisites and stop conditions;
- Session 112: private hardware manifest and aggregate public summary;
- Session 113: electrical plan requiring authoritative device references;
- Session 114: dummy-load abort and non-writing recovery plan;
- Session 115: passive observation and private-capture contract;
- Session 116: eight-hazard risk register and unsigned approval gate;
- Session 117: deterministic normal and abort state-machine rehearsal;
- Session 118: fail-closed private evidence intake;
- Session 119: eight-stage preparation integration and honest-stop verdict.

All eight preparation criteria pass at operational graph v111. The ninth M7
criterion requires accepted real private evidence, so M7 is not COMPLETE.

## Required Session 120 evidence

- a privately completed identity and isolation manifest;
- authoritative pinout and power-limit reference fingerprints;
- a completed dummy-load recovery rehearsal;
- operator and independent-reviewer approval tied to the risk fingerprint;
- a two-person pre-power check;
- passive observation, safe shutdown and private capture hashes;
- completed stop response when any stop condition occurs.

Until that bundle passes the validator, M7 remains
`AWAITING_BENCH_EVIDENCE` and M8 remains `NOT_READY`.

The safe template is
`docs/templates/SESSION-120-private-bench-evidence.template.json`. Copy it to
an ignored private path below `work/`, complete it only after the physical
preconditions are satisfied, then run:

```shell
PYTHONPATH=sdk python tools/session120/validate_private_bench_evidence.py \
  work/m7/private-bench-evidence.json \
  --public-output work/m7/public-bench-summary.json
```

An exit status of `2` means the physical gate remains blocked.

## Safety boundary

No hardware was powered during Sessions 111-119. No target firmware was
executed, no storage was accessed, no Component Protection operation was
attempted and no vehicle or live MOST network was connected.

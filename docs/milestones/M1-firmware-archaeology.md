# Milestone M1 - Firmware Archaeology

Status: **COMPLETE**  
Closure: Session 065  
Evidence graph: v57

## What M1 established

- the registered identity and complete ISO 9660 inventory of all three MMI
  5570 update discs;
- 593 files, 968 directories and 435,708,503 payload bytes;
- complete routing of every update member into an evidence-backed format
  family and later milestone;
- reproducible METAINFO topology across 706 sections and 589 payload records;
- direct evidence that 24 CD1 declarations resolve to payloads on CD3;
- the staged CD1 EEPROM target to CD3 source dependency;
- safe, static entrypoints for deeper work in Phoenix SDK;
- a machine-audited newcomer reproduction path.

## What M1 did not establish

- firmware or YIM write integrity;
- safe repacking or installation;
- LOD record/address/integrity semantics;
- exact renderer or runtime owner;
- navigation routing and coordinate grammars;
- compatibility with newer map data;
- bench recovery or vehicle-side validation.

These are preserved as open questions and assigned to M2-M7.

## Reproduce the closure

Install the repository in editable mode and run:

```powershell
python tools/session061_065/close_m1.py `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd1-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd2-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd3-3.iso `
  --output work/session061_065 `
  --public-root research/milestones/m1 `
  --repository-root .
```

The runner verifies registered identities before accepting any result. It
reads media and descriptors only; it does not execute firmware, extract
persistent payloads, create update media or communicate with a vehicle.

## Decision record

The authoritative machine-readable decision is
`research/milestones/m1/session065/milestone-m1-closure.json`.
It records five passing criteria while retaining
`safe_mutation_ready = false` and `installable_artifact_ready = false`.

# Session 085 - Static task and service inventory

- Date: 2026-07-29
- Objective: inventory runtime vocabulary without publishing firmware text.
- Status: COMPLETE; M4-X1 PASS; operational graph v77.

The fixed extractor reports 623 runtime-label records in CD1 and 614 in CD3,
representing 539 and 537 unique records with 354 shared. Both images contain
one bounded `taskSpawn` probe. Two fixed I/O probes account for 21 occurrences
in CD1 and 19 in CD3. Other fixed task-lifecycle probes were absent.

This confirms a bounded lexical inventory, not the scheduled task set, task
entry points or runtime scheduling.

Authoritative report:
`research/milestones/m4/session085/runtime-inventory-summary.json`.

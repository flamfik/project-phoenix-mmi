# Milestone M6 - Navigation Feasibility

Status: **COMPLETE**

Closure evidence: Session 110, operational graph v102

## Mission

Evaluate navigation database structure, routing-engine boundaries, legal data
sources and the feasibility of an independently authored OpenStreetMap
conversion path. M6 is a static research milestone, not a map replacement or
vehicle installation project.

## Entry gate

- M1 through M5 are COMPLETE;
- M5 passes 8/8 criteria and deterministic integration;
- the Phoenix UI prototype is offline and independently authored;
- firmware parser ownership, navigation write format and integrity remain
  unresolved;
- safe mutation and installable-artifact gates remain false.

## Completed route

- Session 102: capability baseline, provenance/safety contract and ordered
  Sessions 103-110 backlog;
- Session 103: registered public evidence ledger;
- Session 104: confidence-graded map knowledge and blocker matrix;
- Session 105: static media-to-runtime boundary graph;
- Session 106: OSM source, ODbL and attribution policy;
- Session 107: target-independent neutral navigation graph;
- Session 108: bounded OSM XML 0.6 adapter;
- Session 109: deterministic synthetic routing lab;
- Session 110: dual-track verdict, integration and M6 closure.

All eight exit criteria pass. Direct MMI media replacement remains `BLOCKED`
because the inner routing grammar, coordinate/index semantics, writer,
integrity, consumer ABI and recovery path are unresolved. The independently
authored OSM host pipeline is `PROTOTYPE_FEASIBLE`; this status does not imply
target compatibility.

## Safety boundary

M6 may analyze registered media structure and independently licensed data
formats. It may not redistribute proprietary map content, synthesize unknown
integrity fields, create installable navigation media, bypass licensing or
communicate with a vehicle.

M7 is READY only for controlled read-only bench planning and signed risk
review. Mutation and installable-artifact gates remain false.

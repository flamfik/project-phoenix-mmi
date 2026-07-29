# Milestone M5 - Phoenix UI Prototype

Status: **IN PROGRESS**

Entry evidence: Session 092; baseline: Session 093, operational graph v85

## Mission

Build an offline Phoenix UI prototype constrained by the original 480x240
display, physical controls and the confirmed resource/runtime boundaries.
M5 evaluates information architecture, interaction states, themes and host
preview behavior without modifying firmware.

## Entry gate

- M1 through M4 are COMPLETE;
- M4 passes 8/8 criteria and deterministic integration;
- the resource pixel layout and firmware renderer remain unresolved;
- the host harness is synthetic and isolated;
- safe mutation and installable-artifact gates remain false.

## Route

- Session 093: capability baseline, UX constraint contract and ordered
  offline backlog - complete;
- Session 094: typed information architecture and screen schema;
- Session 095: deterministic focus and navigation reducer;
- Session 096: bounded 480x240 layout engine;
- Session 097: original design tokens and synthetic asset registry;
- Session 098: offline Phoenix UI preview renderer;
- Session 099: deterministic input playback and snapshots;
- Session 100: legibility, focus and complexity audit;
- Session 101: sanitized integration and M5 closure.

Session 093 starts M5 with 17 capabilities: 2 implemented, 3 partial, 8
missing and 4 blocked. Eight exit criteria remain open.

## Safety boundary

M5 may create original interface code, diagrams and synthetic assets for
offline preview. It may not replace firmware resources, emulate protected
vehicle services, repack update media, execute firmware or communicate with a
vehicle.

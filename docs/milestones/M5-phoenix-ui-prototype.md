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
- Session 094: typed information architecture and screen schema - complete;
- Session 095: deterministic focus and navigation reducer - next;
- Session 096: bounded 480x240 layout engine;
- Session 097: original design tokens and synthetic asset registry;
- Session 098: offline Phoenix UI preview renderer;
- Session 099: deterministic input playback and snapshots;
- Session 100: legibility, focus and complexity audit;
- Session 101: sanitized integration and M5 closure.

Session 094 closes M5-X1 with five original Phoenix screens, 16 focusable
entries, four acyclic navigation edges and no service bindings. One of eight
exit criteria now passes.

## Safety boundary

M5 may create original interface code, diagrams and synthetic assets for
offline preview. It may not replace firmware resources, emulate protected
vehicle services, repack update media, execute firmware or communicate with a
vehicle.

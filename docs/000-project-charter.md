# Project Charter

## Mission

Build a reproducible technical knowledge base and open tooling for Audi MMI 2G High firmware research, with the long-term goal of evaluating a modernized user interface and current navigation data support without compromising vehicle safety or security.

## Phase 0 deliverables

- repository structure and contribution rules;
- artifact handling and integrity procedure;
- research-session template;
- evidence classification model;
- initial inventory of the MMI 5570 three-disc set;
- roadmap for Milestone M1.

## M1 — Firmware Archaeology

### Goals

- inventory every file on all three update discs;
- determine media and filesystem characteristics;
- identify update descriptors, scripts, packages, executables, resources, and checksums;
- map dependencies between discs and modules;
- document the update sequence;
- identify safe candidates for static analysis.

### Exit criteria

M1 is complete when another researcher can reproduce the inventory and understand which artifacts require deeper analysis without relying on undocumented assumptions.

## Out of scope for M1

- flashing modified software to a vehicle;
- bypassing Component Protection or licensing;
- distributing firmware or map images;
- replacing navigation software;
- executing unknown binaries outside an isolated environment.

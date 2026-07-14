# Project Phoenix MMI

Project Phoenix MMI is a research and development initiative focused on documenting the Audi MMI 2G High platform and building safe, reproducible tooling for firmware analysis.

## Current phase

**Phase 0 — Foundation**

The initial repository establishes the research method, evidence model, safety boundaries, artifact policy, session records, and modular project structure required before firmware analysis begins.

## First milestone

**M1 — Firmware Archaeology**

The goal of M1 is to:

- inventory the three MMI 5570 update discs;
- identify package, executable, resource, filesystem, and metadata formats;
- document the update process and module relationships;
- create reproducible manifests and analysis notes;
- avoid vehicle-side testing until the update chain and recovery requirements are understood.

## Repository structure

```text
docs/          Project documentation, decisions, safety rules and session logs
research/      Firmware-specific research records and reproducible manifests
tools/         Small, focused analysis utilities
scripts/       Lab setup and workflow helpers
tests/         Unit, integration and sanitized fixture data
sdk/           Future reusable parsers and libraries
emulator/      Future host-side simulation experiments
ui/            Future interface and resource research
```

## Research evidence levels

Every technical claim should be marked as one of:

- **CONFIRMED** — directly verified by reproducible evidence;
- **PROBABLE** — strongly supported but not fully verified;
- **HYPOTHESIS** — plausible and awaiting evidence;
- **DISPROVED** — tested and shown to be incorrect.

## Safety and scope

This project does not publish copyrighted firmware images, vehicle-specific secrets, Component Protection bypass instructions, immobilizer material, private identifiers, or instructions intended to defeat access controls.

Firmware images remain local research artifacts. The repository stores only independently created documentation, tools, metadata, hashes, and sanitized test fixtures.

## Guiding rule

> Understand first. Modify second.

See [`docs/000-project-charter.md`](docs/000-project-charter.md), [`SECURITY.md`](SECURITY.md), and [`docs/safety/lab-safety.md`](docs/safety/lab-safety.md) before contributing.

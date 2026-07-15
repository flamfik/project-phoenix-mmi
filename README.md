# Project Phoenix MMI

Project Phoenix MMI is a research and development initiative focused on documenting the Audi MMI 2G High platform and building safe, reproducible tooling for firmware analysis.

## Current phase

**M1 — Firmware Archaeology**

The foundation, media/update model and principal-image fingerprinting are complete. Session 004 confirms the executable SuperH startup layout and adds a read-only control-flow/reference pass to Phoenix SDK.

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
sdk/           Phoenix SDK reusable static-analysis library
emulator/      Future host-side simulation experiments
ui/            Future interface and resource research
```

## Current research results

- [Session 003 report](docs/sessions/SESSION-003-mmi-bin-static-analysis.md)
- [Session 004 report](docs/sessions/SESSION-004-superh-vxworks-layout.md)
- [Research Questions](docs/research-questions/README.md)
- [Technical specifications](docs/specs/)
- [Session 004 publication-safe evidence](research/firmware-5570/session004/)
- [Phoenix SDK usage](sdk/README.md)

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

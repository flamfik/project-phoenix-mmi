# Project Phoenix MMI

Project Phoenix MMI is a research and development initiative focused on documenting the Audi MMI 2G High platform and building safe, reproducible tooling for firmware analysis.

## Current phase

**M1 — Firmware Archaeology**

The foundation, update model and principal-image fingerprinting are complete. Session 022 finds no adjacent literal/JSR or direct BSR ingress to the two owner pairs, but confirms one internal address-taken use per release and stable entry-argument-rooted state bases. Owner A preserves 17/17 root classes with four versioned field-expression shifts; Owner B preserves 19/19 aligned expressions. Every owner contains four bases obtained through an `r4`-rooted load, while zero selected-owner bases originate from static image pointers. This supports a runtime-provided state/object contract without identifying its creator, semantic type or writer/loader. The producer edge, parser, sector ABI, buffer owner/provenance, partition consumer, backing-volume layout and dynamic compatibility remain open.

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
- [Session 005 report](docs/sessions/SESSION-005-browser-resource-bundle.md)
- [Session 006 report](docs/sessions/SESSION-006-runtime-address-map.md)
- [Session 007 report](docs/sessions/SESSION-007-reference-graph-owner-evidence.md)
- [Session 008 report](docs/sessions/SESSION-008-firmware-operational-model.md)
- [Session 009 report](docs/sessions/SESSION-009-navigation-storage-boundary.md)
- [Session 010 report](docs/sessions/SESSION-010-navigation-dataflow-optical-contract.md)
- [Session 011 report](docs/sessions/SESSION-011-navigation-media-fldb.md)
- [Session 012 report](docs/sessions/SESSION-012-payload-partitions-parser-constants.md)
- [Session 013 report](docs/sessions/SESSION-013-corrected-fldb-parser-dataflow.md)
- [Session 014 report](docs/sessions/SESSION-014-global-fldb-parser-search.md)
- [Session 015 report](docs/sessions/SESSION-015-optical-interprocedural-callgraph.md)
- [Session 016 report](docs/sessions/SESSION-016-predecessor-context-object-dispatch.md)
- [Session 017 report](docs/sessions/SESSION-017-descriptor-producer-lineage.md)
- [Session 018 report](docs/sessions/SESSION-018-accessor-call-family-runtime-linkage.md)
- [Session 019 report](docs/sessions/SESSION-019-runtime-slot-shadow-accessors.md)
- [Session 020 report](docs/sessions/SESSION-020-bilateral-runtime-linkage-family.md)
- [Session 021 report](docs/sessions/SESSION-021-residual-linkage-owner-lineage.md)
- [Session 022 report](docs/sessions/SESSION-022-owner-ingress-state-provenance.md)
- [Research Questions](docs/research-questions/README.md)
- [Technical specifications](docs/specs/)
- [Session 006 publication-safe evidence](research/firmware-5570/session006/)
- [Session 007 publication-safe evidence](research/firmware-5570/session007/)
- [Session 008 publication-safe evidence](research/firmware-5570/session008/)
- [Session 009 publication-safe evidence](research/firmware-5570/session009/)
- [Session 010 publication-safe evidence](research/firmware-5570/session010/)
- [Session 011 publication-safe evidence](research/navigation-media/session011/)
- [Session 012 publication-safe evidence](research/navigation-media/session012/)
- [Session 013 publication-safe evidence](research/navigation-media/session013/)
- [Session 014 publication-safe evidence](research/navigation-media/session014/)
- [Session 015 publication-safe evidence](research/navigation-media/session015/)
- [Session 016 publication-safe evidence](research/navigation-media/session016/)
- [Session 017 publication-safe evidence](research/navigation-media/session017/)
- [Session 018 publication-safe evidence](research/navigation-media/session018/)
- [Session 019 publication-safe evidence](research/navigation-media/session019/)
- [Session 020 publication-safe evidence](research/navigation-media/session020/)
- [Session 021 publication-safe evidence](research/navigation-media/session021/)
- [Session 022 publication-safe evidence](research/navigation-media/session022/)
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

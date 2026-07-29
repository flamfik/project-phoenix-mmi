# Project Phoenix MMI

Project Phoenix MMI is a research and development initiative focused on documenting the Audi MMI 2G High platform and building safe, reproducible tooling for firmware analysis.

## Current phase

**M1 — Firmware Archaeology**

The foundation, update model and principal-image fingerprinting are complete. Sessions 039-042 close fixed registered, raw, record-normalized and distributed provenance searches as bounded-negative. Sessions 044-050 identify the LOD/YIM families, validate a read-only XIM2 decoder and produce operational graph v42. Sessions 051-060 confirm 84 strict embedded XIM2 resources shared by MMI 5150 and 5570, retain the unknown YIM integrity fields as write blockers, establish repeatable LOD fill and shared-region topology, reject unsupported record promotion and advance the evidence model to graph v52. M1 remains partial because consumer ownership, exact section boundaries, loader transformation, YIM integrity and LOD record semantics remain open.

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
- [Session 023 report](docs/sessions/SESSION-023-internal-continuation-contracts.md)
- [Session 024 report](docs/sessions/SESSION-024-owner-entry-indirect-caller-compatibility.md)
- [Session 025 report](docs/sessions/SESSION-025-producer-first-owner-caller-candidates.md)
- [Session 026 report](docs/sessions/SESSION-026-call-return-producer-family.md)
- [Session 027 report](docs/sessions/SESSION-027-producer-return-use-family.md)
- [Session 028 report](docs/sessions/SESSION-028-handoff-field60-contract.md)
- [Session 029 report](docs/sessions/SESSION-029-runtime-prefix-handoff-mapping.md)
- [Session 030 report](docs/sessions/SESSION-030-literal-pool-boundary-correction.md)
- [Session 031 report](docs/sessions/SESSION-031-piecewise-link-address-map.md)
- [Session 032 report](docs/sessions/SESSION-032-relocation-anchor-breakpoints.md)
- [Session 033 report](docs/sessions/SESSION-033-bounded-reorder-descriptor-search.md)
- [Session 034 report](docs/sessions/SESSION-034-exact-block-reorder-map.md)
- [Session 035 report](docs/sessions/SESSION-035-dual-delta-similarity-profile.md)
- [Session 036 report](docs/sessions/SESSION-036-fixed-content-island-atlas.md)
- [Session 037 report](docs/sessions/SESSION-037-rz012-micro-island.md)
- [Session 038 report](docs/sessions/SESSION-038-rz012-run-gap-topology.md)
- [Session 039 report](docs/sessions/SESSION-039-registered-external-provenance.md)
- [Session 040 report](docs/sessions/SESSION-040-cross-payload-homolog-search.md)
- [Session 041 report](docs/sessions/SESSION-041-record-normalized-homolog-search.md)
- [Session 042 report](docs/sessions/SESSION-042-distributed-near-homolog-search.md)
- [Session 044 report](docs/sessions/SESSION-044-lod-yim-family-census.md)
- [Session 045 report](docs/sessions/SESSION-045-yim-xim2-envelope.md)
- [Session 046 report](docs/sessions/SESSION-046-yim-rle-decoder.md)
- [Session 047 report](docs/sessions/SESSION-047-yim-integrity-boundary.md)
- [Session 048 report](docs/sessions/SESSION-048-lod-structural-topology.md)
- [Session 049 report](docs/sessions/SESSION-049-yim-decoded-homolog-search.md)
- [Session 050 report](docs/sessions/SESSION-050-integrated-firmware-evidence-map.md)
- [Session 051 report](docs/sessions/SESSION-051-yim-expanded-integrity-catalog.md)
- [Session 052 report](docs/sessions/SESSION-052-yim-field-relations.md)
- [Session 053 report](docs/sessions/SESSION-053-embedded-xim2-census.md)
- [Session 054 report](docs/sessions/SESSION-054-yim-integrity-decision.md)
- [Session 055 report](docs/sessions/SESSION-055-lod-alignment-census.md)
- [Session 056 report](docs/sessions/SESSION-056-lod-fill-regions.md)
- [Session 057 report](docs/sessions/SESSION-057-lod-grid-reuse.md)
- [Session 058 report](docs/sessions/SESSION-058-lod-record-hypothesis.md)
- [Session 059 report](docs/sessions/SESSION-059-lod-shared-regions.md)
- [Session 060 report](docs/sessions/SESSION-060-firmware-evidence-map-v2.md)
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
- [Session 023 publication-safe evidence](research/navigation-media/session023/)
- [Session 024 publication-safe evidence](research/navigation-media/session024/)
- [Session 025 publication-safe evidence](research/navigation-media/session025/)
- [Session 026 publication-safe evidence](research/navigation-media/session026/)
- [Session 027 publication-safe evidence](research/navigation-media/session027/)
- [Session 028 publication-safe evidence](research/navigation-media/session028/)
- [Session 029 publication-safe evidence](research/navigation-media/session029/)
- [Session 030 publication-safe evidence](research/navigation-media/session030/)
- [Session 031 publication-safe evidence](research/navigation-media/session031/)
- [Session 032 publication-safe evidence](research/navigation-media/session032/)
- [Session 033 publication-safe evidence](research/navigation-media/session033/)
- [Session 034 publication-safe evidence](research/navigation-media/session034/)
- [Session 035 publication-safe evidence](research/navigation-media/session035/)
- [Session 036 publication-safe evidence](research/navigation-media/session036/)
- [Session 037 publication-safe evidence](research/navigation-media/session037/)
- [Session 038 publication-safe evidence](research/navigation-media/session038/)
- [Session 060 publication-safe evidence](research/navigation-media/session060/)
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

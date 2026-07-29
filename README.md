# Project Phoenix MMI

Project Phoenix MMI is a research and development initiative focused on documenting the Audi MMI 2G High platform and building safe, reproducible tooling for firmware analysis.

## Current phase

**M1 — Firmware Archaeology: COMPLETE; M2 — Analysis Toolkit: COMPLETE; M3 —
Resource Laboratory: COMPLETE; M4 — Runtime Research: READY**

Sessions 075-083 establish the strict resource catalog, geometry taxonomy,
pixel-layout hypotheses, private offline preview, publication-safe text and
font catalogs, language topology and deterministic integration. All 8 M3 exit
criteria pass; operational graph v75 authorizes the static-first M4 entry.
Safe mutation and installable-artifact gates remain false.

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
- [Session 061 report](docs/sessions/SESSION-061-m1-media-reproduction.md)
- [Session 062 report](docs/sessions/SESSION-062-m1-artifact-routing.md)
- [Session 063 report](docs/sessions/SESSION-063-m1-update-model-reproduction.md)
- [Session 064 report](docs/sessions/SESSION-064-m1-evidence-traceability.md)
- [Session 065 report](docs/sessions/SESSION-065-milestone-m1-closure.md)
- [Session 066 report](docs/sessions/SESSION-066-m2-toolkit-foundation.md)
- [Session 067 report](docs/sessions/SESSION-067-versioned-artifact-manifest.md)
- [Session 068 report](docs/sessions/SESSION-068-declarative-format-registry.md)
- [Session 069 report](docs/sessions/SESSION-069-normalized-parser-contract.md)
- [Session 070 report](docs/sessions/SESSION-070-checksum-experiment-framework.md)
- [Session 071 report](docs/sessions/SESSION-071-generic-structural-diff.md)
- [Session 072 report](docs/sessions/SESSION-072-schema-registry.md)
- [Session 073 report](docs/sessions/SESSION-073-unified-toolkit-cli.md)
- [Session 074 report](docs/sessions/SESSION-074-milestone-m2-closure.md)
- [Session 075 report](docs/sessions/SESSION-075-m3-resource-laboratory-baseline.md)
- [Session 076 report](docs/sessions/SESSION-076-versioned-resource-catalog.md)
- [Session 077 report](docs/sessions/SESSION-077-resource-geometry-taxonomy.md)
- [Session 078 report](docs/sessions/SESSION-078-pixel-layout-hypotheses.md)
- [Session 079 report](docs/sessions/SESSION-079-offline-resource-preview.md)
- [Session 080 report](docs/sessions/SESSION-080-cross-release-text-catalog.md)
- [Session 081 report](docs/sessions/SESSION-081-font-candidate-catalog.md)
- [Session 082 report](docs/sessions/SESSION-082-language-topology-resource-graph.md)
- [Session 083 report](docs/sessions/SESSION-083-milestone-m3-closure.md)
- [Milestone M1 closure guide](docs/milestones/M1-firmware-archaeology.md)
- [Milestone M2 closure](docs/milestones/M2-analysis-toolkit.md)
- [Milestone M3 closure](docs/milestones/M3-resource-laboratory.md)
- [Milestone M4 entry](docs/milestones/M4-runtime-research.md)
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
- [Sessions 061-065 M1 closure evidence](research/milestones/m1/)
- [M2 Analysis Toolkit evidence](research/milestones/m2/)
- [M3 Resource Laboratory evidence](research/milestones/m3/)
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

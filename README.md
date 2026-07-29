# Project Phoenix MMI

Project Phoenix MMI is a research and development initiative focused on documenting the Audi MMI 2G High platform and building safe, reproducible tooling for firmware analysis.

## Current phase

**M1 — Firmware Archaeology: COMPLETE; M2 — Analysis Toolkit: COMPLETE; M3 —
Resource Laboratory: COMPLETE; M4 — Runtime Research: COMPLETE; M5 — Phoenix
UI Prototype: COMPLETE; M6 — Navigation Feasibility: COMPLETE; M7 —
Controlled Hardware Validation: READY**

Sessions 084-092 establish static task/service and IPC evidence, resource
consumer and device-boundary searches, anonymous pointer topology, an isolated
host contract and deterministic integration. All 8 M4 exit criteria pass;
operational graph v84 authorizes an offline M5 UI prototype. Safe mutation and
installable-artifact gates remain false.

Session 093 freezes the M5 capability registry, the 480x240 offline viewport,
abstract focus-only input, original/synthetic asset policy and Sessions
094-101 route. Operational graph v85 keeps firmware execution, mutation,
repacking, installable artifacts and vehicle integration blocked.

Session 094 adds the first typed Phoenix UI model: five independently authored
screens, 16 focusable entries and four acyclic routes without layout geometry,
firmware menu reconstruction or service bindings. M5 now passes 1/8 criteria
at operational graph v86.

Sessions 095-101 complete a pure reducer, bounded 480x240 layout, original
theme and vector assets, five static SVG previews, deterministic playback,
quality audit and end-to-end integration. M5 closes 8/8 at graph v93 and makes
M6 static Navigation Feasibility READY. Firmware compatibility, hardware
suitability, mutation and installable artifacts remain unestablished or
blocked.

Sessions 102-110 normalize the registered navigation evidence, retain nine
explicit direct-replacement blockers, establish an ODbL-aware provenance gate,
define a target-neutral graph and exercise a bounded OSM XML adapter plus
deterministic routing on original synthetic data. M6 closes 8/8 at graph v102.
Direct MMI navigation-media replacement remains BLOCKED; an independent
host-side OSM pipeline is PROTOTYPE_FEASIBLE. M7 is READY only for controlled
read-only bench planning and signed risk review.

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
- [Session 084 report](docs/sessions/SESSION-084-m4-runtime-research-baseline.md)
- [Session 085 report](docs/sessions/SESSION-085-static-task-service-inventory.md)
- [Session 086 report](docs/sessions/SESSION-086-bounded-ipc-contract.md)
- [Session 087 report](docs/sessions/SESSION-087-resource-consumer-matrix.md)
- [Session 088 report](docs/sessions/SESSION-088-device-boundary-catalog.md)
- [Session 089 report](docs/sessions/SESSION-089-anonymous-runtime-object-topology.md)
- [Session 090 report](docs/sessions/SESSION-090-isolated-host-runtime-contract.md)
- [Session 091 report](docs/sessions/SESSION-091-runtime-evidence-graph.md)
- [Session 092 report](docs/sessions/SESSION-092-milestone-m4-closure.md)
- [Session 093 report](docs/sessions/SESSION-093-m5-ui-prototype-baseline.md)
- [Session 094 report](docs/sessions/SESSION-094-ui-information-architecture.md)
- [Session 095 report](docs/sessions/SESSION-095-ui-focus-navigation-reducer.md)
- [Session 096 report](docs/sessions/SESSION-096-ui-bounded-layout.md)
- [Session 097 report](docs/sessions/SESSION-097-ui-original-theme-assets.md)
- [Session 098 report](docs/sessions/SESSION-098-ui-offline-renderer.md)
- [Session 099 report](docs/sessions/SESSION-099-ui-playback-snapshots.md)
- [Session 100 report](docs/sessions/SESSION-100-ui-quality-audit.md)
- [Session 101 report](docs/sessions/SESSION-101-milestone-m5-closure.md)
- [Session 102 report](docs/sessions/SESSION-102-m6-navigation-feasibility-baseline.md)
- [Session 103 report](docs/sessions/SESSION-103-navigation-evidence-ledger.md)
- [Session 104 report](docs/sessions/SESSION-104-navigation-knowledge-matrix.md)
- [Session 105 report](docs/sessions/SESSION-105-navigation-boundary-graph.md)
- [Session 106 report](docs/sessions/SESSION-106-navigation-provenance-policy.md)
- [Session 107 report](docs/sessions/SESSION-107-neutral-navigation-model.md)
- [Session 108 report](docs/sessions/SESSION-108-bounded-osm-adapter.md)
- [Session 109 report](docs/sessions/SESSION-109-synthetic-routing-lab.md)
- [Session 110 report](docs/sessions/SESSION-110-milestone-m6-closure.md)
- [Milestone M1 closure guide](docs/milestones/M1-firmware-archaeology.md)
- [Milestone M2 closure](docs/milestones/M2-analysis-toolkit.md)
- [Milestone M3 closure](docs/milestones/M3-resource-laboratory.md)
- [Milestone M4 closure](docs/milestones/M4-runtime-research.md)
- [Milestone M5 closure](docs/milestones/M5-phoenix-ui-prototype.md)
- [Milestone M6 closure](docs/milestones/M6-navigation-feasibility.md)
- [Milestone M7 entry](docs/milestones/M7-controlled-hardware-validation.md)
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
- [M4 Runtime Research evidence](research/milestones/m4/)
- [M5 Phoenix UI Prototype evidence](research/milestones/m5/)
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

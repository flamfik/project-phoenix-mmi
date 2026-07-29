# Phoenix SDK

Phoenix SDK is a dependency-free Python library for reproducible, read-only static analysis of MMI research artifacts.

## Modules

- `binary` - bounded reads, chunk iteration, SHA-256 and signature search;
- `fingerprint` - validated executable, filesystem, compression, archive and resource signatures;
- `entropy` - Shannon entropy windows and transition detection;
- `strings` - ASCII/UTF-16 discovery with publication-safe aggregate summaries;
- `segments` - evidence-backed candidate boundaries and long `00`/`FF` runs;
- `checksum` - CRC32/IEEE helpers, METAINFO parsing and sequential block-map detection;
- `analysis` - complete single-artifact analysis and sanitized comparison;
- `report` - local full reports and compact publication-safe summaries;
- `iso9660` - targeted read-only access to one selected ISO member;
- `superh` - bounded big-endian SH-3 decoding, delayed-branch flow and PC-relative literals;
- `layout` - startup tracing, VxWorks fixed-name probes and resource-reference/island analysis;
- `resource_bundle` - publication-safe HTML summaries, relative-offset table tests and bounded big-endian pointer-run comparison;
- `runtime_map` - explicit runtime-address models, bounded link-base code probes, target-region mapping and cross-version relocation evidence.
- `reference_graph` - exact runtime-word edges, normalized descriptor graphs, bounded marker profiles and conservative owner-evidence policy.
- `operational_model` - relocated equal-region discovery, sparse-row bitmap classification, control comparison and confidence-graded firmware graph.
- `navigation_storage` - fixed navigation/storage markers, cross-version bands, bounded SH-3 references and structural ISO-9660/FAT/UDF validation.
- `navigation_dataflow` - fixed navigation/optical-service anchors, relocation-normalized record neighborhoods, bounded SH-3 call-site windows and conservative adjacent `MOV.L`/`JSR` target resolution.
- `map_media` - ISO-9660/Joliet inventory, fixed-width FLDB record-table validation, aggregate payload profiling and conservative firmware/media correlation without extraction.
- `map_payload` - bounded proprietary family headers, B/V directories, speech index/data splits, anonymous partition topology and opaque-field model probes.
- `parser_contract` - one-pass SH parser-constant loads, relocation-normalized cross-version comparison and operational graph v5 correlation.
- `parser_dataflow` - bounded SH register slicing, expected-value versus pointer discrimination, cross-version probe-block comparison and corrected operational graph v6.
- `parser_search` - global role-sensitive 36-byte stride census, backward-loop classification, cross-version pairing, conservative parser promotion gates and operational graph v7 correlation.
- `optical_callgraph` - code-gated optical record seeds, static SH call resolution, delay-slot-aware argument provenance, bounded cross-version graph expansion and operational graph v8 correlation.
- `object_dispatch` - bounded predecessor-context recovery, symbolic call-return and descriptor paths, conservative dynamic-dispatch comparison and operational graph v9 correlation.
- `descriptor_lineage` - nearest-producer tracing, exact field-12 accessor clustering, optical-target-aware static descriptor census, mixed-width initializer gates and operational graph v10 correlation.
- `accessor_dispatch` - literal-backed accessor call-family pairing, normalized context consensus, zero-tail runtime-slot detection, direct callback gates and operational graph v11 correlation.
- `runtime_slot` - complete zero-tail slot census, translated shadow-accessor mapping, bounded direct-writer/relocation probes and operational graph v12 correlation.
- `runtime_linkage` - normalized bilateral pointer-zero run pairing, global zero-target census, bounded GBR/helper/coherent-copy probes and operational graph v13 correlation.
- `linkage_owner` - bounded residual-call owner grouping, fixed-context and full-sequence lineage, short return-shape gates, global owner census and operational graph v14 correlation.
- `owner_provenance` - bounded direct-ingress tests, address-taken use classification, canonical argument/load-rooted state bases and operational graph v15 correlation.
- `continuation_contract` - internal-label live-in diagnostics, delayed argument tracing, address-record helper geometry and operational graph v16 correlation.
- `owner_caller` - bilateral owner-entry argument contracts, fixed indirect-call signature census, compatibility rejection gates and operational graph v17 correlation.
- `owner_producer` - registered shared-owner decoding, producer-first `r4`/`r6` gates, bilateral dynamic-call candidate families and operational graph v18 correlation.
- `call_return_producer` - immediate `CALL_RETURN` producer tracing, target-specific literal-call census, returned-object field geometry and operational graph v19 correlation.
- `producer_return_family` - exact target-pointer use census, bilateral return-flow classification, static-handoff limits and operational graph v20 correlation.
- `handoff_field60` - strict exact-entry reassessment, field-60 pointer-store/byte-return contract, bounded selected-owner pointer probe and operational graph v21 correlation.
- `handoff_mapping` - deterministic leading runtime-pointer-prefix correction, bilateral exact-entry/shape gates, direct CFG entry-`r5` liveness and operational graph v22 correlation.
- `literal_pool_boundary` - bounded full-pool recovery around registered targets, PC-relative use-role comparison, adjacent-code/runtime-callee separation and operational graph v23 correction.
- `piecewise_link_map` - publication-safe link-pair deduplication, relocation-family atlas, structural-delta-preserving bounded correction solver, independent code-anchor gate and operational graph v24.
- `relocation_breakpoints` - revalidated direct-link/data/marker anchors, non-interpolated code plateaus, monotonic and section-reorder brackets, exact identity-versus-delta reconciliation and operational graph v25.
- `micro_island` - strict 2 KiB overlap derivation, exact-run and naturally aligned unit profiles, two-phase microbins, fixed mapped negative control, anonymous SH decoder morphology and operational graph v30.
- `run_gap_topology` - exact-run replay, fixed singleton-gap components, relaxed-cap control, direct-stride/phase-lattice tests, repeated-run spacing gates and operational graph v31.
- `registered_provenance` - frozen prior-evidence registry, bilateral distance/containment gates, conservative semantic-owner audit and operational graph v32.
- `cross_payload_homolog` - fixed five-anchor raw update-payload census, equal-geometry control, content-identity exclusion/deduplication and operational graph v33.
- `record_normalization` - strict Intel HEX and partial S-record validation, address-contiguous private reconstruction, opaque-gap isolation and operational graph v34.
- `distributed_homolog` - fixed quality-gated 12-byte subanchor constellation, multi-parent voting, raw/decoded corpus reproduction and operational graph v35.
- `yim` - strict XIM2 envelope parsing, bounded two-byte-unit RLE decoding and fixed integrity-candidate tests without raster publication.
- `legacy_cycle` - LOD/YIM census, XIM2 reports, opaque LOD topology, decoded-YIM homolog search and integrated operational graph v42.
- `yim_research` - frozen expanded integrity tests, exact field relations, strict embedded-XIM2 census and explicit YIM write gate.
- `lod_research` - fixed phase, fill-region, shifted-grid, record-hypothesis and shared-region analyses for opaque LOD payloads.
- `evidence_cycle` - Sessions 051-060 synthesis and operational graph v52.
- `m1_closure` - registered-media replay, complete artifact routing, METAINFO
  suite resolution, evidence traceability and the Project Charter M1 gate.
- `toolkit_audit` - M2 capability registry, repository probes, entry gate,
  eight exit criteria and ordered Session 067-074 backlog.
- `manifest` - strict artifact identity, provenance and duplicate-content
  model.
- `format_registry` - declarative format rules with bounded structural
  validators.
- `parse_result` - normalized parser contract and structural-only LOD reader.
- `checksum_experiments` - reproducible bounded checksum hypotheses and
  explicit negative outcomes.
- `structural_diff` - deterministic redacted JSON-compatible comparisons.
- `schema_registry` - central schema lookup and fail-closed validation.
- `integration` - synthetic non-firmware M2 end-to-end gate.
- `resource_lab_audit` - M3 capability registry, entry/exit gates and explicit
  progress transitions.
- `resource_catalog` - strict embedded XIM2 scanning, private resource
  identities and publication-safe aggregate catalogs.
- `resource_graphics` - neutral geometry, fixed 16-bit layout hypotheses and
  format-explicit bounded PPM preview.
- `resource_text` - aggregate text discovery, structural SFNT/PCF validation,
  locale topology and the confidence-graded resource graph.
- `resource_lab_integration` - deterministic synthetic non-firmware M3 gate.
- `runtime_lab_audit` - M4 capability registry, entry/exit gates and explicit
  progress transitions.
- `runtime_inventory` - identifier-bounded task/API probes and private-label
  aggregate inventory.
- `runtime_ipc` - bounded fixed IPC probe results with conservative negative
  classification.
- `runtime_resources` - exact resource/font address words and SH referrer
  gates without consumer promotion.
- `runtime_devices` - publication-safe cross-release device-family topology.
- `runtime_objects` - anonymous runtime-range pointer topology and the
  confidence-graded M4 evidence graph.
- `runtime_harness` - deterministic metadata-only host contract with no I/O.
- `runtime_lab_integration` - synthetic non-firmware M4 end-to-end gate.
- `ui_constraints` - frozen 480x240 viewport, abstract focus input, original
  asset policy and fail-closed offline authorization boundary.
- `ui_prototype_audit` - M5 capability registry, entry/exit gates and ordered
  Sessions 094-101 prototype backlog.
- `ui_model` - typed, independently authored five-screen information
  architecture with strict reachability, provenance and service-binding gates.

The SDK does not execute binaries, modify update media, repack images or communicate with a vehicle.

## Unified CLI

```shell
phoenix-mmi manifest artifact.bin -o manifest.json
phoenix-mmi classify payload.hex -o classification.json
phoenix-mmi parse payload.hex -o parse.json
phoenix-mmi checksum payload.hex --algorithm CRC32/IEEE -o checksum.json
phoenix-mmi diff left.json right.json -o diff.json
phoenix-mmi validate parse.json -o validation.json
```

## Install and test

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Reproduce Session 003

```shell
python tools/session003/analyze_mmi_images.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session003 \
  --public-output research/firmware-5570/session003
```

## Reproduce Session 004

```shell
python tools/session004/analyze_executable_layout.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session004 \
  --public-output research/firmware-5570/session004
```

## Reproduce Session 005

```shell
python tools/session005/analyze_resource_bundle.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session005 \
  --public-output research/firmware-5570/session005
```

## Reproduce Session 006

```shell
python tools/session006/analyze_runtime_address_map.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session006 \
  --public-output research/firmware-5570/session006
```

## Reproduce Session 007

```shell
python tools/session007/analyze_reference_graph.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session007 \
  --public-output research/firmware-5570/session007
```

## Reproduce Session 008

```shell
python tools/session008/build_firmware_operational_model.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session008 \
  --public-output research/firmware-5570/session008
```

## Reproduce Session 009

```shell
python tools/session009/analyze_navigation_storage_boundary.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session009 \
  --public-output research/firmware-5570/session009
```

## Reproduce Session 010

```shell
python tools/session010/analyze_navigation_dataflow.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session010 \
  --public-output research/firmware-5570/session010
```

## Reproduce Session 011

```shell
python tools/session011/analyze_navigation_media.py \
  "<local-navigation-image>.iso" \
  --artifact-id nav-dvd-ee-2018-2019-001 \
  --firmware-cd1 MMI-5570-4L0.998.961-cd1-3.iso \
  --firmware-cd3 MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session011 \
  --public-output research/navigation-media/session011
```

## Reproduce Session 012

```shell
python tools/session012/analyze_payload_parser_contract.py \
  "<local-navigation-image>.iso" \
  --artifact-id nav-dvd-ee-2018-2019-001 \
  --firmware-cd1 MMI-5570-4L0.998.961-cd1-3.iso \
  --firmware-cd3 MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session012 \
  --public-output research/navigation-media/session012
```

## Reproduce Session 013

```shell
python tools/session013/analyze_fldb_candidate_dataflow.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session013 \
  --public-output research/navigation-media/session013
```

## Reproduce Session 014

```shell
python tools/session014/analyze_global_fldb_parser_search.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session014 \
  --public-output research/navigation-media/session014
```

## Reproduce Session 015

```shell
python tools/session015/analyze_optical_interprocedural_graph.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session015 \
  --public-output research/navigation-media/session015
```

## Reproduce Session 016

```shell
python tools/session016/analyze_object_dispatch_context.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session016 \
  --public-output research/navigation-media/session016
```

## Reproduce Session 017

```shell
python tools/session017/analyze_descriptor_lineage.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session017 \
  --public-output research/navigation-media/session017
```

## Reproduce Session 018

```shell
python tools/session018/analyze_accessor_dispatch.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session018 \
  --public-output research/navigation-media/session018
```

## Reproduce Session 019

```shell
python tools/session019/analyze_runtime_slot_lineage.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session019 \
  --public-output research/navigation-media/session019
```

## Reproduce Session 020

```shell
python tools/session020/analyze_runtime_linkage_family.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session020 \
  --public-output research/navigation-media/session020
```

## Reproduce Session 021

```shell
python tools/session021/analyze_linkage_owner_lineage.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session021 \
  --public-output research/navigation-media/session021
```

## Reproduce Session 022

```shell
python tools/session022/analyze_owner_ingress_state.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session022 \
  --public-output research/navigation-media/session022
```

## Reproduce Session 023

```shell
python tools/session023/analyze_internal_continuation_contract.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session023 \
  --public-output research/navigation-media/session023
```

## Reproduce Session 024

```shell
python tools/session024/analyze_owner_caller_compatibility.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session024 \
  --public-output research/navigation-media/session024
```

## Reproduce Session 025

```shell
python tools/session025/analyze_owner_producer_candidates.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session025 \
  --public-output research/navigation-media/session025
```

## Reproduce Session 026

```shell
python tools/session026/analyze_call_return_producer.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session026 \
  --public-output research/navigation-media/session026
```

## Reproduce Session 027

```shell
python tools/session027/analyze_producer_return_family.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session027 \
  --public-output research/navigation-media/session027
```

## Reproduce Session 028

```shell
python tools/session028/analyze_handoff_field60.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session028 \
  --public-output research/navigation-media/session028
```

## Reproduce Session 029

```shell
python tools/session029/analyze_handoff_mapping.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session029 \
  --public-output research/navigation-media/session029
```

## Reproduce Session 030

```shell
python tools/session030/analyze_literal_pool_boundaries.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session030 \
  --public-output research/navigation-media/session030
```

## Reproduce Session 031

```bash
python tools/session031/analyze_piecewise_link_map.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session031 \
  --public-output research/navigation-media/session031 \
  --search-radius 0x800
```

The Session 031 analyzer dereferences only the complete literal pools confirmed
by Session 030. It publishes generated pair IDs and relocation deltas, never
raw pointer values. Code anchors preserve the fixed cross-release structural
delta and require strict, fully decoded, equal bilateral shapes. A family needs
two distinct pairs with one common correction; repeated literals do not count
as independent evidence.

## Reproduce Session 032

```bash
python tools/session032/analyze_relocation_breakpoints.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session032 \
  --public-output research/navigation-media/session032
```

Session 032 consumes only prior confirmed evidence classes and revalidates their
raw hashes or bounded code gates. Code plateaus require repeated exact deltas,
while breakpoint brackets report only the interval containing a change.
Unobserved gaps are never filled, and a pool pair sharing only a relocation
delta with a known anchor is not promoted to target identity.

## Reproduce Session 033

```bash
python tools/session033/analyze_relocation_descriptors.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session033 \
  --public-output research/navigation-media/session033
```

Session 033 is seeded only by the two support zones bounding the confirmed
section reorder. It tests fixed exact/aligned boundaries, three explicit
address models, 12/16-byte records and all six field orders. Promotion requires
multi-record two-zone geometry, a syntactic PC-relative table-reference form
and an equal bilateral candidate. The reference census is not a whole-image
code gate. The analyzer never scans arbitrary whole-image integer triples.

## Reproduce Session 034

```bash
python tools/session034/analyze_exact_block_map.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session034 \
  --public-output research/navigation-media/session034
```

Session 034 searches only fixed 128 KiB margins around the two reorder zones.
It accepts 64-byte seeds only when unique in both lane windows, verifies the
bytes directly and extends exact blocks without an adaptive threshold. A
second 128-byte run must reproduce the transition bounds. Exact file-layout
correspondence does not establish runtime execution, loader behavior or
semantic ownership.

## Reproduce Session 035

```bash
python tools/session035/analyze_dual_delta_similarity.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session035 \
  --public-output research/navigation-media/session035
```

Session 035 reads only the remaining Session 034 envelope under the two prior
relocation deltas. It uses fixed 256/512/1024-byte windows, a 128-byte step,
predeclared match/advantage gates and a 64-byte half-step grid control. It does
not discover new deltas or tune thresholds after seeing the result. A
dominance crossing is descriptive file similarity, not an exact section or
runtime boundary.

## Reproduce Session 036

```bash
python tools/session036/analyze_content_island_atlas.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session036 \
  --public-output research/navigation-media/session036
```

Session 036 uses non-overlapping 4 KiB tiles and a half-tile control grid only
inside the unchanged Session 034 envelope. Exact-byte and exact-word support
are kept separate from entropy/histogram morphology. Repeated unequal-word
differences are counted anonymously and never labeled relocations without
independent evidence.

## Reproduce Session 037

```bash
python tools/session037/analyze_micro_island.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session037 \
  --public-output research/navigation-media/session037
```

Session 037 derives the only replicated 2 KiB overlap from Session 036 and
reads it under the prior `RZ-012` mapping plus the prior `RZ-013` negative
control. Fixed 256-byte bins, a 128-byte phase shift, exact runs and natural
word alignment distinguish clustered correspondence from scattered equality.
Anonymous SH decoder morphology never constitutes code proof.

## Reproduce Session 038

```bash
python tools/session038/analyze_run_gap_topology.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session038 \
  --public-output research/navigation-media/session038
```

Session 038 replays the Session 037 exact-run lists and bridges them only
across fixed singleton differences. A two-byte cap is a stability control.
Direct-stride, modulo-lattice and repeated-run-spacing gates remain separate
from the structural component and cannot assign record semantics.

## Reproduce Session 039

```bash
python tools/session039/analyze_registered_provenance.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session039 \
  --public-output research/navigation-media/session039
```

## Reproduce Session 040

```bash
python tools/session040/analyze_cross_payload_homologs.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd2-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session040 \
  --public-output research/navigation-media/session040
```

## Reproduce Session 041

```bash
python tools/session041/analyze_record_normalized_homologs.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd2-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session041 \
  --public-output research/navigation-media/session041
```

Session 041 validates Intel HEX and checksum-valid Motorola S-record runs.
Opaque vendor metadata and invalid envelope material never contribute decoded
bytes or bridge address-contiguous regions.

## Reproduce Session 042

```bash
python tools/session042/analyze_distributed_homologs.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd2-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/navigation-media/work/session042 \
  --public-output research/navigation-media/session042
```

Session 042 reproduces both prior corpora before searching them with one
frozen ten-subanchor target and equal-geometry control. No threshold is
adapted after observing payload results.

## Reproduce Sessions 044-050

```bash
python tools/session044_050/analyze_legacy_cycle.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd2-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output work/session044_050 \
  --public-root research/navigation-media
```

The cycle validates the XIM2 envelope and read-only RLE decoder, keeps
decoded rasters private, tests a frozen integrity-candidate matrix, profiles
LOD only as opaque binary structure, repeats the fixed Session 042 search in
the decoded-YIM domain and emits operational graph v42. Session 043 was never
executed and remains an explicit numbering gap.

## Reproduce Sessions 051-060

```bash
python tools/session051_060/analyze_integrity_lod_cycle.py \
  /path/to/MMI-5570-4L0.998.961-cd1-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd2-3.iso \
  /path/to/MMI-5570-4L0.998.961-cd3-3.iso \
  --output work/session051_060 \
  --public-root research/navigation-media
```

This cycle keeps all payloads private while testing a frozen expanded YIM
integrity catalogue, validating embedded XIM2 resources, profiling LOD
alignment and shared regions, rejecting unsupported record promotion and
emitting operational graph v52.

## Reproduce Sessions 061-065 and close M1

```powershell
python tools/session061_065/close_m1.py `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd1-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd2-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd3-3.iso `
  --output work/session061_065 `
  --public-root research/milestones/m1 `
  --repository-root .
```

The runner verifies registered media, reproduces Session 001 and 002 aggregate
evidence, routes all 593 members and applies the five-part M1 closure gate.
It emits no firmware bytes, extracted resources or installable artifact.

## Reproduce Session 066

```shell
python tools/session066/audit_m2_foundation.py \
  --repository-root . \
  --output work/session066 \
  --public-output research/milestones/m2/session066/m2-toolkit-foundation.json
```

This runner reads the M1 closure record and probes only repository-relative
files and importable SDK symbols. It freezes the M2 capability baseline and
does not access firmware.

## Reproduce Session 067

```powershell
python tools/session067/build_artifact_manifest.py `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd1-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd2-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd3-3.iso `
  --output work/session067 `
  --public-output research/milestones/m2/session067/artifact-manifest-summary.json `
  --repository-root .
```

The complete schema-v1 manifest remains under ignored `work/`. The committed
summary contains only aggregate counts and M2 gate evidence; it excludes
logical IDs, artifact IDs, content hashes, names and member paths.

## Reproduce Sessions 075-083 and close M3

```powershell
python tools/session075_083/close_m3.py `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd1-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd2-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd3-3.iso `
  --repository . `
  --public-output research/milestones/m3 `
  --private-output E:\project-phoenix-mmi\work\milestones\m3
```

The runner verifies all three registered ISO identities before analysis,
extracts the two principal images only into an operating-system temporary
directory, deletes them on exit and writes decoded identities/previews only
to the caller-selected private output. Committed reports contain aggregates
and milestone gates only.

## Reproduce Sessions 084-092 and close M4

```powershell
python tools/session084_092/close_m4.py `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd1-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd2-3.iso `
  E:\project-phoenix-mmi\MMI-5570-4L0.998.961-cd3-3.iso `
  --repository . `
  --public-output research/milestones/m4 `
  --private-output E:\project-phoenix-mmi\work\milestones\m4
```

The runner verifies all registered media, extracts principal images into an
operating-system temporary directory and deletes them on exit. Raw runtime
labels and exact reference profiles are written only to the ignored private
output. The host contract executes synthetic metadata only and provides no
firmware, network, CAN/MOST or vehicle interface.

All session runners verify ISO hashes, extract only selected members into an operating-system temporary directory and remove them after analysis. Full work directories are ignored by Git.

The SuperH decoder deliberately implements only documented instruction families needed for startup and reference analysis. Unknown instructions stay explicit, and indirect calls are not guessed into targets.

The resource-bundle analyzer publishes only structure, counts, hashes and offsets. Raw HTML, URIs, image bytes, firmware bytes and arbitrary strings remain local.

The runtime mapper never selects a base by an unconstrained best-score search. Its model set is fixed by the observed runtime range and METAINFO flash base; competing results remain in every report. A mapped address is not automatically labeled as code or assigned to a subsystem.

The reference graph keeps structural confirmation separate from semantic ownership. Contextual agreement can produce `PROBABLE`; only a direct consumer or equivalent semantic evidence may produce `CONFIRMED` ownership.

The operational model follows the same rule: bitmap morphology can confirm a structural region, while a glyph/font label remains probable until a format or renderer consumer is decoded.

The navigation/storage analyzer confirms subsystem presence only when fixed marker families, ordered cross-version bands and bounded code references agree. A bare `CD001` or FAT string never validates an embedded volume, and no result is treated as proof of the map-media format.

The navigation-dataflow analyzer never treats an analysis window as a decoded function. It resolves only an immediately adjacent PC-relative `MOV.L` feeding the same register used by `JSR`; object dispatch, route-data consumers, sector-read semantics and the map-media schema remain open until direct evidence exists.

The navigation-media analyzer does not extract or publish database members. It
publishes only volume structure, generated member IDs, counts, offsets,
entropy summaries, suffix classes and fixed marker counts. FLDB payload schemas,
the firmware parser edge and compatibility with modified or newer maps remain
explicitly unresolved.

The payload-family analyzer reads only bounded prefixes and publishes family
IDs, sizes, record invariants and anonymous partition counts. It never emits
names, raw headers, metadata, timestamps, payload bytes or opaque values. The
parser-constant analyzer treats an exact constant as numeric coupling only;
without buffer provenance and field-level dataflow it never labels a parser.

The parser-dataflow analyzer is the correction gate for such candidates. It
follows only documented instructions and supported register writes inside a
bounded block. Unsupported writes terminate a slice, branch merges are not
invented, and an attractive numeric match may be explicitly marked
`DISPROVED` when argument roles contradict the proposed format relation.

The global parser-search analyzer separates numeric occurrence from operand
role. A candidate is not promoted unless record iteration agrees across both
firmware releases and independent header-access, endian and buffer-provenance
signals converge. A negative result is explicitly bounded to the decoded
direct-loop model; it is not proof that no parser exists.

The optical call-graph analyzer treats record pointers as seeds, not function
claims. It resolves only direct branches and register calls backed by traced
in-image literals, accounts for call delay slots while tracing `r4`-`r7`, and
keeps object/vtable dispatch explicit. Depth, node and pairing gates bound every
negative result; a local return dereference is never labeled a buffer by itself.

The predecessor/descriptor analyzer revisits only indirect calls paired as
unresolved in Session 015. It may recover a literal target loaded before the
registered seed, but a target becomes graph-expandable only after the separate
bounded-code gate passes in both releases. Dynamic load paths are reported as
structure with explicit `CALL_RETURN`, field-width, displacement and selector
evidence; they are never named vtables or methods without an independently
resolved target and producer lineage.

The descriptor-lineage analyzer treats a nearest producer call, a field-12
accessor shape, a static record and a mixed-width initializer as separate
evidence classes. A cross-version accessor cluster does not close a producer
edge, and a raw `+8`/`+12` store pair is never called an initializer unless its
bounded executable context passes the independent code gate.

The accessor-dispatch analyzer treats raw adjacent PC-relative load/JSR forms
as a census, not as code proof. Cross-version call-family promotion requires a
fixed 16-word context, a minimum unique-match count and dominant-target
consensus. A pointer-plus-zero record run remains structural; runtime patch,
linkage, trampoline and callback semantics require an independently identified
writer, loader or runtime observation.

The runtime-linkage analyzer pairs pointer-zero runs only through exact
normalized geometry and keeps every zero-filled target non-executable. Its
global call-family census is syntactic. GBR, exact-address helper and coherent
copy-table results are bounded to their declared address/dataflow models; a
zero result cannot exclude memory-loaded bases, an external loader or
runtime-created metadata.

The internal-continuation analyzer never promotes an address inside an owner
window to an owner entry. It traces delayed arguments and preserved registers,
keeps field values path-merged across unresolved branches and applies the
cross-version family gate separately from the selected non-adjacent use.
Landing-pad, frame and unwind semantics remain probable until an ABI or
independent runtime evidence is identified.

The owner-caller analyzer tests only previously registered dynamic dispatch
contracts. A candidate must preserve every bilateral owner entry argument
after its last preceding call. Exact normalized context equality cannot
replace a concrete target or prove runtime equivalence.

The producer-first analyzer reconstructs the Session 021 registry and decodes
only exact owner shapes present in both releases. It requires explicit,
available `r4` and `r6` definitions after the last preceding call. A promoted
family remains structural until its memory-loaded target is independently
linked to a selected owner entry.

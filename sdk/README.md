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

The SDK does not execute binaries, modify update media, repack images or communicate with a vehicle.

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

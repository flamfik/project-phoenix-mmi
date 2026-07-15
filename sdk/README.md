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

All session runners verify ISO hashes, extract only selected members into an operating-system temporary directory and remove them after analysis. Full work directories are ignored by Git.

The SuperH decoder deliberately implements only documented instruction families needed for startup and reference analysis. Unknown instructions stay explicit, and indirect calls are not guessed into targets.

The resource-bundle analyzer publishes only structure, counts, hashes and offsets. Raw HTML, URIs, image bytes, firmware bytes and arbitrary strings remain local.

The runtime mapper never selects a base by an unconstrained best-score search. Its model set is fixed by the observed runtime range and METAINFO flash base; competing results remain in every report. A mapped address is not automatically labeled as code or assigned to a subsystem.

The reference graph keeps structural confirmation separate from semantic ownership. Contextual agreement can produce `PROBABLE`; only a direct consumer or equivalent semantic evidence may produce `CONFIRMED` ownership.

The operational model follows the same rule: bitmap morphology can confirm a structural region, while a glyph/font label remains probable until a format or renderer consumer is decoded.

The navigation/storage analyzer confirms subsystem presence only when fixed marker families, ordered cross-version bands and bounded code references agree. A bare `CD001` or FAT string never validates an embedded volume, and no result is treated as proof of the map-media format.

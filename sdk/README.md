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
- `layout` - startup tracing, VxWorks fixed-name probes and resource-reference/island analysis.

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

Both runners verify ISO hashes, extract only selected members into an operating-system temporary directory and remove them after analysis. Full work directories are ignored by Git.

The SuperH decoder deliberately implements only documented instruction families needed for startup and reference analysis. Unknown instructions stay explicit, and indirect calls are not guessed into targets.

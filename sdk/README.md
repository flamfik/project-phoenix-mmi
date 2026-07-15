# Phoenix SDK

Phoenix SDK is a dependency-free Python library for reproducible, read-only static analysis of MMI research artifacts.

## Modules

- `binary` — bounded reads, chunk iteration, SHA-256 and signature search;
- `fingerprint` — validated executable, filesystem, compression, archive and resource signatures;
- `entropy` — Shannon entropy windows and transition detection;
- `strings` — ASCII/UTF-16 discovery with publication-safe aggregate summaries;
- `segments` — evidence-backed candidate boundaries and long `00`/`FF` runs;
- `checksum` — CRC32/IEEE helpers, METAINFO parsing and sequential block-map detection;
- `analysis` — complete single-artifact analysis and sanitized comparison;
- `report` — local full reports and compact publication-safe summaries;
- `iso9660` — targeted read-only access to one selected ISO member.

The SDK does not execute binaries, modify update media, repack images or communicate with a vehicle.

## Install and test

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Reproduce Session 003 from the registered ISOs

```shell
python tools/session003/analyze_mmi_images.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session003 \
  --public-output research/firmware-5570/session003
```

The runner verifies both ISO SHA-256 values against `artifacts.csv`, extracts only the canonical hardware-index-42 MMI image and descriptor into an operating-system temporary directory, writes reports and removes the extracted files. Hardware-index-43 copies were independently verified as byte-identical.

The full output directory is ignored by Git. `--public-output` contains hashes, offsets, dimensions, entropy measurements and checksum metadata only; it contains no firmware payload, resource bytes or arbitrary raw strings.

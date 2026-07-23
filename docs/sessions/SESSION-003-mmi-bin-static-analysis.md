# Session 003 — Principal MMI BIN static analysis and Phoenix SDK

- Date: 2026-07-15
- Objective: Analyze the CD3/K1006 MMI 5570 image and compare CD1/K942 without executing firmware or publishing payloads.
- Environment: Python 3.12, read-only ISO 9660 access, registered ISO hashes.
- Status: COMPLETE for static fingerprinting, entropy, strings, standard resources and numbered checksum mapping.

## Artifact verification

All ISO hashes matched `research/firmware-5570/manifests/artifacts.csv`. The canonical hardware-index-42 members were analyzed; index-43 copies were separately hashed and proved identical.

| Disc | Principal image size | Principal image SHA-256 |
|---|---:|---|
| CD1 / MMI 5150 | 12,954,188 | `8f0b6062e0aaa74e68a80f97e7eff8a5deb7cd5b43146283b22ddc79f49786e5` |
| CD3 / MMI 5570 | 12,690,344 | `8b5f2efec7426fe30b2b56fb1a3a3500f6a725cf13f00bada636e8f8a2558a1f` |

## Confirmed findings

### S003-01 — Runtime identity markers

The first 64 bytes are identical. Both images contain the Wind River copyright at offset `0x20`, five `VxWorks` hits, `BECKER AUDID3 MMI` and `SH7709A`. Neither contains ASCII `QNX`.

The bytes at offset zero have no validated container/filesystem/executable magic. A flat SuperH/VxWorks image is therefore PROBABLE; a formal startup-code disassembly remains open.

### S003-02 — Complete numbered checksum map

All 25 METAINFO values match standard CRC32/IEEE over consecutive `0x80000`-byte chunks. `CheckSum` is chunk 0 and `CheckSum24` is the shorter final chunk. This mapping is identical in structure for 5150 and 5570.

### S003-03 — Standard resources

Structural validators confirmed exactly 3 JPEG and 9 GIF89a resources in each image. All 12 resource SHA-256 values are shared, proving the encoded resources are unchanged and only relocated.

### S003-04 — Negative standard-format results

No embedded ELF, U-Boot image, ROMFS, SquashFS, CRAMFS, UBIFS, valid ISO9660 descriptor, standard font or complete standard compression stream was validated. Short magic-byte coincidences were rejected rather than promoted to findings.

### S003-05 — Entropy and filler structure

| Metric | CD1 / 5150 | CD3 / 5570 |
|---|---:|---:|
| 64 KiB entropy windows | 198 | 194 |
| Mean Shannon entropy | 6.223940 | 6.235292 |
| Minimum | 0.000000 | 0.000000 |
| Maximum | 7.480358 | 7.460651 |
| Large entropy transitions | 15 | 14 |
| `0x00` runs at least 4 KiB | 9 | 9 |

These boundaries produce 46 and 45 analytical candidate segments respectively. They are hypotheses, not a vendor segment table.

## Phoenix SDK deliverable

Session 003 adds modular readers, fingerprint validators, entropy/string analysis, candidate segments, filler detection, CRC mapping, ISO targeting, safe reports and comparisons. The direct-ISO runner verifies registered hashes, extracts only selected members into a temporary directory and deletes them after reporting.

Eight synthetic tests cover binary boundaries, ISO extraction, SuperH ELF metadata, entropy, strings, sequential checksum detection, report safety and comparison. No test fixture contains Audi firmware.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S003-01 | CONFIRMED | Both registered principal images contain Wind River/VxWorks and SH7709A markers; ASCII QNX is absent. |
| S003-02 | CONFIRMED | All 25 checksum fields map to consecutive 512 KiB CRC32/IEEE chunks. |
| S003-03 | CONFIRMED | Three JPEG and nine GIF89a resources are valid and byte-identical across versions. |
| S003-04 | CONFIRMED | Tested standard executable/filesystem/font/compression candidates fail structural validation. |
| S003-05 | CONFIRMED | Entropy and filler measurements are reproducible from registered hashes. |
| S003-06 | PROBABLE | The principal payload is a flat SuperH/VxWorks application image. |
| S003-07 | OPEN | Proprietary table, custom font/resource formats and semantic code/data boundaries. |

## Reproduction

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
python tools/session003/analyze_mmi_images.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session003 \
  --public-output research/firmware-5570/session003
```

## Limits and safety

- No firmware code was executed or decompressed speculatively.
- No resource was exported or committed.
- CRC knowledge does not establish safe repacking or loader acceptance.
- No vehicle, MOST ring, EEPROM or Component Protection data was accessed.

## Recommended Session 004

Perform a read-only SuperH/VxWorks executable-layout pass: confirm the startup instructions, map absolute/PC-relative references, locate VxWorks symbol or module tables if present, and correlate the 12-resource cluster plus filler boundaries with referencing code. Navigation remains a separate later question until an internal module boundary is evidenced.

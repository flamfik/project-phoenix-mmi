# Session 001 — ISO Filesystem Inventory

- Date: 2026-07-14
- Objective: Complete read-only inventory of all three MMI 5570 update discs.
- Method: Direct ISO 9660 parsing, disposable extraction, SHA-256 per file, static file-type classification and cross-disc comparison.

## Artifact summary

| Disc | Volume label | ISO size | Files | Directories | Payload |
|---|---|---:|---:|---:|---:|
| CD1 | `H2_HI_EU_K942` | 150,089,728 B | 215 | 332 | 148,185,748 B |
| CD2 | `DISC` | 98,762,752 B | 93 | 199 | 95,351,480 B |
| CD3 | `DISK` | 194,539,520 B | 285 | 437 | 192,171,275 B |

All three images use ISO 9660 with 2048-byte logical blocks.

## Confirmed findings

### S001-01 — Disc roles

- CD1 descriptor declares release `H2_HI_EU_K942`, vendor `Harman/Becker`, variant `MMI High`, region `Europe`.
- CD2 declares release `EU_BTA_UHV` and contains only `BTA` and `HANDYVORB2` families.
- CD3 declares release `H2_HI_EU_K1006`, vendor `Harman/Becker`, variant `MMI High`, region `Europe`.

CD1 and CD3 are broad multi-component update collections. CD2 is specialized for Bluetooth and telephone hardware.

### S001-02 — Internal release versus public version

CD1 contains MMI application version `5150` under release K942. CD3 contains MMI application version `5570` under release K1006. This explains why the package is commonly called 5570 although its disc-wide release identifier is K1006.

### S001-03 — Descriptor-driven update model

Each disc contains a plain-text `METAINFO` descriptor with component families, hardware-index-specific paths, filenames, sizes, versions, application/bootloader roles, checksums and update-policy flags.

CD1 contains `PerformEepromUpdate = "true"` and `skipPatchFileCRC = "true"`. CD3 contains `PerformEepromUpdate = "true"`. Exact runtime semantics remain open.

### S001-04 — Heterogeneous embedded architecture

Static classification found:

- four Renesas SH ELF executables on CD1;
- the same four Renesas SH ELF executables on CD3;
- 25 U-Boot legacy uImage containers on CD2 reporting ARM/INTEGRITY payloads with gzip compression;
- Intel HEX, raw BIN, LOD, YIM and SW packages.

The update set therefore targets multiple independent embedded controllers on the MOST network, rather than one monolithic computer.

### S001-05 — Main MMI target architecture

The principal MMI binaries contain strings including `SH3`, `SH7709A`, `BECKER AUDID3 MMI`, MOST task names, navigation state names, EEPROM update references and CRC handling messages. This directly supports a Renesas SuperH target for the MMI head unit.

### S001-06 — CD1/CD3 relationship

Path-level comparison found:

- 37 paths common to CD1 and CD3;
- 31 byte-identical common files;
- 6 same-path files with different content, all in `TVHYBRID`;
- 178 paths unique to CD1;
- 248 paths unique to CD3.

Many telephone, speech and peripheral payloads are identical across both discs, while the MMI core and hardware-family coverage differ.

### S001-07 — Repeated payloads

There are 104 duplicate-content SHA-256 groups across the complete set. Identical payloads are often repeated under multiple hardware-index directories. Hardware index is therefore probably part of target selection, although the exact matching logic remains unverified.

## Disc profiles

### CD1 — K942 / MMI 5150 baseline

Top-level families include MMI, telephone, speech recognition, tuner, DAB, television, AMI, amplifiers, DSP variants and media devices.

- 119 `.bin`
- 72 `.hex`
- 15 `.lod`
- 5 `.yim`
- 3 `.sw`
- main MMI image: `H2_HI_EU.BIN`, 12,954,188 bytes

### CD2 — Bluetooth and phone preparation

- release `EU_BTA_UHV`
- 92 `.bin` files plus one descriptor
- Peiker `BTHS-HMI` family
- 25 ARM/INTEGRITY U-Boot images
- repeated `MAIN1`–`MAIN6` and hardware-index branches

### CD3 — K1006 / MMI 5570

CD3 expands the broad component coverage and adds or extends families including `AMP_ASK4`, `AMP_ASK6` and `AMP_LC_P`.

- 164 `.bin`
- 82 `.hex`
- 30 `.lod`
- 5 `.yim`
- 3 `.sw`
- main MMI image: `H2_HI_EU_R1006_SH3_AUDIHI_5.BIN`, 12,690,344 bytes
- explicit `MMI_HI/MMI/EEPROMUPDATE` directory

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S001-01 | CONFIRMED | CD1 and CD3 are broad MMI releases; CD2 is Bluetooth/phone-specific. |
| S001-02 | CONFIRMED | K1006 contains MMI application version 5570. |
| S001-03 | CONFIRMED | METAINFO descriptors define payload roles, versions, sizes and checksums. |
| S001-04 | CONFIRMED | The set contains Renesas SH ELF and ARM/INTEGRITY U-Boot images. |
| S001-05 | CONFIRMED | Main MMI software targets the Renesas SuperH family. |
| S001-06 | CONFIRMED | CD1 and CD3 combine identical, changed, removed and added payloads. |
| S001-07 | PROBABLE | Hardware-index paths participate in component target selection. |
| S001-08 | HYPOTHESIS | The principal MMI BIN is a compound image/archive containing runtime and resources. |
| S001-09 | HYPOTHESIS | METAINFO checksum fields use CRC32 variants; algorithms remain unverified. |

## Risks

- Both broad discs can request EEPROM updates.
- Bootloader payloads exist for multiple component families.
- Hardware-index selection must be understood before any repacking or vehicle-side experiment.
- CRC-related policy flags exist, so checksum logic must be mapped before modification.

## Session outputs

Generated locally and kept free of proprietary payloads:

- complete path/size/SHA-256/type manifest;
- ISO descriptor metadata;
- per-disc statistics;
- duplicate-payload report;
- independent read-only ISO 9660 inventory script.

Extracted firmware files remain outside Git.

## Recommended Session 002

**METAINFO schema and update-selection model**

1. Parse every descriptor section into structured records.
2. Normalize component, hardware index, role, version, filename and checksum fields.
3. Verify descriptor sizes against extracted files.
4. Identify checksum algorithms without modifying payloads.
5. Build a component/version matrix across all three discs.

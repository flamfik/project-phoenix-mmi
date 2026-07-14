# Session 002 — METAINFO schema and update-selection model

- Date: 2026-07-14
- Objective: Determine how the three-disc MMI 5570 set describes, selects, validates and sequences component updates.
- Method: Read-only parsing of all METAINFO descriptors, path correlation with Session 001 manifests, version/flag analysis and CRC32 testing.

## Descriptor scale

| Disc | Release | Sections | Device families | Payload records | Links | EEPROM options |
|---|---|---:|---:|---:|---:|---:|
| CD1 | `H2_HI_EU_K942` | 275 | 27 | 213 | 20 | 14 |
| CD2 | `EU_BTA_UHV` | 95 | 2 | 92 | 0 | 0 |
| CD3 | `H2_HI_EU_K1006` | 336 | 30 | 284 | 20 | 1 |

The descriptors contain 589 concrete payload records. Multiple descriptor records can reference the same physical file for different hardware indices or for both application and bootloader roles.

## Confirmed METAINFO hierarchy

A normal update record has the form:

```text
[component\application-id\hardware-index\variant\role]
```

Example:

```text
[MMI Hi\MMI\42\default\Application]
```

The five selection dimensions are therefore:

1. component family;
2. logical application/submodule;
3. hardware index;
4. variant, normally `default`;
5. role, usually `application`, `bootloader`, or `options`.

Each concrete payload normally declares `FileName`, `FileSize`, `CheckSum` plus optional numbered checksums, `Version`, and `AppName` for applications.

Device-family sections add policy fields such as `DangerousBoloUpdate`, `NoExclusiveBoloUpdate`, and `DelayDownloadAvailable`. The common section adds release metadata and global policy fields including `PerformEepromUpdate`, `skipPatchFileCRC`, and `MetafileChecksum`.

## Confirmed alias mechanism

Twenty records on both CD1 and CD3 use `Link` instead of repeating payload metadata. Examples map many IDC hardware indices to index 21 and MMI screen-data index 43 to index 42.

This confirms that selection is based on an exact logical target tuple, while links provide aliases to a canonical payload record.

## Confirmed checksum result

For many simple raw BIN payloads, `CheckSum` is the standard IEEE CRC32 of the complete physical file. Example:

```text
AMP/AMP/41/default/6315_app_dl.bin
METAINFO CheckSum: e5dbcc8f
calculated CRC32:   e5dbcc8f
```

This proves at least one checksum mode. It is not universal:

- Intel HEX checksums do not equal CRC32 of the textual HEX file;
- compound AMI, MMI, U-Boot and other multi-part images have a primary checksum plus numbered checksums;
- the principal MMI image's whole-file CRC32 does not equal its primary `CheckSum`;
- the `MetafileChecksum` algorithm has not yet been identified.

The numbered values probably validate internal regions or logical flash segments. This remains PROBABLE until offsets are mapped.

## Reconstructed update model

### 1. Read and validate update medium

**CONFIRMED:** The updater can identify release, vendor, variant and region from `[common]`. Every descriptor has `MetafileChecksum`.

**PROBABLE:** The MMI first validates descriptor integrity, then presents or accepts the release as a compatible update source.

### 2. Discover installed MOST components

**CONFIRMED:** Records are separated by component family, logical application, hardware index and role.

**PROBABLE:** The head unit inventories devices on the MOST ring and obtains identifiers including component/application and hardware index, plus installed software versions.

This is the only model that explains why identical payloads are repeated under many hardware-index paths and why some indices are linked to canonical records.

### 3. Resolve an exact descriptor target

**CONFIRMED:** A target record is keyed by the five-part section path. `Link` aliases redirect one target to another record.

**PROBABLE selection key:**

```text
(component, application-id, hardware-index, variant, role)
```

If an exact record exists, it is used. If it is a link, the canonical record is resolved. If no compatible record exists, that installed module is not offered an update from the current disc.

### 4. Compare installed and offered versions

**CONFIRMED:** Every concrete application/bootloader record declares `Version`.

**PROBABLE:** Installed versions are compared with offered versions to build the update list. The service UI may permit reinstallation or selective inclusion, so version comparison is unlikely to be the only gate.

No evidence yet proves whether comparison is numeric, lexical, vendor-specific or merely inequality-based.

### 5. Apply device update policy

**CONFIRMED:** Device sections contain three policy flags.

**Probable meanings based on names and record structure:**

- `DangerousBoloUpdate`: bootloader update is high-risk and requires special treatment or warning;
- `NoExclusiveBoloUpdate`: do not perform bootloader as a standalone exclusive operation; pair or coordinate it with application update;
- `DelayDownloadAvailable`: the target supports downloading or staging data before activation.

These interpretations are strong but still PROBABLE because runtime code paths have not yet been traced.

### 6. Validate payload before transfer

**CONFIRMED:** Descriptor size matches are available and many primary checksums are whole-file CRC32.

**PROBABLE:** The updater verifies declared size and the checksum scheme appropriate to the payload format before or during transfer. Numbered checksums likely validate chunks or flash regions and allow the receiving module to detect segment corruption.

`skipPatchFileCRC = "true"` on CD1 specifically changes checksum policy for patch files, not necessarily for normal application payloads.

### 7. Transfer application and/or bootloader

**CONFIRMED:** Application and bootloader are separate roles for many devices; some combined containers serve both roles.

**PROBABLE:** The head unit orchestrates transfer over MOST using a component-specific download protocol. Bootloader sequencing varies by device policy. Components may enter a programming state, accept payload segments, verify them and reboot.

The descriptors do not specify one universal flash algorithm; heterogeneous file formats and CPUs indicate that target bootloaders perform format-specific programming.

### 8. MMI head-unit special processing

The MMI application records additionally declare:

- `FlashStartAddress = 393216`;
- 24 numbered checksums;
- EEPROM source and target versions/CRCs;
- filesystem files to remove.

**CONFIRMED chain between discs:**

- CD1/K942 MMI 5150 targets EEPROM version `3.1.1f.2c.8.2c.c.2` with CRC `0x05a52f29` and accepts numerous older source states.
- CD3/K1006 MMI 5570 accepts exactly that K942 target state as its source and migrates it to `3.1.20.2d.8.2c.c.2`, CRC `0x7203781a`.

This is direct evidence that the intended broad-update sequence is staged:

```text
older supported MMI state
        ↓ CD1 / K942 / MMI 5150
EEPROM 3.1.1f.2c.8.2c.c.2 / CRC 05a52f29
        ↓ CD3 / K1006 / MMI 5570
EEPROM 3.1.20.2d.8.2c.c.2 / CRC 7203781a
```

CD2 can occur between those broad stages because it updates separate Bluetooth/telephone targets and does not declare an MMI EEPROM transition.

### 9. EEPROM patch selection

**CONFIRMED:** CD1 contains 14 patch-option records and multiple accepted source versions/CRCs. CD3 contains one patch option and one explicit source version/CRC. Both broad discs enable `PerformEepromUpdate`.

**PROBABLE:** The updater reads the existing EEPROM schema/version and, where present, CRC; selects the matching patch; verifies the patch according to policy; applies it after or alongside the head-unit application; and verifies the target state.

This also shows why skipping CD1 may be unsafe for an older installation: CD3 documents only the K942-era EEPROM state as its accepted source.

### 10. Filesystem cleanup and finalization

**CONFIRMED:** Both MMI application records request removal of `HTMLTM.INI`, `HTMLTMSE.INI`, and `HTMLADDR.INI`.

**PROBABLE:** These stale generated, cache, or configuration files are deleted to force regeneration compatible with the new software. The module then reboots and reports its new versions for a final verification scan.

## Most likely disc sequence

The descriptors strongly support:

1. **CD1:** establish K942/MMI 5150 and migrate a range of old EEPROM states to a single intermediate state;
2. **CD2:** update Bluetooth/telephone preparation families;
3. **CD3:** establish K1006/MMI 5570 and migrate the known intermediate EEPROM state to the final state.

This sequence is **PROBABLE**, not yet proven by executable control-flow analysis. The EEPROM source/target chain is, however, CONFIRMED.

## Important implications

1. The update is not simple file replacement. It is hardware-index-aware orchestration across multiple MOST devices.
2. The three-disc package contains an explicit state transition chain; CD1 is not merely an obsolete duplicate of CD3.
3. Any custom medium must preserve exact target mapping, size/checksum semantics, bootloader policy and EEPROM compatibility.
4. Modifying the MMI image alone may still fail because numbered checksums and descriptor integrity checks remain unknown.
5. Repacking before understanding `MetafileChecksum`, segmented checksums and EEPROM patch format would create unacceptable brick risk.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S002-01 | CONFIRMED | METAINFO uses a five-part target hierarchy. |
| S002-02 | CONFIRMED | `Link` aliases hardware targets to canonical records. |
| S002-03 | CONFIRMED | Standard CRC32 validates many simple raw BIN files. |
| S002-04 | CONFIRMED | The checksum model is format-dependent and often segmented. |
| S002-05 | CONFIRMED | CD1 EEPROM target is the explicit CD3 EEPROM source. |
| S002-06 | PROBABLE | Device discovery and exact tuple matching drive update selection. |
| S002-07 | PROBABLE | Version comparison builds the offered update list. |
| S002-08 | PROBABLE | Device policy flags control bootloader and staging behavior. |
| S002-09 | PROBABLE | CD1 → CD2 → CD3 is the intended operational order. |
| S002-10 | HYPOTHESIS | Numbered checksums correspond to internal flash regions in payload order. |
| S002-11 | OPEN | `MetafileChecksum` algorithm and canonicalization. |

## Recommended Session 003

**MMI image container and segmented checksum map**

- map the principal MMI image header and segment table;
- test the 24 numbered checksums against candidate regions;
- identify embedded filesystem/archive boundaries;
- correlate `FlashStartAddress` with segment layout;
- locate application, UI resources and navigation components without executing code.

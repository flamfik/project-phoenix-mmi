# SPEC-001 — Principal MMI image start and runtime identity

- Version: 0.2
- Maturity: ALPHA
- Evidence: Session 003, registered CD1/CD3 images
- Related questions: RQ-001, RQ-002

## Artifacts

| Release | ISO member | Size | SHA-256 |
|---|---|---:|---|
| CD1 K942 / MMI 5150 | `MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN` | 12,954,188 | `8f0b6062e0aaa74e68a80f97e7eff8a5deb7cd5b43146283b22ddc79f49786e5` |
| CD3 K1006 / MMI 5570 | `MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN` | 12,690,344 | `8b5f2efec7426fe30b2b56fb1a3a3500f6a725cf13f00bada636e8f8a2558a1f` |

The hardware-index-43 members have different ISO extents but are byte-identical to the corresponding index-42 payload.

## Confirmed observations

- The first 64 bytes are identical in 5150 and 5570.
- No validated ELF, archive or filesystem magic starts at offset zero; the local report retains the first 64 bytes for the future disassembly pass.
- At file offset `0x20` both images contain `Copyright 1984-1998 Wind River Systems, Inc.`.
- Both contain five ASCII `VxWorks` hits and seven `Wind River` hits.
- Both contain `BECKER AUDID3 MMI` and `SH7709A` at the same early string record around `0x2246`.
- No ASCII `QNX` marker occurs in either complete principal image.
- METAINFO declares `FlashStartAddress = 393216` (`0x00060000`). This is a target address, not a proven file offset.

## Interpretation

`PROBABLE`: the principal MMI image is a flat, big-endian SuperH/VxWorks application image rather than a QNX filesystem container. The initial halfwords are consistent with SuperH startup instructions, but instruction-level confirmation remains pending a documented disassembly pass.

`DISPROVED`: the earlier working assumption that the main MMI 2G High image is demonstrably a QNX payload is not supported by these artifacts. Other components in the platform may still use different runtimes.

## Open structure

No vendor header length, internal table pointer or semantic region directory is yet confirmed. The 512 KiB checksum grid in SPEC-002 is an integrity layout, not proof of application-level segmentation.

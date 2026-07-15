# SPEC-001 - Principal MMI image start and runtime identity

- Version: 0.3
- Maturity: BETA
- Evidence: Sessions 003-004, registered CD1/CD3 images
- Related questions: RQ-001, RQ-002

## Artifacts

| Release | ISO member | Size | SHA-256 |
|---|---|---:|---|
| CD1 K942 / MMI 5150 | `MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN` | 12,954,188 | `8f0b6062e0aaa74e68a80f97e7eff8a5deb7cd5b43146283b22ddc79f49786e5` |
| CD3 K1006 / MMI 5570 | `MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN` | 12,690,344 | `8b5f2efec7426fe30b2b56fb1a3a3500f6a725cf13f00bada636e8f8a2558a1f` |

The hardware-index-43 members have different ISO extents but are byte-identical to the corresponding index-42 payload.

## Confirmed observations

- Executable big-endian SH-3 control flow begins at file offset zero.
- The entry branch and delayed slot are coherent, and the reached instructions perform PC-relative loads and control-register setup.
- No validated ELF, archive or filesystem magic starts at offset zero.
- At file offset `0x20` both images contain the Wind River copyright banner; startup control flow branches over it.
- Both contain five ASCII `VxWorks` hits and seven `Wind River` hits.
- Both contain `BECKER AUDID3 MMI` and `SH7709A` in the early image.
- No ASCII `QNX` marker occurs in either complete principal image.
- METAINFO declares `FlashStartAddress = 393216` (`0x00060000`).

## Interpretation

`CONFIRMED`: there is no separate vendor container header before the entry code.

`PROBABLE`: the complete principal payload is a flat SuperH/VxWorks application image rather than a QNX filesystem container. Later proprietary regions and module boundaries are not yet fully mapped.

`DISPROVED`: the earlier working assumption that the principal MMI 2G High image is demonstrably a QNX payload is not supported by these artifacts. Other platform components may use different runtimes.

## Open structure

No internal table pointer or semantic region directory is yet confirmed. The 512 KiB checksum grid in SPEC-002 is an integrity layout, not proof of application-level segmentation.

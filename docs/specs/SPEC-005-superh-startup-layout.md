# SPEC-005 - SuperH startup and reference model

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 004, registered CD1/CD3 principal images
- Related questions: RQ-001, RQ-002, RQ-011

## Address model

MMI METAINFO declares `FlashStartAddress = 0x00060000`. Phoenix reports file offsets as the primary coordinate and tests both raw file-offset values and `0x00060000 + file_offset` when classifying absolute references.

SuperH PC-relative targets are calculated from the file-relative instruction offset. This is valid here because the declared flash base is aligned to four bytes.

## Confirmed entry flow

Both images share a byte-identical 782-byte entry prefix. At file offset zero:

1. a delayed unconditional branch targets offset `0x8`;
2. its delay slot is `nop` and the two intervening words are not executed;
3. a PC-relative long load reads a literal at `0x4C`;
4. the loaded value is written to the status register;
5. a PC-relative address initializes GBR;
6. the branch at `0x14` targets `0x50`, skipping the Wind River banner at `0x20`.

The bounded control-flow pass reaches 790 instruction offsets through `0xFEE` in each release. It observes the same aggregate counts: 31 unconditional branches, 48 conditional branches, 68 indirect calls, one return and 198 PC-relative literal loads. The first 48 decoded trace records are equal. The complete 4,080-byte reached range is not identical: it contains 177 differing bytes beginning at `0x30E`. Unknown instruction families remain explicit and do not invalidate the confirmed entry semantics.

## Literal address candidates

The reached startup code contains two long literals that fit tested image-address models:

- one is a valid raw file-offset candidate;
- one equals the METAINFO flash base and is ambiguous between raw offset `0x60000` and flash-relative image offset zero.

These candidates establish the analysis model but do not prove a global relocation scheme.

## Source semantics

Branch displacement, delayed-slot and PC-relative load calculations follow the official [Renesas SH-3/SH-3E/SH3-DSP Software Manual](https://www.renesas.com/en/document/mas/sh-3sh-3esh3-dsp-software-manual).

## Limits

- This is a partial decoder, not a complete disassembler.
- Indirect call targets are not resolved.
- The trace starts only from the confirmed entry point and is bounded to the first 64 KiB.
- Reachability is static and does not assert runtime execution on a specific vehicle.

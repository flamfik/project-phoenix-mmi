# SPEC-009 - Principal-image runtime address map

- Version: 0.2
- Maturity: ALPHA
- Evidence: Sessions 006-007, registered CD1/CD3 principal images
- Related questions: RQ-002, RQ-003, RQ-015, RQ-016, RQ-017

## Selected mapping

For the bounded structures tested in Session 006:

```text
file_offset = runtime_address - 0x0C000000
```

Status: `CONFIRMED_BOUNDED_STATIC_MODEL`.

The status applies to the observed code probes and four post-cluster address runs. It is not a claim that every 32-bit value in the firmware is a runtime pointer.

## Independent code evidence

Within the first `0x2000` bytes, both releases contain two structurally coherent sequences in which:

1. a PC-relative `MOV.L` loads `0x0C000000`;
2. another `MOV.L` loads a value inside the same runtime image range;
3. the next instruction performs `JSR` through the loaded register.

The base loads occur at file offsets `0x2A0` and `0x17A4` in both releases. The first sequence calls runtime address `0x0C002410`, which maps to file offset `0x2410`. No instruction bytes are published.

## Competing models

Five independently motivated models are retained:

| Model | Base subtracted | Targets in bounds | Exact 64-byte pairs |
|---|---:|---:|---:|
| Raw file address | `0x00000000` | 0/69 | 0 |
| METAINFO flash address | `0x00060000` | 0/69 | 0 |
| Runtime minus flash | `0x0BFA0000` | 69/69 | 0 |
| Runtime link base | `0x0C000000` | 69/69 | 21 |
| Runtime plus flash | `0x0C060000` | 68/69 | 0 |

The selected model was fixed by code evidence before target-window scoring. The comparison therefore corroborates the model rather than defining it.

## Mapped regions

Under the selected model, all 69 entries (65 unique addresses) are four-byte aligned and inside each principal image:

- one entry maps to file offset zero, the confirmed executable entry;
- 68 entries map to unresolved regions before the browser-resource island;
- zero entries map to the browser-resource core or post-cluster part of the island.

The region label `pre-browser-unresolved` deliberately does not imply code or data.

## Relocated record block

Run 0 contains 20 entries using the dominant `0x4F0DC` release delta. After removing duplicates, they address 16 consecutive records:

| Property | CD1 / 5150 | CD3 / 5570 |
|---|---:|---:|
| Block file offset | `0xAC3DC` | `0xFB4B8` |
| Record count | 16 | 16 |
| Record stride | 16 bytes | 16 bytes |
| Block length | 256 bytes | 256 bytes |

The two blocks are byte-identical and have SHA-256 `87892b3bb1be58b663a229efaaad2fc5a23e94e139aff77600c4e7a8c7102011`. This confirms relocated target semantics for this subset. It does not identify the record schema or owner.

## Session 007 refinement

Two run-0 entries in each release point exactly to the block start. A separate normalized nine-field descriptor graph is anchored `0x1FF4` bytes before the block and relocates by the same `0x4F0DC` delta. These relationships are specified in SPEC-010.

The current owner label is `PROBABLE_BROWSER_SUPPORT_REGION`, based on two contextual signals. It is explicitly not a confirmed code-level owner.

## Safety boundary

Public reports contain no firmware bytes, target-window bytes, full pointer-run lists or raw strings. The analyzer performs only bounded reads and arithmetic mapping; it never executes or modifies an artifact.

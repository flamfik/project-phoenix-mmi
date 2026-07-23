# SPEC-002 — Principal MMI checksum grid

- Version: 1.0
- Maturity: BETA
- Evidence: Session 003, both registered principal images
- Related questions: RQ-003, RQ-004

## Confirmed algorithm

The primary `CheckSum` field is checksum index 0. `CheckSum1` through `CheckSum24` continue the sequence. Every value is standard CRC32/IEEE of one consecutive file region:

```text
block_size = 0x80000 (524,288 bytes)
offset(i)  = i * 0x80000
end(i)     = min(file_size, offset(i) + 0x80000)
crc(i)     = CRC32/IEEE(file[offset(i):end(i)])
```

All 25 fields match in both CD1 and CD3.

| Artifact | Full blocks | Final block offset | Final length | All matches |
|---|---:|---:|---:|---:|
| CD1 / 5150 | 24 | `0xC00000` | `0x5AA4C` (371,276) | 25/25 |
| CD3 / 5570 | 24 | `0xC00000` | `0x1A3A8` (107,432) | 25/25 |

METAINFO checksum values with omitted leading zeroes, such as `f0b7aa9`, are hexadecimal and normalize to eight digits (`0f0b7aa9`).

## Consequences

- Numbered checksums are transport/integrity chunks, not an unknown 24-entry semantic segment table.
- Any byte modification affects exactly one 512 KiB checksum field unless it changes file length or chunk alignment.
- This result does not identify `MetafileChecksum`, signature policy, loader acceptance rules or safe repacking behavior.
- No modified update medium should be built or installed solely from this checksum result.

Full per-block offsets, expected values and calculated values are in the publication-safe Session 003 JSON summaries.

# Session 046 - bounded YIM RLE decoder

- Date: 2026-07-29
- Objective: reconstruct the XIM2 payload with explicit length and output
  bounds.
- Mode: private in-memory decoding; no raster export.
- Status: COMPLETE for all five registered contents.

## Grammar

Each big-endian 16-bit command describes two-byte units:

- high bit clear: repeat the following two-byte unit `count` times;
- high bit set: copy the following `count * 2` bytes literally;
- `count` is the lower 15 bits and must be nonzero.

The decoder rejects truncated commands, zero counts, output overflow, trailing
bytes and any final size other than `width * height * 2`.

## Results

| Metric | Count |
|---|---:|
| Sources decoded | 5 |
| Encoded payload bytes | 123,482 |
| Decoded raster bytes | 1,152,000 |
| Decoded two-byte units | 576,000 |
| Literal commands | 4,746 |
| Repeat commands | 9,370 |
| Total commands | 14,116 |

Every source consumes its entire encoded stream and produces exactly 230,400
bytes, equal to `480 * 240 * 2`. Per-source encoded/decoded ratios range from
0.09307292 to 0.11527778.

## Interpretation boundary

The two-byte unit width is confirmed by stream closure. RGB555 or another
pixel interpretation is not assigned without independent renderer or palette
evidence. A decoder is not an encoder and does not make repacking safe.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S046-01 | CONFIRMED | One bounded RLE grammar closes all five streams. |
| S046-02 | CONFIRMED | Every decoded raster is exactly 480 by 240 by two bytes. |
| S046-03 | OPEN | Pixel-channel semantics and encoding/repacking remain unresolved. |

## Deliverables

- `decode_yim_rle`;
- output-overflow and truncation guards;
- publication-safe command statistics;
- SPEC-054;
- operational graph v38.

## Next step

Session 047 tests the two opaque preamble fields against fixed common
integrity algorithms and byte ranges.

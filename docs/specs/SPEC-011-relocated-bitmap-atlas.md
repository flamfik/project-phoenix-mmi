# SPEC-011 - Relocated sparse-row bitmap atlas

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 008, registered CD1/CD3 principal images
- Related questions: RQ-015, RQ-017, RQ-019, RQ-020

## Relocated invariant extent

The bounded equal-region algorithm expands backward and forward from the confirmed Session 006 block while relocated bytes remain identical. The result is:

| Property | Value |
|---|---:|
| Relative start | `-0x1F00` |
| Relative end | `+0xF74D` |
| Length | 71,245 bytes |
| SHA-256 | `bb3dc59de9d12e402708eccf169fe236294708298d371aedb67815ecfd0a10ce` |

The scan is bounded to `0x20000` bytes in each direction. Neither bound was reached. The endpoints are cross-version equality boundaries, not confirmed segment-directory boundaries.

## Sparse-row classifier

The classifier interprets each byte as one eight-bit row only for measurement. A 64-byte window is positive when all conditions hold:

```text
zero_byte_ratio >= 0.20
0.05 <= set_bit_density <= 0.30
nonzero_row_run_count >= 3
2 <= median_nonzero_row_run_height <= 12
aligned_runtime_pointer_count == 0
recognized_flow_control_halfword_count == 0
```

This is a morphological classifier. It does not parse or export a font.

## Cross-version result

- 793/1,113 windows are positive in both releases: 71.2489%;
- the maximum positive rate among six equal-size controls is 6.7385%;
- all nine normalized descriptor targets are inside the invariant extent;
- all nine target windows are byte-identical and classifier-positive;
- the original 256-byte block is classifier-positive and contains no aligned runtime pointer or recognized SH-3 flow-control halfword.

Structural status: `CONFIRMED_RELOCATED_SPARSE_ROW_BITMAP_REGION`.

Semantic status: `PROBABLE_1BPP_GLYPH_ATLAS`.

## Why semantics are not confirmed

Confirmation requires at least one decoded font header, character-to-glyph map, metric table, or renderer/dataflow consumer. Visual or statistical resemblance alone is insufficient.

## Publication boundary

Public evidence may include offsets, lengths, hashes, bit-density metrics, row-run histograms, classifier thresholds and evidence status. It must exclude firmware bytes, rendered glyphs, screenshots reconstructed from firmware, raw pointer runs and arbitrary extracted strings.

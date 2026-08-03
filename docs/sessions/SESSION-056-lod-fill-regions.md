# Session 056 - LOD fill-region segmentation

- Date: 2026-07-29
- Objective: test whether large zero and `0xFF` runs define repeatable
  cross-language boundaries.
- Mode: read-only, thresholds frozen before the corpus run.
- Status: COMPLETE, STRUCTURAL TOPOLOGY CONFIRMED.

## Frozen thresholds

- zero run: at least 4,096 bytes;
- `0xFF` run: at least 128 bytes.

## Result

Every unique LOD source contains exactly three delimiters in the same order:

```text
FF -> ZERO -> ZERO
```

This yields four bounded regions per source. The first delimiter is always 192
bytes and begins at phase zero modulo three. The two zero delimiters have
stable length families, while their positions move with language-specific
content.

The topology is repeatable, but the semantic role of each region is not known.

## Deliverables

- SPEC-064;
- RQ-204-RQ-206;
- `lod-fill-regions.public.json`;
- fixed-threshold delimiter analyzer.

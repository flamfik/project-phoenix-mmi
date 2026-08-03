# SPEC-053 - YIM/XIM2 envelope

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 045
- Related questions: RQ-169-RQ-171

## Validation gates

- 24-byte ASCII-hex preamble;
- `XIM2` at offset 24;
- ASCII size equals physical size;
- outer span equals size minus 24;
- nonzero big-endian geometry;
- image-header size equals 28;
- 12 reserved bytes are zero;
- payload-block span equals size minus 52;
- raster allocation is bounded to 16 MiB.

The two integrity fields and codec word remain opaque and are omitted from
public output.

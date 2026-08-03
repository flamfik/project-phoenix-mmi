# SPEC-065 - LOD shifted-grid reuse

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 057
- Related questions: RQ-207-RQ-209

## Contract

Exact content reuse is tested at block sizes 128, 256, 512 and 1,024 and at
four quarter-block origins. Hash values remain private.

## Result

All twenty grids contain content shared by all five sources. Reuse is robust
to the tested scale and origin but does not imply a record or runtime owner.

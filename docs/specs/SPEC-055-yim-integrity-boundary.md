# SPEC-055 - YIM integrity boundary

- Version: 0.1
- Maturity: DRAFT
- Evidence: Session 047
- Related questions: RQ-175-RQ-177

## Frozen candidates

Test CRC32/IEEE, Adler-32, byte sum, CCITT CRC with two initial values, IBM
CRC and 16-bit byte sum over four fixed encoded/decoded ranges.

## Result and policy

No candidate matches either opaque field in any registered source.

```text
read_only_decode = allowed
repack_or_install = blocked
```

The negative result is bounded to the declared matrix.

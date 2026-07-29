# SPEC-061 - embedded XIM2 resources

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 053
- Related questions: RQ-194-RQ-197

## Acceptance contract

An embedded record is accepted only when:

- `XIM2` is at the candidate start;
- outer span remains in bounds;
- geometry is positive and within the safety cap;
- image-header size, reserved area and payload span close;
- the 16-bit-unit RLE stream consumes exactly the encoded input;
- decoded size equals width times height times two.

## Corpus result

CD1 and CD3 each contain 84 accepted, unique resources across 15 geometries.
Their encoded and decoded content sets are identical. One standalone YIM source
matches one embedded resource exactly in both representations.

## Publication rule

Offsets, bytes, decoded rasters and content hashes remain private.

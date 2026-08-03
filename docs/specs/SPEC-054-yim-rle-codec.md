# SPEC-054 - YIM bounded RLE codec

- Version: 0.1
- Maturity: ALPHA, DECODER ONLY
- Evidence: Session 046
- Related questions: RQ-172-RQ-174

## Decode rules

Read big-endian 16-bit commands. The lower 15 bits are a nonzero count of
two-byte units. A clear high bit repeats the following unit; a set high bit
copies the following units literally.

Reject truncation, zero counts, output overflow, trailing bytes and output
whose length differs from `width * height * 2`.

## Safety

Decoded bytes remain in memory. The specification does not define pixel
channels, encoding, integrity fields or an installable package.

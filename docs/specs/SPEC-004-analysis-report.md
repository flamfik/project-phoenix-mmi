# SPEC-004 — Phoenix static-analysis reports

- Version: 1.0
- Maturity: ALPHA
- Schemas: `phoenix-mmi.analysis/v1`, `phoenix-mmi.public-summary/v1`, `phoenix-mmi.comparison/v1`

## Local report

The full local report contains artifact identity, header preview, every signature candidate, validator result, 64 KiB entropy windows, long filler runs, publication-safe string aggregates, candidate segments and checksum tests. It is generated under ignored `research/firmware-5570/work/`.

## Public summary

The public summary retains only:

- ISO/member identities and SHA-256;
- SHA-256 identity of the local 64-byte header window and validated magic at offset zero;
- validated format counts and resource metadata/hashes;
- entropy measurements and filler offsets;
- fixed technical-marker counts/offsets, never arbitrary raw strings;
- complete sequential checksum layouts;
- explicit publication-safety flags.

No schema contains firmware payload bytes or exported resource bytes. Unknown schema major versions must be rejected.

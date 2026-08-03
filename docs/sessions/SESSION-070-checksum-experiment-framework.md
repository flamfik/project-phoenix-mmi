# Session 070 - Checksum experiment framework

- Date: 2026-07-29
- Objective: implement M2-X4.
- Status: COMPLETE; operational graph v62.

## Result

`ChecksumExperiment` binds one algorithm, explicit bounded region and optional
expected value. The initial registry supports CRC32/IEEE, Adler-32 and SUM16.
Every experiment yields `MATCH`, `NO_MATCH` or `OBSERVED`; negative results
are first-class evidence rather than discarded guesses.

The sanitized control produced one observation and one deliberate non-match.
`M2-CAP-026` is IMPLEMENTED and M2-X4 passes. Full report:
`research/milestones/m2/session070/checksum-experiment-summary.json`.

## Preserved blockers

This framework does not solve YIM integrity fields or METAINFO
`MetafileChecksum`. `M2-CAP-015` and `M2-CAP-016` remain BLOCKED. No unknown
algorithm is guessed or bypassed.

# Session 047 - YIM integrity boundary

- Date: 2026-07-29
- Objective: test common interpretations of the two leading ASCII fields
  without adapting an algorithm to the five files.
- Mode: read-only candidate census.
- Status: COMPLETE for the fixed candidate matrix.

## Frozen matrix

Four ranges are tested independently:

- bytes after the ASCII preamble;
- bytes after `XIM2`;
- encoded RLE payload;
- private decoded raster.

The 32-bit field is compared with CRC32/IEEE, Adler-32 and a byte sum. The
16-bit field is compared with CCITT CRC using initial values 0 and `0xffff`,
IBM CRC and a byte sum.

## Result

Across five sources:

```text
32-bit matches = 0
16-bit matches = 0
```

This is a bounded negative over 28 algorithm/range combinations per source.
It is not evidence that the fields are not checksums; byte order, polynomial,
initial/final XOR, field masking, chained computation or another protected
range may differ.

## Safety decision

```text
safe_yim_repack = BLOCKED
```

The validated read-only decoder may be used for inspection and comparison.
No encoder, checksum writer or installable update is created.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S047-01 | CLOSED, BOUNDED NEGATIVE | No frozen common candidate matches either field. |
| S047-02 | OPEN | The actual integrity algorithm and protected range remain unknown. |
| S047-03 | CONFIRMED SAFETY GATE | Repacking remains blocked. |

## Deliverables

- fixed integrity candidate matrix;
- explicit unresolved-field classification;
- SPEC-055;
- operational graph v39.

## Next step

Session 048 characterizes LOD without forcing it into the YIM, Intel HEX or
S-record models.

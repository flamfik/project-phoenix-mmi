# SPEC-020 - Navigation payload partition graph

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 012
- Related questions: RQ-022, RQ-030, RQ-032, RQ-034

## Confirmed structural model

The registered medium contains a cross-family partition domain of exactly 16
IDs, numbered 0 through 15:

- all 3,462 XAC headers carry an in-range ID and collectively cover the domain;
- ORT, PLZ and POI each independently provide one complete 16-ID set;
- B and V each provide a complete Cartesian set of 16 IDs by two levels;
- B contains one additional singleton that does not invalidate the paired set.

The cross-family agreement confirms a structural partition graph. It does not
identify countries, regions, coordinate tiles, routing levels or code consumers.

## XAC bounded header fields

| Offset | Width | Field | Status |
|---:|---:|---|---|
| `0x10` | 4 | big-endian header size | CONFIRMED value 176 |
| `0x2C` | 14 | timestamp-shaped field | CONFIRMED SHAPE, value private |
| `0x3C` | 14 | timestamp-shaped field | CONFIRMED SHAPE, value private |
| `header+0x00` | 4 | big-endian first subrecord type | CONFIRMED value 2 |
| `header+0x04` | 2 | big-endian partition ID | CONFIRMED domain 0..15 |

## Confidence boundary

`CONFIRMED_CROSS_FAMILY_16_PARTITION_TOPOLOGY` means only that the same finite
ID domain is encoded consistently across independent media families. The
following remain `OPEN`:

- semantic meaning of each ID;
- spatial/geographical assignment;
- B/V level meaning;
- XAC payload grammar after the first subrecord header;
- runtime selector or consumer;
- compatibility of regenerated partitions.

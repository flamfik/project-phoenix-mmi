# Session 045 - YIM/XIM2 envelope

- Date: 2026-07-29
- Objective: define and validate the fixed YIM/XIM2 envelope.
- Mode: read-only structural parsing.
- Status: COMPLETE for all five registered contents.

## Validated layout

```text
0x00  ASCII hexadecimal preamble, 24 bytes
0x18  "XIM2"
0x1c  outer span
0x20  width, 16-bit big-endian
0x22  height, 16-bit big-endian
0x24  image-header size
0x28  reserved zero area, 12 bytes
0x34  payload-block span
0x38  opaque codec word
0x3c  encoded payload
```

The preamble contains two still-opaque integrity fields, an ASCII file size
and an ASCII version. Raw integrity values and the opaque codec word are not
published.

## Results

- five of five envelopes validate;
- ASCII file size equals physical file size;
- outer span equals `file_size - 24`;
- image-header size is 28 in every source;
- the 12-byte reserved region is zero in every source;
- payload-block span equals `file_size - 52`;
- all sources declare 480 by 240 units;
- encoded payload begins at offset 60.

An independent [2013 community note](https://mycarfreak.blogspot.com/2013/02/mmi-2g-startscreen-fileformat-yim.html)
describes the same offsets and geometry. It is corroboration only; the
project classification rests on the registered files and strict parser.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S045-01 | CONFIRMED | The 60-byte envelope is structurally consistent in five sources. |
| S045-02 | CONFIRMED | All independent length relationships close exactly. |
| S045-03 | CONFIRMED | All sources declare one 480 by 240 geometry. |
| S045-04 | OPEN | The two leading fields and codec word remain semantically opaque. |

## Deliverables

- strict `parse_yim_envelope`;
- bounded raster-size gate;
- public envelope projection;
- SPEC-053;
- operational graph v37.

## Next step

Session 046 validates the encoded payload grammar while retaining decoded
bytes only in memory.

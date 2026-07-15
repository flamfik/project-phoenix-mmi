# SPEC-010 - Reference graph and owner evidence

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 007, registered CD1/CD3 principal images
- Related questions: RQ-015, RQ-017, RQ-018, RQ-019

## Scope

This specification defines the publication-safe graph used to relate a source runtime-address table, a relocated fixed-record block and a nearby descriptor-like pointer structure. It also defines the evidence threshold for assigning a subsystem owner.

## Graph nodes and edges

Nodes are identified by file offsets derived from the Session 006 runtime model:

```text
file_offset = runtime_address - 0x0C000000
```

An exact edge requires a complete big-endian 32-bit runtime word. The public graph records the source run/index and a named target; it does not publish the complete source table.

Confirmed run-0 edges in both releases:

```text
source entry 1  -> record-block-start
source entry 11 -> record-block-start
```

## Descriptor normalization

A descriptor candidate is anchored by an exact pointer to `record-block-end`. Aligned 32-bit fields within `[-0x40, +0x44]` of the anchor are retained only when they map inside the principal image. Each retained field is normalized as:

```text
(field_offset - descriptor_anchor, target_file_offset - record_block_start)
```

Nine normalized pairs are common to both releases:

| Field relative offset | Target delta from block |
|---:|---:|
| `0x00` | `0x100` |
| `0x0C` | `0xE20` |
| `0x10` | `0xE40` |
| `0x1C` | `0xF80` |
| `0x20` | `0xF84` |
| `0x2C` | `0x1004` |
| `0x30` | `0x1010` |
| `0x3C` | `0x1028` |
| `0x40` | `0x13A8` |

The descriptor anchor is `-0x1FF4` from the block in both images, and both relocate by `0x4F0DC`. Status: `CONFIRMED_RELOCATED_DESCRIPTOR_GRAPH`.

The term descriptor describes the observed pointer topology only. No field name, C type, record schema or runtime mutability is specified.

## Marker profile

The fixed vocabulary is:

```text
html, http, mime, url, browser, gif, jpeg
```

Search is ASCII case-insensitive inside a fixed `+/-0x10000` window centered on the record block. Public output contains vocabulary, counts and relative-position aggregates only. It contains no arbitrary strings or surrounding bytes.

Cross-version equality of marker count and ordered marker names is structural context. It is not a direct reference.

## Owner evidence policy

| Level | Minimum evidence |
|---|---|
| `NOT_CONFIRMED` | Fewer than two independent contextual signals. |
| `PROBABLE_*` | At least two independent contextual signals reproduced in both releases. |
| `CONFIRMED_*` | Direct code/dataflow referrer or equivalent semantic evidence, also reproduced cross-version. |

For Session 007, source-table location and marker-profile preservation meet the `PROBABLE_BROWSER_SUPPORT_REGION` threshold. The absence of a direct consumer keeps `confirmed = false`.

## Publication boundary

Public reports may include artifact hashes, file offsets, counts, normalized field pairs, named fixed markers and evidence status. They must exclude firmware bytes, target-window bytes, raw runtime pointer values, complete pointer runs, raw HTML/URIs and arbitrary extracted strings.

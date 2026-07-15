# SPEC-012 - Firmware operational evidence graph

- Version: 0.2
- Maturity: ALPHA
- Evidence: Sessions 001-009
- Related questions: RQ-002, RQ-009, RQ-010, RQ-015, RQ-017, RQ-019, RQ-021, RQ-022, RQ-023

## Purpose

The operational graph is a machine-readable synthesis of verified structures, probable runtime relations and known gaps. It is not a dynamic trace and must never turn an absent edge into an implicit assumption.

## Node status

| Status family | Meaning |
|---|---|
| `CONFIRMED*` | Direct, reproducible structural or metadata evidence exists. |
| `PROBABLE*` | Multiple contextual signals support the interpretation. |
| `PARTIAL` | A structure is mapped but its full role is unknown. |
| `HYPOTHESIS` | A plausible relation has no direct chain yet. |
| `OPEN` | The boundary has not been mapped. |

Semantic status may be separate from structural status. The bitmap atlas is the reference case: its structure is confirmed while glyph semantics remain probable.

## Model layers

### Update layer

- three-disc package and per-device payload topology;
- METAINFO five-part selection hierarchy and aliases;
- segmented checksum grid;
- bootloader/application policy;
- exact CD1-to-CD3 EEPROM state handoff;
- probable MOST inventory and transfer behavior.

### Runtime layer

- big-endian SH-3 entry at file offset zero;
- bounded Wind River/VxWorks runtime fingerprint;
- runtime-linked principal image at `0x0C000000`;
- probable network-facing MOST services;
- separate peripheral firmware boundaries.

### UI/resource layer

- embedded HTML and GIF/JPEG bundle;
- post-cluster runtime-address tables;
- exact edges and descriptor graph into a relocated bitmap region;
- probable 1 bpp glyph/browser rendering path.

### Explicit gaps

- direct renderer consumer;
- address runs 1 and 3;
- exact navigation engine/module boundaries, despite confirmed subsystem presence;
- map-data format and DVD interface;
- internal backing-volume or proprietary object-store layout, despite confirmed dosFs/FAT/TFFS runtime support;
- complete VxWorks task/module table.

### Session 009 refinement

Operational graph v2 splits the former navigation/storage hypotheses into independently graded nodes:

- navigation subsystem presence: `CONFIRMED_SUBSYSTEM_PRESENCE`;
- exact navigation boundary: `PARTIAL`;
- VxWorks dosFs/FAT/TFFS runtime stack: `CONFIRMED_BOUNDED`;
- CD-ROM/ISO-9660 reader support: `PROBABLE`;
- internal backing-volume layout: `OPEN`;
- map-media schema: `OPEN`.

No edge from the optical reader to map media is promoted above `HYPOTHESIS` without direct dataflow or an independently validated navigation medium.

## Rule for derived diagrams

Every diagram edge must carry the source/target node status or its own evidence status. Dotted or hypothesis edges must not be rendered as confirmed control flow.

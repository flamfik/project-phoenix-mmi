# SPEC-012 - Firmware operational evidence graph

- Version: 0.11
- Maturity: ALPHA
- Evidence: Sessions 001-018
- Related questions: RQ-002, RQ-009, RQ-010, RQ-015, RQ-017, RQ-019, RQ-021, RQ-022, RQ-023, RQ-037, RQ-041, RQ-042, RQ-043, RQ-044, RQ-045, RQ-046, RQ-047, RQ-048, RQ-049, RQ-050, RQ-051, RQ-052

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
| `BOUNDED_NEGATIVE` | A documented search model produced no candidate; alternatives outside that model remain open. |

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

### Session 010 refinement

Operational graph v3 adds independently graded firmware-side contracts:

- navigation-data bounded call-site pair: `CONFIRMED_CROSS_VERSION_CODE_COUPLING`;
- route-data record neighborhoods: `CONFIRMED_RELOCATED_STRUCTURE`, consumer `OPEN`;
- CD-ROM event/task record family: `CONFIRMED_RELOCATED_STRUCTURE`, dispatch semantics `OPEN`.

The edge from optical-service records to the probable optical-volume reader is
only `PROBABLE`. The route-record-to-navigation consumer edge and the
optical-reader-to-map-media edge remain `HYPOTHESIS`. Storage-marker proximity
for an indirect call target is not sufficient to promote either edge.

### Session 011 refinement

Operational graph v4 adds independently validated media-side layers:

- navigation ISO-9660/Joliet volume: `CONFIRMED_MEDIA_STRUCTURE`;
- FLDB fixed-record container set: `CONFIRMED_MEDIA_STRUCTURE`;
- map-media node: `PARTIAL_CONFIRMED_OUTER_FORMAT`;
- inner FLDB payload schemas and consumer: `OPEN`;
- firmware optical-reader to ISO-volume relation: `PROBABLE`;
- image provenance: `UNVERIFIED`.

The map-media node is no longer wholly open, but the graph does not connect the
confirmed FLDB layout to the navigation runtime as confirmed control flow.
Neither a matching filename nor a fixed FLDB vocabulary was found in the
principal firmware images under the tested probes.

### Session 012 refinement

Operational graph v5 adds:

- proprietary family headers/directories: `PARTIAL`;
- a cross-family 16-partition topology: `CONFIRMED_STRUCTURAL_PARTITION_GRAPH`;
- a declared speech text-index/binary-data split: `CONFIRMED_MEDIA_STRUCTURE`;
- a cross-version SH `0x220` candidate: `PROBABLE_STATIC_CONSTANT_COUPLING`.

The constant candidate is not promoted to a parser. The partition consumer,
sector-read ABI, internal backing volume and compatibility with modified map
data remain open.

### Session 013 correction

Operational graph v6 replaces the former probable `0x220` relation with:

- a byte-identical memory-mapped probe structure: `CONFIRMED`;
- probable boot-memory/hardware semantics: `PROBABLE` semantic property;
- the former edge from `0x220` to FLDB: `DISPROVED`;
- an explicit FLDB parser node: `OPEN`;
- parser-to-navigation and optical-reader-to-parser relations: `HYPOTHESIS`.

The correction prevents a numeric coincidence from silently surviving as a
runtime edge.

### Session 014 refinement

Operational graph v7 adds a role-sensitive global search result without
inventing a parser edge:

- seven relocation-normalized 36-byte loop pairs: `CONFIRMED` structure;
- one byte-identical write-only fixed-record initializer: `CONFIRMED_BOUNDED`;
- six generic arithmetic loops: `CONFIRMED_BOUNDED`;
- one navigation-adjacent numeric pair rejected because `36` is a call-field
  offset while the actual loops step by `40`: `BOUNDED_NEGATIVE`;
- FLDB parser, optical-sector ABI and optical-buffer provenance: `OPEN`.

The new `BOUNDED_NEGATIVE` edge records that the tested direct 36-byte loop
model did not locate the parser. It does not exclude multiplied indexing,
unrolled iteration, helper-mediated endian conversion or an interprocedural
consumer elsewhere in the image.

### Session 015 refinement

Operational graph v8 adds the bounded interprocedural search:

- 25 code-gated optical record-pointer seed pairs: `CONFIRMED_BOUNDED`;
- two unique Session 010 navigation roots: `CONFIRMED_CROSS_VERSION`;
- 35 node pairs and 20 deduplicated static-call edge pairs:
  `CONFIRMED_BOUNDED_ANALYSIS`;
- zero shared cross-domain node pairs and zero direct navigation-to-optical
  static edges: `BOUNDED_NEGATIVE`;
- 13 CD1 and 12 CD3 unresolved indirect calls: explicit object-dispatch gap;
- sector ABI, optical-buffer provenance and buffer owner: `OPEN`.

The negative edge is limited to the registered seeds, depth-two expansion and
direct/literal-backed call resolver. It does not cover callbacks, event queues,
vtable targets, computed calls or deeper chains.

### Session 016 refinement

Operational graph v9 adds bounded predecessor and descriptor evidence:

- four unique paired unresolved call sites after overlapping-root
  deduplication: `CONFIRMED_BOUNDED`;
- two optical literal-backed call-target pairs recovered before their original
  seeds: `CONFIRMED_PAIRED_CONTEXTUAL_LITERAL_CALL_TARGET`;
- zero new graph nodes because both target pairs fail the independent bounded-
  code expansion gate;
- two navigation call sites sharing one call-return-backed dynamic descriptor
  shape: `CONFIRMED_CROSS_VERSION_DYNAMIC_DESCRIPTOR_STRUCTURE`;
- outer target field displacement `12`, receiver adjustment path constant `8`
  and delayed selector `r5 = 3`: confirmed structural fields only;
- zero recovered navigation-to-optical edges: `BOUNDED_NEGATIVE`;
- dynamic method target, descriptor producer semantics, sector ABI, buffer
  owner and parser: `OPEN`.

The descriptor is not labeled a vtable and the literal targets are not labeled
function boundaries. Context is capped at `0x100` predecessor bytes and no
branch dominance is asserted.

### Session 017 refinement

Operational graph v10 adds producer and field-lineage evidence:

- two paired nearest-producer call sites with stable argument roles:
  `CONFIRMED_PAIRED_LITERAL_PRODUCER_CALL_SITES`;
- one unique producer target pair, but zero cross-version promotions because
  target evidence is asymmetric;
- one CD3-only forwarding chain to a field-12 accessor;
- 12 exact accessor occurrences per release and one paired six-member cluster:
  `CONFIRMED_CROSS_VERSION_ACCESSOR_CLUSTER`;
- broad static descriptor grammar around 20 of 31 optical target pairs, with
  zero bilateral direct base references: structural census only;
- zero code-gated direct mixed-width initializers among 18 paired analyzable
  signatures: `BOUNDED_NEGATIVE`;
- bilateral producer edge, sector ABI, optical-buffer provenance/owner, FLDB
  parser and partition consumer: `OPEN`.

The new node records a bounded analysis, not a runtime object identity. The
missing CD1 edge prevents promotion from accessor-family equivalence to a
cross-version producer lineage.

### Session 018 refinement

Operational graph v11 adds accessor call-family and runtime-slot evidence:

- 288 direct CD3 accessor calls and zero direct calls to the paired CD1
  accessor: `CONFIRMED_LITERAL_BACKED_ACCESSOR_CALL_FAMILY`;
- 179 unique normalized context matches and 266/288 single-target-consensus
  contexts: `CONFIRMED_BOUNDED_TARGET_CONVERGENCE`;
- one unique five-record CD1 `pointer + 12 zero` run containing the dominant
  target: `CONFIRMED_ZERO_TAIL_RUNTIME_POINTER_RECORD_RUN`;
- runtime patch, linkage and trampoline semantics: `HYPOTHESIS`;
- zero data-only target occurrences and zero direct static callback records:
  `BOUNDED_NEGATIVE`;
- zero intersections with the same pair among 35 registered graph nodes:
  `BOUNDED_NEGATIVE`;
- specific producer edge, optical relation, sector ABI, buffer provenance/
  owner, FLDB parser and partition consumer: `OPEN`.

The convergent CD1 address is not treated as static executable code. The graph
records a call-family transition and structural slot, not runtime equivalence.

### Session 019 refinement

Operational graph v12 expands the structural slot without naming a runtime
mechanism:

- three of 15 CD1 zero-tail words have literal-backed adjacent calls:
  `CONFIRMED_THREE_LITERAL_BACKED_CALL_TARGETS`;
- three compact CD3 direct entries have byte-identical translated bodies in
  CD1, all with zero direct calls: `CONFIRMED` static shadow layout;
- one slot/member mapping passes the fixed Session 018 promotion gate, one is
  probable below the gate and one remains a structural candidate;
- slot-to-static-body deltas `-368`, `-360`, `-352` are branch-feasible, but no
  branch encoding or runtime write is observed;
- 235,864 syntactic address seeds yield zero bounded direct stores to the run:
  `BOUNDED_NEGATIVE` search result;
- the exact 32-byte source/destination-pair model yields zero relocation
  records: `BOUNDED_NEGATIVE`;
- writer/loader chain, pointer-field roles, producer edge, sector ABI, buffer
  provenance/owner, FLDB parser and partition consumer: `OPEN`.

The new graph edge is a confirmed cross-version layout relation. It is not
runtime control flow. Patch, overlay or linkage behavior remains a strengthened
hypothesis until a concrete writer/loader chain is recovered.

## Rule for derived diagrams

Every diagram edge must carry the source/target node status or its own evidence status. Dotted or hypothesis edges must not be rendered as confirmed control flow.

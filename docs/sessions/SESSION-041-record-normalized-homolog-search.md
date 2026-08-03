# Session 041 - record-normalized homolog search

- Date: 2026-07-29
- Objective: repeat the frozen Session 040 target/control search after
  checksum-valid address reconstruction of supported record containers.
- Mode: read-only static analysis; decoded bytes remained private and no
  firmware was executed or modified.
- Status: COMPLETE for Intel HEX and validated Motorola S-record runs.

## Safety boundary

The runner verifies the three registered ISO hashes, the two principal-image
hashes and the Session 038-040 input classifications. It reads update members
directly from ISO extents and reconstructs bytes only in memory.

No gap is filled. No decoded region crosses an address discontinuity or an
opaque physical envelope gap. Vendor-specific Intel records are retained as
opaque metadata and never interpreted as data or address state.

## Source corpus

The fixed record-container corpus contains:

| Metric | Count |
|---|---:|
| Members | 215 |
| Member bytes | 172,611,997 |
| Unique source contents | 27 |
| Normalized unique sources | 17 |
| Unsupported unique sources | 10 |
| Validation-rejected unique sources | 0 |

Per disc:

| Disc | Members | Bytes | Members with validated decoded regions |
|---|---:|---:|---:|
| CD1 | 95 | 67,616,763 | 75 |
| CD2 | 0 | 0 | 0 |
| CD3 | 120 | 104,995,234 | 85 |

## Format validation

### Intel HEX

All 16 unique `.HEX` contents pass line grammar, byte-count, checksum, EOF,
address-state and overlap validation.

| Metric | Count |
|---|---:|
| Members | 154 |
| Unique contents | 16 |
| Standard-only contents | 10 |
| Contents with one opaque vendor record | 6 |
| Decoded bytes | 1,404,128 |
| Address-contiguous regions | 365 |
| Regions at least 240 bytes | 219 |
| Conflicting overlaps | 0 |

The six vendor-bearing contents use one first record of type `0x10` or
`0x11`, with count four and address field zero. Its payload is not
interpreted. Standard `0x00` data records remain independently
checksum-valid and are reconstructed according to the standard address
state.

### Motorola S-record envelope

The six `.SW` members are byte-identical and reduce to one source content.
The source contains a valid S-record subset plus opaque envelope material:

| Metric | Count |
|---|---:|
| Candidate record lines | 76,277 |
| Accepted checksum-valid records | 73,534 |
| Accepted `S3` data records | 73,533 |
| Accepted `S7` termination records | 1 |
| Invalid candidate lines | 2,743 |
| Decoded data bytes | 2,205,892 |
| Validated contiguous regions | 2,820 |
| Regions at least 240 bytes | 2,820 |
| Unvalidated envelope bytes | 329,914 |

The `S7` termination contract is valid. Invalid lines and opaque bytes split
regions even when adjacent decoded addresses might otherwise appear
continuous.

### LOD and YIM

Five unique `.LOD` and five unique `.YIM` contents do not satisfy Intel HEX
or Motorola S-record structure. They remain classified as unsupported binary
containers. Session 041 performs no speculative decoding and does not rescan
their already-tested raw bytes.

## Decoded corpus

After content deduplication:

| Metric | Count |
|---|---:|
| Unique decoded regions | 3,109 |
| Scannable unique regions | 3,012 |
| Unique decoded-region bytes | 3,570,586 |

The target and equal-geometry control remain exactly those frozen in Session
040.

## Results

### S041-01 - Intel HEX decoder is structurally validated

All 16 unique sources pass their applicable grammar, count, checksum, EOF,
address and overlap gates. Opaque vendor records are bounded and do not alter
the decoded data model.

### S041-02 - S-record recovery is deliberately partial

Every accepted `S3`/`S7` record passes byte-count and one's-complement
checksum validation. The 2,743 invalid candidates and 329,914 opaque bytes are
excluded and never used to bridge regions.

### S041-03 - No fixed target anchor occurs after decoding

Across 3,012 scannable unique regions:

```text
first target anchor occurrences     0
target geometry matches             0
target strong matches               0
first control anchor occurrences    0
control geometry matches            0
control strong matches              0
scan saturation events              0
```

### S041-04 - Record-normalized homolog remains absent

```text
record_normalized_homolog = NOT_FOUND_IN_VALIDATED_DECODED_REGIONS
cross_payload_owner = OPEN
semantic_owner = OPEN
exact_section_boundary = OPEN
runtime_loader_transform = NOT_OBSERVED
```

This is a bounded negative for supported, checksum-valid record regions. It
does not cover `.LOD`, `.YIM`, compression, encryption, relocation
normalization or runtime-created data.

## Operational graph v34

Graph v34 contains 68 nodes and 82 edges. It adds the record-normalized
homolog census and one bounded-negative owner edge. It adds no runtime,
loader, media-format or semantic-owner edge.

## Phoenix SDK 0.39 deliverable

Session 041 adds:

- strict Intel HEX grammar, length, checksum, EOF and address validation;
- bounded opaque handling for vendor record types `0x10` and `0x11`;
- Motorola S-record byte-count and checksum validation;
- physical-envelope and address-continuity region splitting;
- normalized-region content deduplication;
- reuse of the unchanged target/control signature;
- publication-safe format and normalization profiles;
- operational graph v34;
- nine new synthetic unit tests.

The complete suite contains 225 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S041-01 | CONFIRMED | Sixteen unique Intel HEX sources are safely normalized. |
| S041-02 | CONFIRMED, PARTIAL | The accepted S3/S7 subset is checksum-valid; opaque material is excluded. |
| S041-03 | CLOSED, BOUNDED NEGATIVE | Neither target nor control first anchor occurs in validated decoded regions. |
| S041-04 | OPEN OUTSIDE MODEL | Unsupported binary containers and transformed forms remain unresolved. |

## Next step

Session 042 should use a frozen distributed near-homolog constellation:
two non-overlapping 12-byte subanchors from each of the five Session 040
anchors, with fixed quality gates, at least four exact subanchors from at
least three parent zones and at least 60% full-component similarity. The same
model must be applied to an equal-geometry control across both raw and
record-normalized domains.

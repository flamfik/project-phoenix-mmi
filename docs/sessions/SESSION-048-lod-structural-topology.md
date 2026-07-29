# Session 048 - LOD structural topology

- Date: 2026-07-29
- Objective: measure cross-language LOD structure without speculative
  payload reconstruction.
- Mode: read-only opaque-binary topology.
- Status: COMPLETE for five registered contents.

## Corpus

- five unique language payloads;
- sizes from 2,195,064 to 2,421,270 bytes;
- entropy from 6.42604115 to 6.64332020 bits/byte;
- zero-byte ratios from 0.22609811 to 0.24956129;
- `0xff` ratios from 0.03809984 to 0.04173272.

## Results

- common prefix: 3 bytes;
- common suffix: 18 bytes;
- aligned bytes equal in all five sources: 104,369;
- aligned all-source equality over the minimum span: 4.754713%;
- 256-byte content blocks shared by all five sources: 34;
- pairwise shared block-content counts range from 34 to 3,027.

The family is therefore neither random nor a set of independent opaque
blobs. It contains measurable cross-language reuse, but alignment changes and
language-specific content prevent a simple fixed-offset segmentation.

## Interpretation boundary

The common prefix/suffix and block reuse do not define record lengths,
addresses, checksums, compression or executable boundaries. No LOD byte is
decoded or exported.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S048-01 | CONFIRMED | Five LOD contents form one structurally related family. |
| S048-02 | CONFIRMED | Cross-language block reuse exists. |
| S048-03 | OPEN | Record, address and integrity models are not established. |
| S048-04 | BLOCKED | LOD payload reconstruction is not yet justified. |

## Deliverables

- cross-source prefix/suffix and aligned equality census;
- content-only 256-byte block reuse statistics;
- filler and entropy profiles;
- SPEC-056;
- operational graph v40.

## Next step

Session 049 searches only the now-validated private YIM rasters with the
unchanged Session 042 target and control.

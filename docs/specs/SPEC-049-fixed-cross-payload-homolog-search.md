# SPEC-049 - fixed cross-payload homolog search

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 038-040
- Related questions: RQ-143-RQ-150

## Purpose

Define a controlled raw-payload search for a contiguous homolog of the stable
Session 038 component.

## Input gate

The input must:

- reproduce all three registered ISO hashes;
- reproduce both principal-image hashes;
- use `phoenix-mmi.run-gap-topology-comparison/v1`;
- use `phoenix-mmi.registered-provenance-comparison/v1`;
- retain the stable 240-byte component;
- retain the Session 039 bounded-negative registry result and open owner.

## Target anchors

Select every exact run in the promoted component whose length is exactly 25
bytes. Exactly five positions are required.

Every anchor must satisfy:

```text
length = 25
distinct bytes >= 8
Shannon entropy >= 2.5
```

The signature must contain at least three distinct byte patterns and have no
pattern overlap with the control signature.

Raw anchor bytes and their hashes are private.

## Geometry and strong-match gate

The first anchor is searched exactly. For each occurrence, derive the
candidate component base from its registered relative offset. The other four
anchors must match at their exact registered offsets.

The five anchors contribute 125 exact bytes. A strong homolog additionally
requires:

```text
best full-component similarity >= 0.75
```

against either registered release component.

## Control

Use 240 bytes beginning at the Session 038 overlap start. Read five control
anchors at the same relative offsets and under identical quality, geometry,
similarity and saturation gates.

## Corpus

Include only ISO members:

- from CD1, CD2 or CD3;
- with extension `BIN`, `HEX`, `LOD`, `YIM` or `SW`;
- with size at least 240 bytes.

Exclude any member whose complete SHA-256 equals either principal image.
Deduplicate all remaining contents by complete SHA-256 before searching.
Retain member multiplicity for aggregate reporting.

## Fixed saturation limits

```text
first-anchor occurrences per unique payload <= 4096
geometry matches per unique payload <= 256
```

Any exceeded limit makes the model inconclusive. Thresholds may not be
adapted after inspecting a payload.

## Classification

```text
target strong > 0, control strong = 0
  CROSS_PAYLOAD_HOMOLOG_SUPPORTED

target geometry > 0, target strong = 0, control strong = 0
  ANCHOR_GEOMETRY_CANDIDATE_ONLY

control strong > 0
  MODEL_NOT_DISCRIMINATING_CONTROL_HIT

any saturation
  INCONCLUSIVE_SCAN_SATURATED

otherwise
  NOT_FOUND_UNDER_FIXED_SIGNATURE_MODEL
```

A positive homolog is structural provenance only. It cannot identify a
semantic owner without independent component metadata or dataflow.

## Session 040 result

- five anchor positions, three distinct target patterns, 125 anchor bytes;
- 590 eligible members and 435,574,832 eligible bytes;
- four principal-image copies excluded;
- 586 scanned members and 384,285,768 scanned member bytes;
- 133 unique contents totaling 81,647,732 bytes;
- zero target first-anchor occurrences;
- zero target geometry or strong matches;
- zero corresponding control occurrences or matches;
- zero saturation events;
- raw cross-payload homolog not found;
- semantic owner and exact section boundary open.

## Interpretation boundary

The result applies to contiguous bytes as stored in ISO members. It cannot
exclude:

- Intel HEX or other record-decoded byte order;
- compressed or encrypted content;
- split or interleaved sections;
- relocation-normalized code or data;
- externally supplied link/loader material;
- runtime-created content.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, member paths for
positive hits, sizes, extensions, counts, entropy, ratios and statuses.

They must not contain firmware bytes, payload bytes, component/signature
bytes, signature hashes, instruction bytes, mnemonic names, raw strings,
pointer values, absolute runtime addresses, local paths, extracted resources
or map payloads.

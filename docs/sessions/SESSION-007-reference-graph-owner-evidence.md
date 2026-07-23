# Session 007 - Reference graph and bounded owner evidence

- Date: 2026-07-15
- Objective: trace exact references around the Session 006 record block and the browser post-cluster source runs, compare their normalized structure across MMI 5150/5570, and evaluate ownership without promoting contextual evidence to fact.
- Mode: read-only static analysis; firmware was never executed.
- Status: COMPLETE for the declared exact-address, PC-relative, descriptor-window and marker-profile probes.

## Safety gates

The runner re-verifies both ISO SHA-256 values and both principal-image hashes before analysis. It extracts only the selected principal BINs into an operating-system temporary directory and removes them afterward. It neither executes nor writes firmware.

Owner classification was fixed before analysis:

- two independent contextual signals may support `PROBABLE`;
- `CONFIRMED` requires a direct code/dataflow referrer or equivalent semantic evidence;
- a relocated structure alone cannot identify its subsystem.

## Confirmed findings

### S007-01 - Two run-0 entries point to the record-block start

The runtime word for the confirmed 256-byte block start occurs exactly twice in each image. Both occurrences are in post-cluster run 0, at source entry indices 1 and 11. This establishes two source-to-target edges without publishing the complete pointer run.

Status: `CONFIRMED`.

### S007-02 - A relocated descriptor graph precedes the block

The sole exact runtime word for the first byte after the block occurs at:

| Property | CD1 / 5150 | CD3 / 5570 |
|---|---:|---:|
| Record block | `0xAC3DC` | `0xFB4B8` |
| Descriptor anchor | `0xAA3E8` | `0xF94C4` |
| Anchor relative to block | `-0x1FF4` | `-0x1FF4` |

The descriptor and block both relocate by `0x4F0DC`. A bounded aligned scan around the anchor finds nine fields with the same field-relative offsets and the same target deltas from the block in both releases. The graph is therefore `CONFIRMED_RELOCATED_DESCRIPTOR_GRAPH`.

This confirms structure, not the meaning of each field or the owner of the graph.

### S007-03 - Browser marker profile is structurally preserved

Within a fixed `+/-0x10000` window around each block, a predefined vocabulary produces 85 marker occurrences in both images:

| Marker | Count per release |
|---|---:|
| `browser` | 1 |
| `gif` | 11 |
| `html` | 31 |
| `http` | 33 |
| `jpeg` | 2 |
| `url` | 7 |
| `mime` | 0 |

Counts and ordered marker names are identical. Ten marker/name-relative-offset pairs are exact. Ordinal pairing produces four relative shift groups: `-56` (66), `+236` (16), `+720` (2), and `+776` (1). This confirms a preserved technical-vocabulary layout with staged internal shifts, not a byte-identical region.

### S007-04 - Exact direct-reference probe is negative

The declared browser boundaries, all four source-run boundaries, and the record-block boundaries were searched as exact big-endian runtime words. Every exact occurrence was then tested for a SuperH PC-relative `MOV.L` referrer using exact literal-address arithmetic.

No declared browser/source boundary address occurs in either principal image. The block-start and block-end occurrences described above have zero PC-relative `MOV.L` referrers. This is a `CONFIRMED_BOUNDED_NEGATIVE`, limited to exact absolute runtime words and the implemented instruction form.

## Owner assessment

Two independent contextual signals agree:

1. both confirmed source edges originate in the confirmed browser post-cluster area;
2. the target neighborhood preserves the browser marker count and order across releases.

The normalized descriptor graph is a third structural signal, but does not itself identify a browser subsystem. Because no direct code/dataflow referrer identifies an owner, the result is:

```text
PROBABLE_BROWSER_SUPPORT_REGION
confirmed = false
```

The label intentionally means browser-support adjacency/ownership is the best current explanation. It does not prove that the 16 records are UI images, URLs, MIME records, or executable browser code.

## Phoenix SDK 0.5 deliverable

Session 007 adds `phoenix_mmi.reference_graph` with:

- explicit anchor construction from prior published evidence;
- exact runtime-word occurrence and SH PC-relative referrer searches;
- source-run to block-edge extraction;
- bounded descriptor-candidate normalization;
- fixed-vocabulary marker profiles;
- cross-version graph and owner-policy comparison;
- public-report sanitization;
- a registered-ISO Session 007 runner;
- three synthetic tests, bringing the suite to 21 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S007-01 | CONFIRMED | Run 0 contains two exact edges to the record-block start in both releases. |
| S007-02 | CONFIRMED, STRUCTURAL | A nine-field normalized descriptor graph relocates with the block. |
| S007-03 | CONFIRMED, STRUCTURAL | Browser marker counts/order are preserved near the block. |
| S007-04 | CONFIRMED, BOUNDED NEGATIVE | No exact PC-relative `MOV.L` referrer was found for the declared anchors. |
| S007-05 | PROBABLE | The target is part of, or adjacent to, a browser-support region. |
| S007-06 | NOT CONFIRMED | A code-level owner and the 16-record schema remain unidentified. |

## Reproduction

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
python tools/session007/analyze_reference_graph.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session007 \
  --public-output research/firmware-5570/session007
```

## Limits

- Exact word searches do not cover computed addresses, base-plus-displacement construction, register propagation or indirect table walks.
- The SuperH referrer probe recognizes exact PC-relative `MOV.L` literals only.
- Technical-marker adjacency is contextual evidence and cannot name a record schema.
- The descriptor window is deliberately bounded; version-specific fields outside the nine-field intersection remain uninterpreted.
- Public reports contain offsets, counts, hashes and normalized field relationships only; no firmware bytes, target bytes, raw HTML/URIs, arbitrary strings or full pointer runs are included.

## Recommended Session 008

Trace consumers of the descriptor graph rather than widening the owner label. Start from the descriptor anchor and its nine common targets, add bounded SH-3 base-plus-displacement/register-flow patterns, and require the same normalized consumer structure in both releases. Keep all write, repack and vehicle operations out of scope.

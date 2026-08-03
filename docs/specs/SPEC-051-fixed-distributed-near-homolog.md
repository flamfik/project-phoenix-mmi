# SPEC-051 - fixed distributed near-homolog model

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 038-042
- Related questions: RQ-158-RQ-165

## Purpose

Define a bounded near-homolog search that remains discriminating after no
complete 25-byte anchor survives in raw or validated decoded payload data.

## Derivation

Use the five exact 25-byte anchors registered by SPEC-049. From each parent
select exactly:

```text
[0, 12)
[13, 25)
```

This produces ten fixed, non-overlapping 12-byte subanchors distributed
across five parent zones. Apply the same operation to the Session 040
equal-geometry control.

## Quality gates

Every target and control subanchor must satisfy:

```text
length = 12
distinct bytes >= 8
Shannon entropy >= 2.75
```

The target must contain at least six distinct patterns. Target and control
pattern sets must not overlap. Raw bytes and hashes remain private.

## Candidate gate

Search each subanchor exactly. Convert every occurrence into a candidate
component base using its registered relative offset.

A base is retained only when:

```text
exact subanchor positions >= 4
represented parent zones >= 3
```

Repeated byte patterns at different positions remain distinct positional
votes, but one occurrence cannot vote twice for the same position.

## Strong gate

Read exactly 240 bytes at the retained base. Compare the window independently
with both registered release components.

```text
strong candidate if best exact-byte similarity >= 0.60
```

The similarity gate is mandatory. Anchor geometry alone is not a homolog.

## Domains

Search separately:

- the content-deduplicated, non-principal raw corpus from SPEC-049;
- checksum-valid record-normalized regions from SPEC-050.

The implementation must reproduce the registered corpus counts before
searching. A mismatch terminates the run.

## Saturation

```text
occurrences per anchor per unit <= 4096
constellation candidates per unit <= 256
```

Any exceeded limit makes the complete model inconclusive. Limits cannot be
changed after observing a corpus result.

## Classification

```text
any saturation
  INCONCLUSIVE_DISTRIBUTED_SCAN_SATURATED

control strong > 0
  DISTRIBUTED_MODEL_NOT_DISCRIMINATING

target strong > 0
  DISTRIBUTED_NEAR_HOMOLOG_SUPPORTED

target constellation candidate > 0
  DISTRIBUTED_CONSTELLATION_CANDIDATE_ONLY

otherwise
  NOT_FOUND_UNDER_FIXED_DISTRIBUTED_MODEL
```

A positive result provides structural provenance only. Semantic ownership
requires independent component metadata or dataflow.

## Session 042 result

- ten quality-gated target and ten control subanchors;
- six distinct target and ten distinct control patterns;
- zero target/control pattern overlap;
- 133 raw unique units and 81,647,732 raw bytes;
- 3,012 normalized scannable units and 3,566,108 decoded bytes;
- zero target and control subanchor occurrences in both domains;
- zero candidates, strong results or saturation events;
- distributed near-homolog not found;
- semantic owner and loader mechanism remain open.

## Interpretation boundary

The result cannot exclude a representation that changes every 12-byte
subanchor through:

- unsupported container decoding;
- compression or encryption;
- relocation or instruction rewriting;
- splitting or interleaving;
- external loading;
- runtime generation.

## Publication contract

Reports may contain artifact hashes, domain and corpus counts, anchor
positions and quality metrics, match counts, candidate offsets and
similarities for positive results, member paths and conservative
classifications.

They must not contain firmware, payload, decoded-region, component or
signature bytes; signature or payload hashes; raw strings; instruction bytes;
mnemonic names; pointer or address values; absolute runtime addresses; local
paths; extracted resources or map payloads.

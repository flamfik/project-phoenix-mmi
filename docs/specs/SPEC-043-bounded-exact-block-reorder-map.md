# SPEC-043 - Bounded exact-block reorder map

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 032-034
- Related questions: RQ-103, RQ-106, RQ-108, RQ-111-RQ-115

## Purpose

Define how Phoenix derives exact file-layout correspondence around a confirmed
section reorder without assuming a container, section table or loader
descriptor.

## Input gate

The input must:

- use the Session 033 relocation-descriptor schema;
- reproduce both principal-image hashes;
- preserve the confirmed Session 032 `SECTION_REORDER_BRACKET`;
- preserve `RZ-012` and `RZ-013` on both sides;
- retain the Session 033 simple-descriptor bounded-negative result.

## Search windows

Each zone defines one CD1/CD3 lane. A window extends by a fixed 128 KiB before
and after the exact zone extent and is clamped to the image.

The two lanes are independent. A match in one lane cannot be used as evidence
for the other lane unless it independently passes that lane's expected-delta
gate.

## Seed gate

Primary seeds are:

- 64 bytes long;
- aligned and sampled every four bytes;
- indexed with BLAKE2s-128;
- retained only when the digest is unique inside each side of the lane.

Every digest match must pass direct byte equality. Hash equality alone is never
accepted.

## Maximal extension

Adjacent or overlapping unique seeds at one relocation delta form a group.
Phoenix extends the group backward and forward while bytes remain exactly
equal and both offsets remain inside their declared lane windows.

The result is maximal only under those window bounds. Repeated seed blocks are
excluded, although low-information bytes may be included by exact contiguous
extension from a unique bilateral seed.

## Expected-delta gate

A block becomes reorder support only when:

```text
right_start - left_start == prior zone relocation delta
```

Other exact blocks are summarized as negative controls. They do not refine the
transition envelope.

## Transition envelope

Let:

- `L` be the Session 032 lower bound;
- `U` be the Session 032 upper bound;
- `E1` be the last expected-delta exact-block end from the first lane inside
  `[L, U)`;
- `S2` be the first expected-delta exact-block start from the second lane
  inside `[L, U)`.

If `E1 <= S2` and the two lane families do not overlap:

```text
new envelope = [max(L, E1), min(U, S2))
```

The envelope is a bounded file-layout transition. It is not automatically a
runtime section or loader boundary.

## Stability gate

The complete analysis is repeated with a 128-byte seed while retaining the
same windows and stride.

`CONFIRMED_STABLE` requires:

- exact-block support under both expected deltas in both runs;
- equal transition classification;
- equal lower bound, upper bound and width.

## Session 034 result

- `RZ-012`: 14 primary expected-delta blocks, 6,040 exact bytes;
- `RZ-013`: 263 primary expected-delta blocks, 57,912 exact bytes;
- both lanes have exact byte support;
- the envelope narrows from 183,523 to 146,841 bytes;
- the 128-byte control reproduces both bounds;
- exact section boundary remains open;
- compile/link placement is consistent but unproved;
- runtime loader transformation is not observed.

## Publication contract

Reports may contain hashes, generated block IDs, file-relative offsets,
lengths, relocation deltas, counts, window geometry, seed parameters,
transition bounds and evidence statuses.

They must not contain firmware bytes, raw seed digests, instruction bytes,
raw strings, raw pointers, absolute runtime addresses, local paths, map
payloads or extracted resources.

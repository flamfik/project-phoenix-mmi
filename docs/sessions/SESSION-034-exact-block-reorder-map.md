# Session 034 - Exact-block reorder map

- Date: 2026-07-28
- Objective: map byte-identical content around the two sides of `RB-015`
  without assuming another loader or descriptor grammar.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the declared two-window exact-block model.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes, the Session 003
principal-image hashes and the Session 033 input schema. It extracts only the
two principal members into a temporary directory and removes them after
analysis.

Only two lanes are searched:

- `RZ-012` in CD1 against `RZ-012` in CD3;
- `RZ-013` in CD1 against `RZ-013` in CD3.

Each lane is limited to 128 KiB on either side of its support zone. No
whole-image content search, adaptive threshold, firmware execution, resource
publication, repacking or vehicle operation is performed.

## Exact-block gate

The primary model uses:

- 64-byte seeds;
- four-byte alignment and stride;
- BLAKE2s-128 indexing;
- uniqueness inside both lane windows;
- direct byte verification after every hash match;
- maximal backward/forward extension only while bytes remain equal.

A block supports a reorder lane only when its relocation delta equals the
independently established Session 032 zone delta. Other exact matches remain
counted as controls but are not used to move the transition bounds.

The complete analysis is repeated with a stricter 128-byte seed. The transition
envelope is accepted as stable only when both runs return the same bounds.

## Confirmed findings

### S034-01 - Both reorder lanes have exact byte support

| Lane | Expected delta | All exact blocks | Expected-delta blocks | Exact bytes | Largest block |
|---|---:|---:|---:|---:|---:|
| `RZ-012` | 61,136 | 729 | 14 | 6,040 | 4,035 |
| `RZ-013` | -7,488,776 | 704 | 263 | 57,912 | 2,133 |

The `RZ-012` family contains one 4,035-byte exact block that covers the entire
marker zone and extends from file offset `7,828,232` through `7,832,267`.

The `RZ-013` family contains 263 exact blocks under the expected delta. Their
first transition-relevant block begins at CD1 offset `7,979,108`.

Therefore:

```text
file_layout_reorder_exact_block_support =
  CONFIRMED_AT_EXACT_BLOCKS
```

This confirms movement of byte-identical file content. It does not establish
runtime relocation, execution or semantic ownership.

### S034-02 - The transition envelope narrows by 36,682 bytes

Session 032 bounded the change to:

```text
[7,832,261, 8,015,784)
width = 183,523
```

Session 034 finds:

- the final `RZ-012` exact block ends at `7,832,267`;
- the first `RZ-013` exact block begins at `7,979,108`;
- the two exact families do not overlap in CD1.

The new bounded envelope is:

```text
[7,832,267, 7,979,108)
width = 146,841
```

The range is 36,682 bytes narrower, a reduction of approximately 20.0%.

The exact breakpoint remains open because changed or relocation-patched bytes
inside the envelope are not mapped.

### S034-03 - A stricter seed reproduces the same envelope

The 128-byte control retains:

| Lane | Primary blocks/bytes | Strict blocks/bytes | Largest equal |
|---|---:|---:|---|
| `RZ-012` | 14 / 6,040 | 6 / 5,292 | yes |
| `RZ-013` | 263 / 57,912 | 179 / 50,007 | yes |

Both runs produce the same lower bound, upper bound and width.

```text
strict_seed_control = CONFIRMED_STABLE
```

### S034-04 - Link placement is consistent, not proved

Session 033 found no simple internal copy/relocation table. Session 034 now
confirms that two content families occupy different file positions in the two
releases.

The result is consistent with compile/link-time section placement. It cannot
exclude an indirect, encoded or external loader transform because no loader
code or runtime behavior was observed.

## Operational graph v27

Graph v27 contains 56 nodes and 68 edges. It adds:

- a confirmed exact-block file-layout map;
- a stable narrowed transition envelope;
- no runtime loader, map-media or semantic-ownership edge.

## Phoenix SDK 0.32 deliverable

Session 034 adds:

- fixed per-zone window construction;
- bilateral unique-seed indexing;
- direct collision-resistant byte verification;
- maximal exact-block extension;
- independent expected-delta classification;
- two-lane transition-envelope refinement;
- 64/128-byte seed stability comparison;
- compact publication-safe summaries;
- operational graph v27;
- seven new unit tests.

The complete suite contains 159 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S034-01 | CONFIRMED, BYTE-EXACT | Both independently known reorder deltas contain verified exact blocks. |
| S034-02 | CONFIRMED, BOUNDED | `RB-015` narrows to `[7,832,267, 7,979,108)`. |
| S034-03 | CONFIRMED, STABLE | Seeds of 64 and 128 bytes produce the same transition envelope. |
| S034-04 | PARTIAL | Compile/link placement is consistent; loader transformation is not observed but remains possible. |
| S034-05 | OPEN | The exact section boundary and changed-byte grammar remain unresolved. |

## Next step

Session 035 should analyze only the remaining 146,841-byte envelope. A fixed
dual-delta similarity profile can compare each CD1 window against the two known
CD3 mappings (`+61,136` and `-7,488,776`) and locate a reproducible dominance
change. Any promotion must survive multiple fixed window sizes and must keep
the exact boundary open unless direct byte or decoded structural evidence
closes it.

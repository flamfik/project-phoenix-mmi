# Session 030 - Literal-pool boundary correction

- Date: 2026-07-27
- Objective: identify the complete structures containing the two Session 029
  targets and determine whether pool-end code is a proven runtime callee.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the two registered target pairs.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes and Session 003
principal-image hashes. Only the two principal members are extracted to a
temporary directory and removed after analysis.

The scan is restricted to:

- the two target pairs registered by Session 029;
- at most 16 runtime-range words before and after each target;
- exact PC-relative referrers for words inside those bounded runs;
- exact runtime-address words and direct `BSR` targets for the registered
  target and pool-end successor.

No arbitrary entry search, firmware execution, resource extraction, repacking
or vehicle operation was performed.

## Correction rule

A run is a confirmed literal pool only when:

1. it is maximal inside the declared bounds;
2. the registered target is one member of the run;
3. every run word has exactly one preceding PC-relative `MOV.L` referrer;
4. all referrer/use-role positions match across CD1/CD3;
5. pool boundaries share one structural relocation delta.

Code beginning at the pool end is reported separately. Adjacency and equal
shape do not make that code the runtime target.

## Confirmed findings

### S030-01 - Both registered targets lie inside complete literal pools

| Flow | Pool words | CD1 target index | CD3 target index | CD1/CD3 suffix words |
|---:|---:|---:|---:|---:|
| 12 | 4 | 1 | 0 | 3 / 4 |
| 13 | 6 | 4 | 3 | 2 / 3 |

The Session 029 “prefix” is therefore the suffix from the selected pool member
to the end of a larger pool. CD3 places both targets exactly one word earlier
than CD1; pool sizes remain equal.

### S030-02 - The complete pool grammar is bilateral

Every one of the ten pool words per release has exactly one preceding
PC-relative referrer.

The relative referrer positions and use roles are identical:

- flow 12: three indirect-control targets and one argument to another
  indirect call;
- flow 13: six indirect-control targets.

No raw pointer value is needed for this conclusion.

### S030-03 - Structural and raw-target relocation differ

Each registered runtime address still occurs exactly once as a PC-relative
literal feeding an indirect control target in both releases. The call
topology is therefore syntactically real; it is the base-only file mapping
that fails.

Both pool starts and ends relocate by:

```text
322532 bytes
```

The registered raw targets relocate by:

```text
322528 bytes
```

The common four-byte skew follows directly from the one-word target-index
shift. This proves that the tested base-only runtime mapping does not preserve
the surrounding file structure for these addresses.

### S030-04 - Pool-end code is adjacent, not a proven callee

The code immediately after both pools:

- passes the strict entry and bounded-code gates;
- is fully decoded;
- has equal normalized shape per CD1/CD3 pair.

However, all four pool ends have:

- zero exact runtime-address word occurrences;
- zero PC-relative referrers;
- zero direct `BSR` targets.

Status:

```text
pool_end_successor_code_family =
  CONFIRMED_BILATERAL_STRUCTURAL_ADJACENCY

pool_end_runtime_callee =
  NOT_ESTABLISHED
```

Computed, encoded or loader-created references were not tested.

## Correction to Session 029

Session 029 correctly located stable code after each selected word run, but
misclassified the run suffix as a function prefix. Session 030 replaces that
interpretation with:

```text
session029_prefix_interpretation =
  CORRECTED_TO_LITERAL_POOL_SUFFIX
```

Consequences:

- the local loader/section-metadata hypothesis is disproved for these words;
- the entry-`r5` negative result remains valid only for the adjacent
  pool-end successors;
- those successors are not proven runtime callees;
- the actual handoff callee, entry-`r5` use and registration path return to
  `OPEN`;
- the universal runtime-to-file map remains unestablished.

## Operational graph v23

Graph v23 contains 47 nodes and 57 edges:

- 39 confirmed nodes;
- four probable nodes;
- two open nodes;
- nine bounded-negative edges;
- one disproved edge.

It replaces the former “corrected callee” node with a confirmed literal-pool
family and a separate pool-end adjacency node. The old registration-disproof
edge is withdrawn and replaced by an open target edge.

## Phoenix SDK 0.28 deliverable

Session 030 adds:

- bounded bidirectional literal-pool recovery;
- full PC-relative reference coverage and use-role signatures;
- structural-versus-raw relocation comparison;
- exact runtime-word and direct-`BSR` boundary censuses;
- operational graph v23;
- a hash-gated runner and seven new unit tests.

The complete suite contains 135 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S030-01 | CONFIRMED, BOUNDED STRUCTURAL | Both raw targets are members of complete four- and six-word literal pools. |
| S030-02 | CONFIRMED, BILATERAL STRUCTURAL | All ten words per release have one preceding PC-relative referrer and equal relative use-role signatures. |
| S030-03 | CONFIRMED, STRUCTURAL | Pool boundaries relocate by 322,532 bytes while raw targets relocate by 322,528 bytes. |
| S030-04 | OPEN, BOUNDED NEGATIVE | Pool-end successors are equal code families but have no exact runtime-word or direct-BSR inbound reference. |
| S030-05 | CORRECTED | The Session 029 callee and entry-r5 disproof claims are withdrawn beyond the adjacent successor bodies. |

## Next step

Session 031 should build a bounded piecewise link-address/file-layout model
from the paired literal pools. It should group their referenced values by
cross-version relocation family and require independently paired code/data
anchors before proposing any real target mapping.

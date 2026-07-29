# Milestone M2 - Analysis Toolkit

Status: **IN PROGRESS**

Entry: Session 066

Evidence graph: v58

## Mission

Turn the read-only research code created during M1 into one coherent,
versioned and reproducible analysis toolkit. M2 standardizes identities,
format detection, parser results, checksum experiments, structural
comparisons, report schemas and command-line use.

## Entry gate

- Milestone M1 is complete;
- the registered archaeology and routing path is reproducible;
- safe mutation and installable-artifact gates remain false;
- all current implemented or partial toolkit capabilities pass their
  repository probes.

Session 066 passes this gate and freezes a registry of 27 capabilities:
8 implemented, 8 partial, 9 missing and 2 blocked.

## Exit criteria

| ID | Deliverable | Target session |
|---|---|---:|
| M2-X1 | versioned manifest and identity model | 067 |
| M2-X2 | declarative format registry | 068 |
| M2-X3 | normalized parser results and bounded LOD handling | 069 |
| M2-X4 | declarative checksum experiment framework | 070 |
| M2-X5 | generic structural diff engine | 071 |
| M2-X6 | schema registry and validation | 072 |
| M2-X7 | unified toolkit CLI | 073 |
| M2-X8 | deterministic sanitized-fixture integration gate | 074 |

M2 closes only when all eight criteria pass through the same machine-readable
capability audit introduced in Session 066.

## Safety boundary

M2 produces analyzers, normalized metadata and evidence reports. It does not
authorize firmware execution, payload mutation, media repacking, installation
or vehicle communication. Unknown YIM and METAINFO checksum algorithms remain
explicit blockers, not values to guess around.

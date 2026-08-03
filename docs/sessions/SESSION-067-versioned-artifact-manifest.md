# Session 067 - Versioned artifact manifest and identity model

- Date: 2026-07-29
- Objective: implement M2-X1 as one strict identity model for local files,
  media images and container members.
- Mode: read-only hashing and ISO member traversal; no extraction, execution,
  mutation or media creation.
- Status: COMPLETE; M2-X1 PASS; M2 remains IN PROGRESS.

## Result

Phoenix SDK 0.64.0 introduces `phoenix_mmi.manifest` and schema
`phoenix-mmi.artifact-manifest/v1`. The model separates three identity
layers:

| Layer | Purpose |
|---|---|
| logical ID | stable caller-assigned reference inside a research corpus |
| content ID | exact byte identity expressed as SHA-256 |
| artifact ID | deterministic v1 identity over logical ID, content, kind and parent/member provenance |

This prevents a duplicated payload from being confused with a duplicated
artifact instance. Equal content is tracked as a relationship; it is not an
error and does not imply equal semantics.

## Registered-media reproduction

The runner re-read all three registered MMI 5570 images and every non-directory
ISO member:

| Measurement | Result |
|---|---:|
| registered media roots | 3 |
| verified registered roots | 3 |
| container members | 593 |
| manifest records | 596 |
| member payload bytes | 435,708,503 |
| parent-member relationships | 593 |
| orphan records | 0 |
| unique byte contents | 141 |
| duplicate-content groups | 104 |
| records participating in duplicate groups | 559 |

The three root sizes, SHA-256 values and volume identifiers all match the
existing register. The 593-member and payload-byte totals independently
reproduce Session 001. The aggregate duplicate-group count also reproduces
the prior inventory.

## Validation contract

Schema v1 rejects:

- invalid or duplicate logical IDs;
- unsupported artifact and origin kinds;
- malformed SHA-256 values and negative sizes;
- missing parents, self-parenting and parent cycles;
- absolute, non-canonical or traversal container paths;
- stored content, artifact or manifest IDs that do not recompute;
- unsorted metadata and non-primitive metadata values.

Manifest-specific comparison reports additions, removals and changed identity
fields. This is not the generic structural diff planned for Session 071.

## Private and public outputs

The complete manifest is generated under ignored `work/session067`. It
contains source names, member locators and hashes required for local
reproduction.

The committed report contains only counts, status, schemas and capability
evidence. It includes no source name, logical/artifact/content ID, member path,
source hash, firmware byte or extracted resource.

## M2 transition

`M2-CAP-023` advances from `MISSING` to `IMPLEMENTED` through an explicit,
probed state transition. The frozen Session 066 registry is not edited, so its
historical report remains reproducible.

Current state:

- 9 implemented;
- 8 partial;
- 8 missing;
- 2 blocked;
- 1 of 8 M2 exit criteria passed.

Operational graph v59 adds `m2-versioned-artifact-manifest`.

## Limits

- generated member logical IDs prove stable path identity, not semantic
  equivalence across releases;
- equal SHA-256 values prove equal bytes only;
- the MMI 5570 replay models one ISO-member level, although the SDK parent
  graph supports nested relationships;
- schema v1 is validated by its model; the central multi-schema registry is
  intentionally reserved for Session 072;
- no write, repack, installation or vehicle-side capability is introduced.

## Next

Session 068 implements M2-X2: move validated fingerprint rules and confidence
requirements into a declarative format registry without weakening the current
positive structural gates.

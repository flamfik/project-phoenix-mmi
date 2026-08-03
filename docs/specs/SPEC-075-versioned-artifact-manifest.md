# SPEC-075 - Versioned artifact manifest

- Version: 1.0
- Maturity: BETA
- Evidence: Session 067
- Related questions: RQ-251-RQ-258
- Schema: `phoenix-mmi.artifact-manifest/v1`

## Scope

The manifest is a deterministic, read-only graph of research artifacts. It
models ordinary files, media images and container members without embedding
source bytes.

## Artifact record

Every record contains:

- `logical_id`: caller-assigned stable reference;
- `kind`: `file`, `media-image` or `container-member`;
- `size_bytes`;
- lowercase SHA-256 and derived `content_id`;
- deterministic `artifact_id`;
- origin scheme and private locator;
- optional parent logical ID;
- canonical primitive metadata.

`content_id` is `sha256:<digest>`. `artifact_id` is the SHA-256 of canonical
JSON containing schema version, logical ID, kind, size, content hash,
parent logical ID and, for a member, its canonical POSIX locator. A local
machine path is never part of this deterministic ID.

## Manifest record

The root contains:

- exact schema identifier;
- manifest logical ID;
- sorted artifact array;
- declared artifact count;
- deterministic manifest fingerprint.

On load, all derived values are recomputed. Unknown or missing schema-v1
fields are rejected.

## Parent graph

A container member must name an existing parent. Self-parenting, unknown
parents and cycles are invalid. Member locators must be non-empty relative
POSIX paths without backslashes, `.` or `..` components.

The schema allows nested parent graphs. Session 067 exercises the one-level
ISO image-to-member case.

## Duplicate and change semantics

Duplicate logical IDs are invalid. Duplicate content IDs are valid and
reported as groups because identical bytes can legitimately occur at multiple
container locations.

The manifest comparison contract keys records by logical ID and reports:

- added IDs;
- removed IDs;
- changed kind, size, hash, origin or metadata;
- unchanged IDs.

It does not infer semantic equivalence from equal content or a stable path.

## Publication reduction

`phoenix-mmi.artifact-manifest-summary/v1` publishes aggregate counts only.
It removes logical IDs, artifact IDs, content IDs, source names, local paths
and member paths. Full manifests remain in ignored local work directories.

## M2 gate

An importable `ArtifactManifest` symbol plus the real three-disc reproduction
passes `M2-CAP-023` and M2-X1. It does not pass the declarative format,
normalized parser, checksum, diff, schema-registry, CLI or integration
criteria.

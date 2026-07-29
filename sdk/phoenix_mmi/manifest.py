"""Versioned artifact identities and manifests for read-only analysis.

The model deliberately separates:

* a stable, human-assigned ``logical_id``;
* a content identity (SHA-256);
* a deterministic artifact-instance identity derived from both provenance
  and content.

Local locators and container-member paths are retained only in the private
manifest. :func:`build_public_manifest_summary` removes them.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Iterable, Mapping


MANIFEST_SCHEMA = "phoenix-mmi.artifact-manifest/v1"
PUBLIC_SUMMARY_SCHEMA = "phoenix-mmi.artifact-manifest-summary/v1"
ARTIFACT_KINDS = frozenset(
    {"file", "media-image", "container-member"}
)
ORIGIN_SCHEMES = frozenset({"local-file", "container-member"})
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_METADATA_KEY_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_JSON_PRIMITIVES = (str, int, bool)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _require_id(value: str, label: str) -> None:
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")


def _canonical_member_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("member locator must be a non-empty POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe container-member locator: {value!r}")
    canonical = path.as_posix()
    if canonical != value:
        raise ValueError(
            f"container-member locator is not canonical: {value!r}"
        )
    return canonical


def sha256_chunks(chunks: Iterable[bytes]) -> tuple[str, int]:
    """Hash a bounded byte stream and return its digest and observed size."""

    digest = hashlib.sha256()
    size = 0
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("artifact chunks must be bytes")
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class ArtifactOrigin:
    """Private provenance locator for one artifact instance."""

    scheme: str
    locator: str
    parent_logical_id: str | None = None

    def __post_init__(self) -> None:
        if self.scheme not in ORIGIN_SCHEMES:
            raise ValueError(f"unsupported origin scheme: {self.scheme!r}")
        if not self.locator or "\x00" in self.locator:
            raise ValueError("origin locator must be non-empty")
        if self.scheme == "local-file":
            if self.parent_logical_id is not None:
                raise ValueError("local-file origin cannot have a parent")
        else:
            if self.parent_logical_id is None:
                raise ValueError(
                    "container-member origin requires a parent"
                )
            _require_id(self.parent_logical_id, "parent logical ID")
            _canonical_member_path(self.locator)

    def to_dict(self) -> dict[str, object]:
        return {
            "scheme": self.scheme,
            "locator": self.locator,
            "parent_logical_id": self.parent_logical_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ArtifactOrigin":
        expected = {"scheme", "locator", "parent_logical_id"}
        if set(value) != expected:
            raise ValueError("origin fields do not match schema v1")
        parent = value["parent_logical_id"]
        if not isinstance(value["scheme"], str) or not isinstance(
            value["locator"], str
        ):
            raise TypeError("origin scheme and locator must be strings")
        if parent is not None and not isinstance(parent, str):
            raise TypeError("parent_logical_id must be a string or null")
        return cls(
            scheme=value["scheme"],
            locator=value["locator"],
            parent_logical_id=parent,
        )


@dataclass(frozen=True)
class ArtifactRecord:
    """One content-addressed artifact with explicit provenance."""

    logical_id: str
    kind: str
    size_bytes: int
    sha256: str
    origin: ArtifactOrigin
    metadata: tuple[tuple[str, str | int | bool], ...] = field(
        default_factory=tuple
    )

    def __post_init__(self) -> None:
        _require_id(self.logical_id, "logical ID")
        if self.kind not in ARTIFACT_KINDS:
            raise ValueError(f"unsupported artifact kind: {self.kind!r}")
        if not isinstance(self.size_bytes, int) or isinstance(
            self.size_bytes, bool
        ):
            raise TypeError("size_bytes must be an integer")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        if not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError("sha256 must be 64 lowercase hex digits")
        if (
            self.kind == "container-member"
        ) != (
            self.origin.scheme == "container-member"
        ):
            raise ValueError(
                "container-member kind and origin scheme must agree"
            )

        keys = []
        for key, value in self.metadata:
            if not _METADATA_KEY_RE.fullmatch(key):
                raise ValueError(f"invalid metadata key: {key!r}")
            if not isinstance(value, _JSON_PRIMITIVES):
                raise TypeError(
                    "metadata values must be strings, integers or booleans"
                )
            keys.append(key)
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError(
                "metadata must have unique keys in canonical order"
            )

    @property
    def content_id(self) -> str:
        return f"sha256:{self.sha256}"

    @property
    def artifact_id(self) -> str:
        identity = {
            "schema": "phoenix-mmi.artifact-identity/v1",
            "logical_id": self.logical_id,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "parent_logical_id": self.origin.parent_logical_id,
            "member_locator": (
                self.origin.locator
                if self.origin.scheme == "container-member"
                else None
            ),
        }
        return "artifact-v1:" + hashlib.sha256(
            _canonical_json(identity)
        ).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "logical_id": self.logical_id,
            "content_id": self.content_id,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "origin": self.origin.to_dict(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ArtifactRecord":
        expected = {
            "artifact_id",
            "logical_id",
            "content_id",
            "kind",
            "size_bytes",
            "sha256",
            "origin",
            "metadata",
        }
        if set(value) != expected:
            raise ValueError("artifact fields do not match schema v1")
        origin = value["origin"]
        metadata = value["metadata"]
        if not isinstance(origin, Mapping):
            raise TypeError("origin must be an object")
        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be an object")
        for field_name in ("logical_id", "kind", "sha256"):
            if not isinstance(value[field_name], str):
                raise TypeError(f"{field_name} must be a string")
        if not isinstance(value["size_bytes"], int) or isinstance(
            value["size_bytes"], bool
        ):
            raise TypeError("size_bytes must be an integer")
        if not all(isinstance(key, str) for key in metadata):
            raise TypeError("metadata keys must be strings")
        record = cls(
            logical_id=value["logical_id"],
            kind=value["kind"],
            size_bytes=value["size_bytes"],
            sha256=value["sha256"],
            origin=ArtifactOrigin.from_dict(origin),
            metadata=tuple(
                sorted((str(key), item) for key, item in metadata.items())
            ),
        )
        if value["content_id"] != record.content_id:
            raise ValueError("stored content_id does not match SHA-256")
        if value["artifact_id"] != record.artifact_id:
            raise ValueError("stored artifact_id does not match identity")
        return record

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        logical_id: str,
        kind: str = "file",
        metadata: Mapping[str, str | int | bool] | None = None,
    ) -> "ArtifactRecord":
        source = Path(path)
        if not source.is_file():
            raise FileNotFoundError(source)
        digest, size = sha256_chunks(_file_chunks(source))
        return cls(
            logical_id=logical_id,
            kind=kind,
            size_bytes=size,
            sha256=digest,
            origin=ArtifactOrigin("local-file", source.name),
            metadata=_canonical_metadata(metadata),
        )

    @classmethod
    def from_container_member(
        cls,
        chunks: Iterable[bytes],
        *,
        logical_id: str,
        parent_logical_id: str,
        member_path: str,
        expected_size: int | None = None,
        metadata: Mapping[str, str | int | bool] | None = None,
    ) -> "ArtifactRecord":
        digest, size = sha256_chunks(chunks)
        if expected_size is not None and size != expected_size:
            raise ValueError(
                f"member size mismatch: expected {expected_size}, got {size}"
            )
        return cls(
            logical_id=logical_id,
            kind="container-member",
            size_bytes=size,
            sha256=digest,
            origin=ArtifactOrigin(
                "container-member",
                _canonical_member_path(member_path),
                parent_logical_id,
            ),
            metadata=_canonical_metadata(metadata),
        )


def _canonical_metadata(
    value: Mapping[str, str | int | bool] | None,
) -> tuple[tuple[str, str | int | bool], ...]:
    return tuple(sorted((value or {}).items()))


def _file_chunks(
    path: Path, chunk_size: int = 1024 * 1024
) -> Iterable[bytes]:
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            yield chunk


@dataclass(frozen=True)
class ArtifactManifest:
    """Strict, deterministic artifact graph using schema v1."""

    manifest_id: str
    artifacts: tuple[ArtifactRecord, ...]

    def __post_init__(self) -> None:
        _require_id(self.manifest_id, "manifest ID")
        logical_ids = [item.logical_id for item in self.artifacts]
        if logical_ids != sorted(logical_ids):
            raise ValueError("artifacts must be sorted by logical_id")
        if len(logical_ids) != len(set(logical_ids)):
            raise ValueError("duplicate logical artifact ID")

        by_id = {item.logical_id: item for item in self.artifacts}
        for item in self.artifacts:
            parent = item.origin.parent_logical_id
            if parent is not None and parent not in by_id:
                raise ValueError(
                    f"unknown parent {parent!r} for {item.logical_id!r}"
                )
            if parent == item.logical_id:
                raise ValueError("artifact cannot be its own parent")

        for logical_id in logical_ids:
            visited: set[str] = set()
            current = logical_id
            while True:
                parent = by_id[current].origin.parent_logical_id
                if parent is None:
                    break
                if parent in visited:
                    raise ValueError("artifact parent cycle detected")
                visited.add(parent)
                current = parent

    @property
    def manifest_fingerprint(self) -> str:
        body = {
            "schema": MANIFEST_SCHEMA,
            "manifest_id": self.manifest_id,
            "artifacts": [item.to_dict() for item in self.artifacts],
        }
        return "sha256:" + hashlib.sha256(
            _canonical_json(body)
        ).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": MANIFEST_SCHEMA,
            "manifest_id": self.manifest_id,
            "manifest_fingerprint": self.manifest_fingerprint,
            "artifact_count": len(self.artifacts),
            "artifacts": [item.to_dict() for item in self.artifacts],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ArtifactManifest":
        expected = {
            "schema",
            "manifest_id",
            "manifest_fingerprint",
            "artifact_count",
            "artifacts",
        }
        if set(value) != expected:
            raise ValueError("manifest fields do not match schema v1")
        if value["schema"] != MANIFEST_SCHEMA:
            raise ValueError(f"unsupported manifest schema: {value['schema']!r}")
        rows = value["artifacts"]
        if not isinstance(rows, list):
            raise TypeError("artifacts must be an array")
        if not isinstance(value["manifest_id"], str):
            raise TypeError("manifest_id must be a string")
        if not isinstance(value["artifact_count"], int) or isinstance(
            value["artifact_count"], bool
        ):
            raise TypeError("artifact_count must be an integer")
        manifest = cls(
            manifest_id=value["manifest_id"],
            artifacts=tuple(ArtifactRecord.from_dict(row) for row in rows),
        )
        if value["artifact_count"] != len(manifest.artifacts):
            raise ValueError("stored artifact_count does not match artifacts")
        if value["manifest_fingerprint"] != manifest.manifest_fingerprint:
            raise ValueError("stored manifest fingerprint does not match")
        return manifest

    @classmethod
    def build(
        cls, manifest_id: str, artifacts: Iterable[ArtifactRecord]
    ) -> "ArtifactManifest":
        return cls(
            manifest_id=manifest_id,
            artifacts=tuple(sorted(artifacts, key=lambda item: item.logical_id)),
        )


@dataclass(frozen=True)
class VerificationResult:
    logical_id: str
    size_matches: bool
    sha256_matches: bool

    @property
    def verified(self) -> bool:
        return self.size_matches and self.sha256_matches

    def to_dict(self) -> dict[str, object]:
        return {
            "logical_id": self.logical_id,
            "size_matches": self.size_matches,
            "sha256_matches": self.sha256_matches,
            "verified": self.verified,
        }


def verify_file(
    artifact: ArtifactRecord, path: str | Path
) -> VerificationResult:
    """Re-hash a local file against one manifest record."""

    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    digest, size = sha256_chunks(_file_chunks(source))
    return VerificationResult(
        logical_id=artifact.logical_id,
        size_matches=size == artifact.size_bytes,
        sha256_matches=digest == artifact.sha256,
    )


def duplicate_content_groups(
    manifest: ArtifactManifest,
) -> list[tuple[str, ...]]:
    """Return logical-ID groups which intentionally share content."""

    groups: dict[str, list[str]] = defaultdict(list)
    for artifact in manifest.artifacts:
        groups[artifact.content_id].append(artifact.logical_id)
    return sorted(
        tuple(sorted(values))
        for values in groups.values()
        if len(values) > 1
    )


def compare_manifests(
    left: ArtifactManifest, right: ArtifactManifest
) -> dict[str, object]:
    """Detect logical additions, removals and identity changes."""

    left_by_id = {item.logical_id: item for item in left.artifacts}
    right_by_id = {item.logical_id: item for item in right.artifacts}
    added = sorted(right_by_id.keys() - left_by_id.keys())
    removed = sorted(left_by_id.keys() - right_by_id.keys())
    changed = []
    unchanged = []
    for logical_id in sorted(left_by_id.keys() & right_by_id.keys()):
        old = left_by_id[logical_id]
        new = right_by_id[logical_id]
        if old.artifact_id == new.artifact_id:
            unchanged.append(logical_id)
            continue
        fields = []
        for field_name, old_value, new_value in (
            ("kind", old.kind, new.kind),
            ("size_bytes", old.size_bytes, new.size_bytes),
            ("sha256", old.sha256, new.sha256),
            ("origin", old.origin.to_dict(), new.origin.to_dict()),
            ("metadata", old.metadata, new.metadata),
        ):
            if old_value != new_value:
                fields.append(field_name)
        changed.append(
            {"logical_id": logical_id, "changed_fields": fields}
        )
    return {
        "schema": "phoenix-mmi.artifact-manifest-diff/v1",
        "left_manifest_id": left.manifest_id,
        "right_manifest_id": right.manifest_id,
        "added_logical_ids": added,
        "removed_logical_ids": removed,
        "changed": changed,
        "unchanged_logical_ids": unchanged,
        "has_changes": bool(added or removed or changed),
    }


def build_public_manifest_summary(
    manifest: ArtifactManifest,
    *,
    verifications: Iterable[VerificationResult] = (),
) -> dict[str, object]:
    """Produce aggregate evidence without source identities or locators."""

    verification_rows = list(verifications)
    duplicate_groups = duplicate_content_groups(manifest)
    kind_counts = Counter(item.kind for item in manifest.artifacts)
    roots = [
        item
        for item in manifest.artifacts
        if item.origin.parent_logical_id is None
    ]
    members = [
        item
        for item in manifest.artifacts
        if item.origin.parent_logical_id is not None
    ]
    return {
        "schema": PUBLIC_SUMMARY_SCHEMA,
        "manifest_schema": MANIFEST_SCHEMA,
        "manifest_id": manifest.manifest_id,
        "artifact_count": len(manifest.artifacts),
        "root_artifact_count": len(roots),
        "container_member_count": len(members),
        "parent_child_relationship_count": len(members),
        "orphan_count": 0,
        "kind_counts": dict(sorted(kind_counts.items())),
        "root_bytes": sum(item.size_bytes for item in roots),
        "member_payload_bytes": sum(
            item.size_bytes for item in members
        ),
        "unique_content_count": (
            len({item.content_id for item in manifest.artifacts})
        ),
        "duplicate_content_group_count": len(duplicate_groups),
        "duplicated_artifact_count": sum(
            len(group) for group in duplicate_groups
        ),
        "verification_count": len(verification_rows),
        "verified_artifact_count": sum(
            int(row.verified) for row in verification_rows
        ),
        "classification": {
            "schema_validation": "PASS",
            "parent_member_integrity": "PASS",
            "registered_root_identity": (
                "PASS"
                if verification_rows
                and all(row.verified for row in verification_rows)
                else "NOT_TESTED"
            ),
            "duplicate_content": "TRACKED_NOT_REJECTED",
        },
        "identity_fields_in_public_summary": {
            "logical_ids": False,
            "artifact_ids": False,
            "content_ids": False,
            "source_names": False,
            "member_paths": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "source_content_hashes_included": False,
            "local_paths_included": False,
            "member_paths_included": False,
            "extracted_resources_included": False,
            "installable_artifacts_included": False,
            "runtime_execution_observed": False,
        },
    }


def write_manifest(
    manifest: ArtifactManifest, path: str | Path
) -> Path:
    """Write the private deterministic manifest."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def load_manifest(path: str | Path) -> ArtifactManifest:
    """Load and fully validate a schema-v1 manifest."""

    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise TypeError("manifest root must be an object")
    return ArtifactManifest.from_dict(value)

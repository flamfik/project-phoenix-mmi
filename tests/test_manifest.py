import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.manifest import (
    ArtifactManifest,
    ArtifactOrigin,
    ArtifactRecord,
    build_public_manifest_summary,
    compare_manifests,
    duplicate_content_groups,
    load_manifest,
    write_manifest,
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _root(logical_id="media", data=b"root"):
    return ArtifactRecord(
        logical_id=logical_id,
        kind="media-image",
        size_bytes=len(data),
        sha256=_digest(data),
        origin=ArtifactOrigin("local-file", "fixture.iso"),
    )


def _member(
    logical_id="member",
    parent="media",
    path="A/B.BIN",
    data=b"member",
):
    return ArtifactRecord.from_container_member(
        [data[:2], data[2:]],
        logical_id=logical_id,
        parent_logical_id=parent,
        member_path=path,
        expected_size=len(data),
    )


class ManifestTests(unittest.TestCase):
    def test_identity_layers_are_deterministic_and_distinct(self):
        first = _root()
        second = _root()
        self.assertEqual(first.content_id, second.content_id)
        self.assertEqual(first.artifact_id, second.artifact_id)
        self.assertTrue(first.content_id.startswith("sha256:"))
        self.assertTrue(first.artifact_id.startswith("artifact-v1:"))

    def test_manifest_round_trip_validates_fingerprint(self):
        manifest = ArtifactManifest.build(
            "fixture-manifest", [_member(), _root()]
        )
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            write_manifest(manifest, path)
            restored = load_manifest(path)
        self.assertEqual(restored, manifest)
        self.assertEqual(
            restored.manifest_fingerprint,
            manifest.manifest_fingerprint,
        )

    def test_tampered_fingerprint_is_rejected(self):
        manifest = ArtifactManifest.build("fixture", [_root()])
        value = manifest.to_dict()
        value["manifest_fingerprint"] = "sha256:" + ("0" * 64)
        with self.assertRaises(ValueError):
            ArtifactManifest.from_dict(value)

    def test_noncanonical_schema_types_are_rejected(self):
        value = ArtifactManifest.build("fixture", [_root()]).to_dict()
        value["artifacts"][0]["size_bytes"] = True
        with self.assertRaises(TypeError):
            ArtifactManifest.from_dict(value)

    def test_duplicate_logical_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            ArtifactManifest(
                "fixture",
                (_root("same"), _root("same")),
            )

    def test_unknown_parent_and_unsafe_member_path_are_rejected(self):
        with self.assertRaises(ValueError):
            ArtifactManifest.build("fixture", [_member(parent="absent")])
        with self.assertRaises(ValueError):
            ArtifactOrigin(
                "container-member", "../escape.bin", "media"
            )

    def test_duplicate_content_is_tracked_not_rejected(self):
        left = _member("left", path="A.BIN")
        right = _member("right", path="B.BIN")
        manifest = ArtifactManifest.build(
            "fixture", [_root(), left, right]
        )
        self.assertEqual(
            duplicate_content_groups(manifest),
            [("left", "right")],
        )

    def test_member_size_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            ArtifactRecord.from_container_member(
                [b"abc"],
                logical_id="member",
                parent_logical_id="media",
                member_path="A.BIN",
                expected_size=4,
            )

    def test_manifest_diff_detects_content_change(self):
        before = ArtifactManifest.build(
            "before", [_root(), _member()]
        )
        after = ArtifactManifest.build(
            "after", [_root(), _member(data=b"changed")]
        )
        report = compare_manifests(before, after)
        self.assertTrue(report["has_changes"])
        self.assertEqual(report["changed"][0]["logical_id"], "member")
        self.assertEqual(
            report["changed"][0]["changed_fields"],
            ["size_bytes", "sha256"],
        )

    def test_public_summary_omits_all_source_identities(self):
        manifest = ArtifactManifest.build(
            "fixture", [_root(), _member()]
        )
        report = build_public_manifest_summary(manifest)
        serialized = json.dumps(report)
        self.assertNotIn("fixture.iso", serialized)
        self.assertNotIn("A/B.BIN", serialized)
        self.assertNotIn(_digest(b"root"), serialized)
        self.assertNotIn("artifact-v1:", serialized)
        self.assertFalse(
            any(
                report["identity_fields_in_public_summary"].values()
            )
        )


if __name__ == "__main__":
    unittest.main()

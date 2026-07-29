from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.cross_payload_homolog import (
    PayloadInput,
    analyze_cross_payload_homologs,
    build_public_cross_payload_homolog_report,
    correlate_cross_payload_homologs,
    derive_cross_payload_signature,
    payload_member_eligible,
    update_operational_graph_v33,
)


_RELATIVES = (2, 32, 104, 140, 196)


def _stream(length: int, salt: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(salt + counter.to_bytes(4, "big")).digest()
        )
        counter += 1
    return bytes(output[:length])


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _fixture():
    left = bytearray(_stream(0x5000, b"cross-payload-left"))
    right = bytearray(_stream(0x6000, b"cross-payload-right"))
    control_start = 0x1000
    left_start = 0x2000
    right_start = 0x3000
    component = bytearray(_stream(240, b"cross-payload-component"))
    left[left_start : left_start + 240] = component
    right[right_start : right_start + 240] = component
    anchor_positions = {
        index
        for relative in _RELATIVES
        for index in range(relative, relative + 25)
    }
    for index in range(0, 240, 13):
        if index not in anchor_positions:
            right[right_start + index] ^= 0x5A
    left_bytes = bytes(left)
    right_bytes = bytes(right)
    left_hash = hashlib.sha256(left_bytes).hexdigest()
    right_hash = hashlib.sha256(right_bytes).hexdigest()
    runs = [
        {
            "run_id": f"RZ012-RUN-{ordinal + 1:03d}",
            "start": left_start + relative,
            "end": left_start + relative + 25,
            "length": 25,
        }
        for ordinal, relative in enumerate(_RELATIVES)
    ]
    session038 = {
        "schema": "phoenix-mmi.run-gap-topology-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "search_contract": {"overlap_start": control_start},
        "rz012": {
            "runs": runs,
            "dominant_promoted_component": {
                "component_id": "RZ012-G1-C001",
                "start": left_start,
                "end": left_start + 240,
                "span": 240,
                "promotion_gate_passed": True,
                "run_ids": [run["run_id"] for run in runs],
            },
        },
        "classification": {
            "micro_island_structural_model": (
                "STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON"
            ),
        },
    }
    session039 = {
        "schema": "phoenix-mmi.registered-provenance-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "target": {
            "component_id": "RZ012-G1-C001",
            "left": {"start": left_start, "end": left_start + 240},
            "rz012_right": {
                "start": right_start,
                "end": right_start + 240,
            },
        },
        "classification": {
            "registered_external_provenance": (
                "NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES"
            ),
            "semantic_owner": "OPEN",
        },
    }
    return left_bytes, right_bytes, session038, session039


def _components(left: bytes):
    target = left[0x2000 : 0x2000 + 240]
    control = left[0x1000 : 0x1000 + 240]
    return target, control


def _payload_with_window(window: bytes, *, salt: bytes) -> bytes:
    data = bytearray(_stream(0x1000, salt))
    data[0x300 : 0x300 + 240] = window
    return bytes(data)


def _analyze(payloads: list[PayloadInput]):
    left, right, session038, session039 = _fixture()
    with TemporaryDirectory() as temporary:
        return analyze_cross_payload_homologs(
            _reader(left, temporary, "left.bin"),
            _reader(right, temporary, "right.bin"),
            session038,
            session039,
            payloads,
        )


class CrossPayloadHomologTests(unittest.TestCase):
    def test_signature_has_five_quality_gated_exact_anchors(self):
        left, right, session038, session039 = _fixture()
        with TemporaryDirectory() as temporary:
            signature = derive_cross_payload_signature(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                session038,
                session039,
            )
        self.assertEqual(len(signature["anchors"]), 5)
        self.assertGreaterEqual(
            len(
                {
                    row["_internal_bytes"]
                    for row in signature["anchors"]
                }
            ),
            3,
        )
        self.assertEqual(
            [row["relative_offset"] for row in signature["anchors"]],
            list(_RELATIVES),
        )
        self.assertTrue(
            all(row["entropy"] >= 2.5 for row in signature["anchors"])
        )

    def test_exact_target_window_promotes_homolog(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        report = _analyze(
            [
                PayloadInput(
                    "cd2",
                    "PHONE/APP.BIN",
                    _payload_with_window(target, salt=b"target-hit"),
                )
            ]
        )
        self.assertEqual(
            report["classification"]["cross_payload_homolog"],
            "CROSS_PAYLOAD_HOMOLOG_SUPPORTED",
        )
        self.assertEqual(
            report["summary"]["target_strong_hit_unique_count"], 1
        )
        self.assertGreaterEqual(
            report["summary"]["target_first_anchor_occurrence_count"], 1
        )
        self.assertEqual(
            report["summary"]["control_geometry_hit_unique_count"], 0
        )

    def test_control_hit_prevents_discriminating_result(self):
        left, *_ = _fixture()
        _, control = _components(left)
        report = _analyze(
            [
                PayloadInput(
                    "cd1",
                    "CONTROL/APP.BIN",
                    _payload_with_window(control, salt=b"control-hit"),
                )
            ]
        )
        self.assertEqual(
            report["classification"]["cross_payload_homolog"],
            "MODEL_NOT_DISCRIMINATING_CONTROL_HIT",
        )
        self.assertEqual(
            report["summary"]["control_strong_hit_unique_count"], 1
        )

    def test_anchor_geometry_without_similarity_is_not_strong(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        data = bytearray(_stream(0x1000, b"geometry-only"))
        base = 0x300
        for relative in _RELATIVES:
            data[
                base + relative : base + relative + 25
            ] = target[relative : relative + 25]
        report = _analyze(
            [PayloadInput("cd3", "OTHER/APP.BIN", bytes(data))]
        )
        self.assertEqual(
            report["classification"]["cross_payload_homolog"],
            "ANCHOR_GEOMETRY_CANDIDATE_ONLY",
        )
        self.assertEqual(
            report["summary"]["target_geometry_hit_unique_count"], 1
        )
        self.assertEqual(
            report["summary"]["target_strong_hit_unique_count"], 0
        )

    def test_principal_identity_is_excluded(self):
        left, *_ = _fixture()
        report = _analyze(
            [PayloadInput("cd1", "MMI/COPY.BIN", left)]
        )
        self.assertEqual(report["corpus_contract"]["scanned_member_count"], 0)
        self.assertEqual(
            report["disc_summaries"]["cd1"][
                "principal_identity_exclusion_count"
            ],
            1,
        )

    def test_duplicate_payload_content_is_scanned_once(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        payload = _payload_with_window(target, salt=b"duplicate")
        report = _analyze(
            [
                PayloadInput("cd1", "A/APP.BIN", payload),
                PayloadInput("cd3", "B/APP.BIN", payload),
            ]
        )
        self.assertEqual(
            report["corpus_contract"]["unique_payload_content_count"], 1
        )
        self.assertEqual(
            report["corpus_contract"]["duplicate_content_group_count"], 1
        )
        self.assertEqual(
            report["summary"]["target_strong_hit_member_count"], 2
        )

    def test_payload_filter_is_extension_and_size_bounded(self):
        self.assertTrue(payload_member_eligible("A/B.BIN", 240))
        self.assertTrue(payload_member_eligible("A/B.hex", 240))
        self.assertFalse(payload_member_eligible("A/B.TXT", 1000))
        self.assertFalse(payload_member_eligible("A/B.BIN", 239))

    def test_hash_gate_rejects_changed_principal(self):
        left, right, session038, session039 = _fixture()
        changed = bytearray(left)
        changed[-1] ^= 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                ValueError, "left principal-image hash differs"
            ):
                analyze_cross_payload_homologs(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    session038,
                    session039,
                    [],
                )

    def test_public_copy_is_detached_and_safe(self):
        report = _analyze([])
        public = build_public_cross_payload_homolog_report(report)
        public["classification"]["semantic_owner"] = "changed"
        self.assertEqual(report["classification"]["semantic_owner"], "OPEN")
        self.assertFalse(
            public["publication_safety"]["raw_signature_bytes_included"]
        )
        self.assertFalse(
            public["signature_contract"]["signature_hashes_included"]
        )

    def test_graph_and_correlation_keep_owner_open(self):
        report = _analyze([])
        graph = update_operational_graph_v33(
            {
                "schema": "phoenix-mmi.operational-graph/v32",
                "nodes": [],
                "edges": [],
            },
            report,
        )
        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v33")
        self.assertEqual(graph["edges"][-1]["status"], "BOUNDED_NEGATIVE")
        correlation = correlate_cross_payload_homologs(
            {
                "media": {"status": "UNCHANGED"},
                "operational_graph": {
                    "schema": "phoenix-mmi.operational-graph/v32",
                    "nodes": [],
                    "edges": [],
                },
            },
            report,
        )
        self.assertEqual(
            correlation["cross_domain_homolog_edge"], "NOT_ASSERTED"
        )
        self.assertEqual(correlation["firmware"]["semantic_owner"], "OPEN")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.distributed_homolog import (
    NearHomologPayloadInput,
    analyze_distributed_homologs,
    build_public_distributed_homolog_report,
    correlate_distributed_homologs,
    derive_distributed_constellation,
    update_operational_graph_v35,
)
from phoenix_mmi.cross_payload_homolog import payload_member_eligible
from phoenix_mmi.record_normalization import (
    normalize_record_payload,
    record_member_eligible,
)
from tests.test_record_normalization import (
    _components,
    _fixture,
    _intel_payload,
    _reader,
)


_SUBANCHOR_OFFSETS = (2, 15, 32, 45, 104, 117, 140, 153, 196, 209)


def _prior_reports(
    payloads: list[NearHomologPayloadInput],
    left_hash: str,
    right_hash: str,
):
    raw_members = [
        payload
        for payload in payloads
        if payload_member_eligible(payload.path, len(payload.data))
    ]
    raw_unique = {
        hashlib.sha256(payload.data).hexdigest(): payload.data
        for payload in raw_members
    }
    disc_summaries = {}
    for payload in raw_members:
        row = disc_summaries.setdefault(
            payload.disc,
            {"principal_identity_exclusion_count": 0},
        )
        row.setdefault("principal_identity_exclusion_count", 0)
    session040 = {
        "schema": "phoenix-mmi.cross-payload-homolog-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "classification": {
            "cross_payload_homolog": (
                "NOT_FOUND_UNDER_FIXED_SIGNATURE_MODEL"
            ),
        },
        "corpus_contract": {
            "eligible_member_count": len(raw_members),
            "eligible_member_bytes": sum(
                len(payload.data) for payload in raw_members
            ),
            "scanned_member_count": len(raw_members),
            "scanned_member_bytes": sum(
                len(payload.data) for payload in raw_members
            ),
            "unique_payload_content_count": len(raw_unique),
            "unique_payload_content_bytes": sum(
                len(data) for data in raw_unique.values()
            ),
        },
        "disc_summaries": disc_summaries,
    }

    record_members = [
        payload
        for payload in payloads
        if record_member_eligible(payload.path, len(payload.data))
    ]
    record_unique = {}
    for payload in record_members:
        digest = hashlib.sha256(payload.data).hexdigest()
        record_unique.setdefault(digest, payload)
    regions = {}
    normalized_sources = 0
    for payload in record_unique.values():
        result = normalize_record_payload(payload.path, payload.data)
        if result.decoded_regions:
            normalized_sources += 1
        for region in result.decoded_regions:
            regions.setdefault(
                hashlib.sha256(region.data).hexdigest(),
                region.data,
            )
    session041 = {
        "schema": "phoenix-mmi.record-normalized-homolog-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "classification": {
            "record_normalized_homolog": (
                "NOT_FOUND_IN_VALIDATED_DECODED_REGIONS"
            ),
        },
        "source_corpus": {
            "member_count": len(record_members),
            "member_bytes": sum(
                len(payload.data) for payload in record_members
            ),
            "unique_source_content_count": len(record_unique),
            "normalized_unique_source_count": normalized_sources,
        },
        "decoded_corpus": {
            "unique_region_content_count": len(regions),
            "unique_decoded_region_bytes": sum(
                len(data) for data in regions.values()
            ),
            "scannable_unique_region_count": sum(
                len(data) >= 240 for data in regions.values()
            ),
        },
    }
    return session040, session041


def _analyze(payloads: list[NearHomologPayloadInput]):
    left, right, session038, session039 = _fixture()
    session040, session041 = _prior_reports(
        payloads,
        session038["left_artifact_sha256"],
        session038["right_artifact_sha256"],
    )
    with TemporaryDirectory() as temporary:
        report = analyze_distributed_homologs(
            _reader(left, temporary, "left.bin"),
            _reader(right, temporary, "right.bin"),
            session038,
            session039,
            session040,
            session041,
            payloads,
        )
    return report


def _variant(
    component: bytes,
    preserved_anchor_indices: set[int],
    *,
    changed_byte_count: int,
) -> bytes:
    data = bytearray(component)
    preserved = {
        offset + relative
        for index, offset in enumerate(_SUBANCHOR_OFFSETS)
        if index in preserved_anchor_indices
        for relative in range(12)
    }
    forced = [
        _SUBANCHOR_OFFSETS[index]
        for index in range(len(_SUBANCHOR_OFFSETS))
        if index not in preserved_anchor_indices
    ]
    changed = set()
    for offset in forced:
        if offset not in preserved:
            data[offset] ^= 0xA5
            changed.add(offset)
    for offset in range(len(data)):
        if len(changed) >= changed_byte_count:
            break
        if offset not in preserved and offset not in changed:
            data[offset] ^= 0x5A
            changed.add(offset)
    if len(changed) != changed_byte_count:
        raise AssertionError("fixture cannot satisfy requested mutation count")
    return bytes(data)


class DistributedHomologTests(unittest.TestCase):
    def test_constellation_is_fixed_quality_gated_and_independent(self):
        left, right, session038, session039 = _fixture()
        session040, _ = _prior_reports(
            [],
            session038["left_artifact_sha256"],
            session038["right_artifact_sha256"],
        )
        with TemporaryDirectory() as temporary:
            result = derive_distributed_constellation(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                session038,
                session039,
                session040,
            )
        self.assertEqual(len(result["target_anchors"]), 10)
        self.assertEqual(
            [row["relative_offset"] for row in result["target_anchors"]],
            list(_SUBANCHOR_OFFSETS),
        )
        self.assertTrue(
            all(
                row["distinct_byte_count"] >= 8
                and row["entropy"] >= 2.75
                for row in result["target_anchors"]
            )
        )
        self.assertFalse(
            {
                row["_internal_bytes"] for row in result["target_anchors"]
            }
            & {
                row["_internal_bytes"] for row in result["control_anchors"]
            }
        )

    def test_exact_raw_component_promotes_distributed_homolog(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        report = _analyze(
            [NearHomologPayloadInput("cd1", "A/APP.BIN", target)]
        )
        self.assertEqual(
            report["classification"]["distributed_near_homolog"],
            "DISTRIBUTED_NEAR_HOMOLOG_SUPPORTED",
        )
        self.assertEqual(
            report["domain_summaries"]["RAW"]["target_strong_unit_count"],
            1,
        )

    def test_four_anchors_from_four_parents_and_similarity_promote(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        variant = _variant(
            target,
            {0, 2, 4, 6},
            changed_byte_count=80,
        )
        report = _analyze(
            [NearHomologPayloadInput("cd3", "A/APP.BIN", variant)]
        )
        self.assertEqual(
            report["classification"]["distributed_near_homolog"],
            "DISTRIBUTED_NEAR_HOMOLOG_SUPPORTED",
        )

    def test_four_anchors_from_only_two_parents_do_not_form_candidate(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        variant = _variant(
            target,
            {0, 1, 2, 3},
            changed_byte_count=70,
        )
        report = _analyze(
            [NearHomologPayloadInput("cd1", "A/APP.BIN", variant)]
        )
        self.assertEqual(
            report["classification"]["distributed_near_homolog"],
            "NOT_FOUND_UNDER_FIXED_DISTRIBUTED_MODEL",
        )

    def test_similarity_gate_keeps_weak_constellation_candidate_only(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        variant = _variant(
            target,
            {0, 2, 4, 6},
            changed_byte_count=110,
        )
        report = _analyze(
            [NearHomologPayloadInput("cd1", "A/APP.BIN", variant)]
        )
        self.assertEqual(
            report["classification"]["distributed_near_homolog"],
            "DISTRIBUTED_CONSTELLATION_CANDIDATE_ONLY",
        )
        self.assertEqual(
            report["summary"]["target_strong_unique_unit_count"], 0
        )

    def test_equal_geometry_control_hit_blocks_discrimination(self):
        left, *_ = _fixture()
        _, control = _components(left)
        report = _analyze(
            [NearHomologPayloadInput("cd1", "A/APP.BIN", control)]
        )
        self.assertEqual(
            report["classification"]["distributed_near_homolog"],
            "DISTRIBUTED_MODEL_NOT_DISCRIMINATING",
        )

    def test_record_normalized_domain_is_separate_and_reproducible(self):
        left, *_ = _fixture()
        target, _ = _components(left)
        report = _analyze(
            [
                NearHomologPayloadInput(
                    "cd3",
                    "A/APP.HEX",
                    _intel_payload(target),
                )
            ]
        )
        self.assertEqual(
            report["domain_summaries"]["RECORD_NORMALIZED"][
                "target_strong_unit_count"
            ],
            1,
        )
        self.assertEqual(
            report["corpus_reproduction"]["record_normalized"][
                "unique_region_content_count"
            ],
            1,
        )

    def test_public_copy_graph_and_correlation_preserve_limits(self):
        report = _analyze([])
        public = build_public_distributed_homolog_report(report)
        public["classification"]["semantic_owner"] = "changed"
        self.assertEqual(report["classification"]["semantic_owner"], "OPEN")
        self.assertFalse(
            public["publication_safety"]["raw_signature_bytes_included"]
        )
        graph = update_operational_graph_v35(
            {
                "schema": "phoenix-mmi.operational-graph/v34",
                "nodes": [],
                "edges": [],
            },
            report,
        )
        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v35")
        correlation = correlate_distributed_homologs(
            {
                "media": {"status": "UNCHANGED"},
                "operational_graph": {
                    "schema": "phoenix-mmi.operational-graph/v34",
                    "nodes": [],
                    "edges": [],
                },
            },
            report,
        )
        self.assertEqual(
            correlation["cross_domain_homolog_edge"], "NOT_ASSERTED"
        )


if __name__ == "__main__":
    unittest.main()

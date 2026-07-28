from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.registered_provenance import (
    analyze_registered_provenance,
    build_public_registered_provenance_report,
    build_registered_evidence,
    correlate_registered_provenance,
    evaluate_registered_pairs,
    update_operational_graph_v32,
)


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _prior(left: bytes, right: bytes) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.run-gap-topology-comparison/v1",
        "left_artifact_sha256": hashlib.sha256(left).hexdigest(),
        "right_artifact_sha256": hashlib.sha256(right).hexdigest(),
        "search_contract": {
            "left_delta": 0x2000,
            "right_delta": -0x800,
        },
        "rz012": {
            "dominant_promoted_component": {
                "component_id": "RZ012-G1-C001",
                "start": 0x1000,
                "end": 0x10F0,
                "span": 240,
                "promotion_gate_passed": True,
            }
        },
        "classification": {
            "micro_island_structural_model": (
                "STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON"
            ),
            "exact_section_boundary": "OPEN",
        },
    }


def _registries(left: bytes, right: bytes) -> dict[str, dict[str, object]]:
    left_hash = hashlib.sha256(left).hexdigest()
    right_hash = hashlib.sha256(right).hexdigest()
    reference_left = {
        "schema": "phoenix-mmi.reference-graph/v1",
        "artifact": {"sha256": left_hash},
        "anchors": [
            {
                "label": "target",
                "target_file_offset": 0x200,
                "exact_runtime_word_occurrences": [
                    {
                        "file_offset": 0x500,
                        "pc_relative_mov_l_referrer_offsets": [],
                    }
                ],
            }
        ],
        "descriptor_candidates": [
            {
                "anchor_file_offset": 0x600,
                "pc_relative_mov_l_referrer_offsets": [],
            }
        ],
    }
    reference_right = {
        "schema": "phoenix-mmi.reference-graph/v1",
        "artifact": {"sha256": right_hash},
        "anchors": [
            {
                "label": "target",
                "target_file_offset": 0x300,
                "exact_runtime_word_occurrences": [
                    {
                        "file_offset": 0x550,
                        "pc_relative_mov_l_referrer_offsets": [],
                    }
                ],
            }
        ],
        "descriptor_candidates": [
            {
                "anchor_file_offset": 0x650,
                "pc_relative_mov_l_referrer_offsets": [],
            }
        ],
    }
    descriptor_lineage = {
        "schema": "phoenix-mmi.descriptor-producer-lineage-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "producer_pairs": [
            {
                "left": {
                    "dispatch_call_site_offset": 0x700,
                    "producer_call_site_offset": 0x720,
                    "producer_target_file_offset": 0x740,
                    "producer_child_target_file_offset": 0x760,
                },
                "right": {
                    "dispatch_call_site_offset": 0x800,
                    "producer_call_site_offset": 0x820,
                    "producer_target_file_offset": 0x840,
                    "producer_child_target_file_offset": 0x860,
                },
                "cross_version_producer_target_promoted": False,
            }
        ],
    }
    literal_pool = {
        "schema": "phoenix-mmi.literal-pool-boundary-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "target_pairs": [
            {
                "flow_ordinal": 12,
                "left": {
                    "registered_target_file_offset": 0x900,
                    "pool": {
                        "pool_start_file_offset": 0x8F0,
                        "pool_end_file_offset": 0x910,
                    },
                    "pool_end_successor": {"entry_file_offset": 0x910},
                },
                "right": {
                    "registered_target_file_offset": 0xA00,
                    "pool": {
                        "pool_start_file_offset": 0x9F0,
                        "pool_end_file_offset": 0xA10,
                    },
                    "pool_end_successor": {"entry_file_offset": 0xA10},
                },
            }
        ],
    }
    breakpoints = {
        "schema": "phoenix-mmi.relocation-breakpoint-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "direct_link_code_anchors": [
            {
                "anchor_id": "CA-001",
                "left_file_offset": 0xB00,
                "right_file_offset": 0xC00,
            }
        ],
        "support_zones": [
            {
                "zone_id": "RZ-001",
                "evidence_class": "BYTE_IDENTICAL_DATA_REGION",
                "left_start": 0x2000,
                "left_end": 0x2100,
                "right_start": 0x3000,
                "right_end": 0x3100,
            }
        ],
        "breakpoint_brackets": [
            {
                "bracket_id": "RB-001",
                "classification": "SECTION_REORDER_BRACKET",
                "left_file_lower_bound": 0xF00,
                "left_file_upper_bound": 0x2000,
            }
        ],
    }
    descriptors = {
        "schema": "phoenix-mmi.relocation-descriptor-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "bilateral_descriptor_pairs": [],
    }
    return {
        "reference_left": reference_left,
        "reference_right": reference_right,
        "descriptor_lineage": descriptor_lineage,
        "literal_pool": literal_pool,
        "breakpoints": breakpoints,
        "descriptors": descriptors,
    }


def _analyze() -> dict[str, object]:
    left = bytes(0x4000)
    right = bytes(0x5000)
    with TemporaryDirectory() as temporary:
        return analyze_registered_provenance(
            _reader(left, temporary, "left.bin"),
            _reader(right, temporary, "right.bin"),
            _prior(left, right),
            _registries(left, right),
        )


class RegisteredProvenanceTests(unittest.TestCase):
    def test_normalizes_only_fixed_registry_families(self):
        left = bytes(0x4000)
        right = bytes(0x5000)
        rows, families = build_registered_evidence(
            _registries(left, right)
        )
        self.assertEqual(len(rows), 12)
        self.assertEqual(len(families), 9)
        self.assertEqual(
            sum(row["registered_pair_count"] for row in families), 12
        )

    def test_actual_model_preserves_open_owner(self):
        report = _analyze()
        self.assertEqual(
            report["classification"]["registered_external_provenance"],
            "NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES",
        )
        self.assertEqual(report["classification"]["semantic_owner"], "OPEN")
        self.assertEqual(report["rz012"]["bilateral_exact_count"], 0)
        self.assertEqual(
            report["registered_explicit_owner_edge_pair_count"], 0
        )

    def test_component_is_contextually_inside_reorder_bracket(self):
        report = _analyze()
        self.assertTrue(
            report["reorder_context"]["left_component_contained"]
        )
        self.assertEqual(
            report["classification"]["reorder_bracket_context"],
            "CONFIRMED_REORDER_BRACKET_CONTEXT_ONLY",
        )

    def test_negative_mapping_is_kept_separate(self):
        report = _analyze()
        self.assertEqual(
            report["classification"]["negative_control_owner_edge"],
            "NOT_FOUND",
        )
        self.assertIn("rz013_negative_right", report["target"])

    def test_two_exact_owner_edge_families_pass_gate(self):
        target = {
            "left": {"start": 100, "end": 200},
            "right": {"start": 300, "end": 400},
        }
        pairs = [
            {
                "evidence_id": "A",
                "family": "FAMILY_A",
                "evidence_role": "DIRECT",
                "left": {"start": 120, "end": 121},
                "right": {"start": 320, "end": 321},
                "explicit_owner_edge": True,
            },
            {
                "evidence_id": "B",
                "family": "FAMILY_B",
                "evidence_role": "DIRECT",
                "left": {"start": 180, "end": 181},
                "right": {"start": 380, "end": 381},
                "explicit_owner_edge": True,
            },
        ]
        result = evaluate_registered_pairs(target, pairs)
        self.assertTrue(result["owner_gate_passed"])
        self.assertEqual(result["exact_owner_family_count"], 2)

    def test_one_family_cannot_promote_owner(self):
        target = {
            "left": {"start": 100, "end": 200},
            "right": {"start": 300, "end": 400},
        }
        pair = {
            "evidence_id": "A",
            "family": "FAMILY_A",
            "evidence_role": "DIRECT",
            "left": {"start": 120, "end": 121},
            "right": {"start": 320, "end": 321},
            "explicit_owner_edge": True,
        }
        result = evaluate_registered_pairs(target, [pair, dict(pair)])
        self.assertFalse(result["owner_gate_passed"])
        self.assertEqual(result["exact_owner_family_count"], 1)

    def test_distance_bands_are_fixed_and_bilateral(self):
        target = {
            "left": {"start": 100, "end": 200},
            "right": {"start": 300, "end": 400},
        }
        pairs = [
            {
                "evidence_id": "adjacent",
                "family": "A",
                "evidence_role": "POINT",
                "left": {"start": 210, "end": 211},
                "right": {"start": 410, "end": 411},
                "explicit_owner_edge": False,
            },
            {
                "evidence_id": "near",
                "family": "B",
                "evidence_role": "POINT",
                "left": {"start": 1200, "end": 1201},
                "right": {"start": 1400, "end": 1401},
                "explicit_owner_edge": False,
            },
            {
                "evidence_id": "touching",
                "family": "C",
                "evidence_role": "INTERVAL",
                "left": {"start": 200, "end": 210},
                "right": {"start": 400, "end": 410},
                "explicit_owner_edge": True,
            },
        ]
        result = evaluate_registered_pairs(target, pairs)
        self.assertEqual(result["bilateral_exact_count"], 0)
        self.assertEqual(result["bilateral_adjacent_count"], 2)
        self.assertEqual(result["bilateral_near_count"], 1)

    def test_hash_gate_rejects_changed_artifact(self):
        left = bytes(0x4000)
        right = bytes(0x5000)
        changed = bytearray(left)
        changed[-1] = 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "left principal-image"):
                analyze_registered_provenance(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    _prior(left, right),
                    _registries(left, right),
                )

    def test_stable_skeleton_gate_is_mandatory(self):
        left = bytes(0x4000)
        right = bytes(0x5000)
        prior = _prior(left, right)
        prior["classification"]["micro_island_structural_model"] = "OPEN"
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "stable skeleton"):
                analyze_registered_provenance(
                    _reader(left, temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                    _registries(left, right),
                )

    def test_public_copy_graph_and_correlation_preserve_limits(self):
        report = _analyze()
        public = build_public_registered_provenance_report(report)
        public["classification"]["semantic_owner"] = "changed"
        self.assertEqual(report["classification"]["semantic_owner"], "OPEN")
        graph = update_operational_graph_v32(
            {
                "schema": "phoenix-mmi.operational-graph/v31",
                "nodes": [],
                "edges": [],
            },
            report,
        )
        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v32")
        self.assertEqual(graph["nodes"][-1]["status"], "OPEN")
        correlation = correlate_registered_provenance(
            {
                "media": {"status": "UNCHANGED"},
                "operational_graph": {
                    "schema": "phoenix-mmi.operational-graph/v31",
                    "nodes": [],
                    "edges": [],
                },
            },
            report,
        )
        self.assertEqual(
            correlation["cross_domain_provenance_edge"], "NOT_ASSERTED"
        )
        self.assertFalse(
            correlation["publication_safety"]["firmware_bytes_included"]
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.micro_island import analyze_micro_island
from phoenix_mmi.run_gap_topology import (
    analyze_run_gap_topology,
    build_public_run_gap_report,
    correlate_run_gap_topology,
    update_operational_graph_v31,
)


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


def _atlas_prior(left: bytes, right: bytes) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.content-island-atlas/v1",
        "left_artifact_sha256": hashlib.sha256(left).hexdigest(),
        "right_artifact_sha256": hashlib.sha256(right).hexdigest(),
        "classification": {
            "island_atlas": "SPARSE_ONE_SIDED_SUPPORT_REPLICATED",
            "multiple_interleaved_family_model": "CLOSED_BOUNDED_NEGATIVE",
            "exact_section_boundary": "OPEN",
        },
        "search_contract": {
            "envelope_lower": 0x4000,
            "envelope_upper": 0xC000,
            "tile_size": 0x1000,
            "left_delta": 0x8000,
            "right_delta": -0x3000,
            "left_zone_id": "RZ-012",
            "right_zone_id": "RZ-013",
        },
        "tiles": [
            {
                "tile_id": "G0000-T003",
                "start": 0x6000,
                "end": 0x7000,
                "assignment": "LEFT_FAMILY",
            }
        ],
        "grid_control": {
            "classification": "REPLICATED_SPARSE_ONE_SIDED_SUPPORT",
            "overlap_pairs": [
                {
                    "primary_tile_id": "G0000-T003",
                    "shifted_tile_id": "G0800-T002",
                    "overlap_length": 0x800,
                    "assignment_equal": True,
                }
            ],
        },
    }


def _fixture(*, periodic: bool = False):
    left = bytearray(_stream(0x20000, b"run-gap-left"))
    right = bytearray(_stream(0x20000, b"run-gap-right"))
    source_start = 0x6000
    mapped_start = source_start + 0x8000
    control_start = source_start - 0x3000
    source = left[source_start : source_start + 0x800]
    for index, value in enumerate(source):
        right[mapped_start + index] = value ^ 0xFF
        right[control_start + index] = value ^ 0xA5
    component_start = 0x200
    component_length = 0xC0
    right[
        mapped_start + component_start :
        mapped_start + component_start + component_length
    ] = source[component_start : component_start + component_length]
    if periodic:
        mismatches = list(range(7, component_length, 8))
    else:
        mismatches = [
            5,
            9,
            35,
            39,
            47,
            57,
            63,
            71,
            87,
            91,
            117,
            123,
            137,
            151,
            157,
            171,
        ]
    for relative in mismatches:
        target = mapped_start + component_start + relative
        right[target] ^= 0x01
    left_bytes = bytes(left)
    right_bytes = bytes(right)
    with TemporaryDirectory() as temporary:
        prior = analyze_micro_island(
            _reader(left_bytes, temporary, "left.bin"),
            _reader(right_bytes, temporary, "right.bin"),
            _atlas_prior(left_bytes, right_bytes),
        )
    return left_bytes, right_bytes, prior


def _analyze(*, periodic: bool = False):
    left, right, prior = _fixture(periodic=periodic)
    with TemporaryDirectory() as temporary:
        return analyze_run_gap_topology(
            _reader(left, temporary, "left.bin"),
            _reader(right, temporary, "right.bin"),
            prior,
        )


class RunGapTopologyTests(unittest.TestCase):
    def test_derives_only_prior_two_kib_overlap(self):
        report = _analyze()
        contract = report["search_contract"]
        self.assertEqual(contract["overlap_start"], 0x6000)
        self.assertEqual(contract["overlap_end"], 0x6800)
        self.assertEqual(contract["overlap_length"], 2048)
        self.assertFalse(contract["whole_image_search_performed"])

    def test_single_byte_gaps_form_promoted_component(self):
        report = _analyze()
        component = report["rz012"]["dominant_promoted_component"]
        self.assertIsNotNone(component)
        self.assertEqual(component["maximum_gap_length"], 1)
        self.assertGreaterEqual(component["span"], 64)
        self.assertGreaterEqual(component["equality_coverage"], 0.75)
        self.assertEqual(
            report["classification"]["run_gap_topology"],
            "CONTROL_DISTINGUISHED_SINGLE_BYTE_GAP_SKELETON",
        )

    def test_negative_control_has_no_promoted_component(self):
        report = _analyze()
        self.assertEqual(
            report["rz013_negative_control"][
                "promoted_component_count"
            ],
            0,
        )
        self.assertTrue(report["summary"]["negative_control_distinguished"])

    def test_relaxed_gap_cap_preserves_dominant_component(self):
        report = _analyze()
        self.assertTrue(
            report["rz012"][
                "dominant_component_stable_under_relaxed_cap"
            ]
        )
        self.assertEqual(
            report["rz012"]["relaxed_promoted_component_count"], 1
        )
        self.assertEqual(
            report["classification"]["gap_cap_control"],
            "STABLE_AT_CAPS_1_AND_2",
        )

    def test_irregular_gaps_do_not_promote_fixed_record_model(self):
        report = _analyze()
        periodicity = report["rz012"]["record_periodicity"]
        self.assertFalse(periodicity["fixed_stride_record_gate_passed"])
        self.assertEqual(
            report["classification"]["fixed_stride_record_model"],
            "NOT_ESTABLISHED",
        )

    def test_periodic_fixture_passes_both_period_gates(self):
        report = _analyze(periodic=True)
        periodicity = report["rz012"]["record_periodicity"]
        self.assertTrue(periodicity["direct_stride_gate_passed"])
        self.assertTrue(periodicity["lattice_gate_passed"])
        self.assertTrue(periodicity["fixed_stride_record_gate_passed"])

    def test_repeated_run_length_needs_stable_spacing(self):
        report = _analyze()
        candidates = report["rz012"]["record_periodicity"][
            "repeated_run_length_candidates"
        ]
        self.assertTrue(candidates)
        self.assertTrue(
            all(
                not candidate["record_spacing_gate_passed"]
                for candidate in candidates
            )
        )
        self.assertEqual(
            report["classification"]["repeated_run_record_model"],
            "NOT_ESTABLISHED",
        )

    def test_hash_gate_rejects_changed_artifact(self):
        left, right, prior = _fixture()
        changed = bytearray(left)
        changed[-1] ^= 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "left principal-image"):
                analyze_run_gap_topology(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                )

    def test_public_report_is_detached_and_safe(self):
        report = _analyze()
        public = build_public_run_gap_report(report)
        public["classification"]["exact_section_boundary"] = "changed"
        self.assertEqual(
            report["classification"]["exact_section_boundary"], "OPEN"
        )
        safety = public["publication_safety"]
        self.assertFalse(safety["firmware_bytes_included"])
        self.assertFalse(safety["unequal_byte_values_included"])
        self.assertFalse(safety["local_paths_included"])

    def test_graph_v31_and_correlation_preserve_semantic_limit(self):
        report = _analyze()
        prior = {
            "media": {"status": "UNCHANGED"},
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v30",
                "nodes": [],
                "edges": [],
            },
        }
        graph = update_operational_graph_v31(
            prior["operational_graph"], report
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v31"
        )
        self.assertEqual(
            graph["nodes"][0]["semantic_status"],
            "STRUCTURAL_NOT_OWNER_PROOF",
        )
        correlation = correlate_run_gap_topology(prior, report)
        self.assertEqual(
            correlation["cross_domain_run_gap_edge"], "NOT_ASSERTED"
        )
        self.assertEqual(correlation["media"]["status"], "UNCHANGED")


if __name__ == "__main__":
    unittest.main()

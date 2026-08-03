from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.micro_island import (
    analyze_micro_island,
    build_public_micro_island_report,
    correlate_micro_island,
    update_operational_graph_v30,
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


def _prior(left: bytes, right: bytes) -> dict[str, object]:
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


def _fixture(*, scattered: bool = False):
    left = bytearray(_stream(0x20000, b"micro-left"))
    right = bytearray(_stream(0x20000, b"micro-right"))
    source_start = 0x6000
    mapped_start = source_start + 0x8000
    source = left[source_start : source_start + 0x800]
    if scattered:
        for index in range(0, len(source), 8):
            right[mapped_start + index] = source[index]
    else:
        right[mapped_start + 0x200 : mapped_start + 0x400] = source[
            0x200:0x400
        ]
    left_bytes = bytes(left)
    right_bytes = bytes(right)
    return left_bytes, right_bytes, _prior(left_bytes, right_bytes)


def _analyze(*, scattered: bool = False):
    left, right, prior = _fixture(scattered=scattered)
    with TemporaryDirectory() as temporary:
        report = analyze_micro_island(
            _reader(left, temporary, "left.bin"),
            _reader(right, temporary, "right.bin"),
            prior,
        )
    return report


class MicroIslandTests(unittest.TestCase):
    def test_derives_exact_two_kib_overlap_from_prior_grids(self):
        report = _analyze()
        contract = report["search_contract"]
        self.assertEqual(contract["overlap_start"], 0x6000)
        self.assertEqual(contract["overlap_end"], 0x6800)
        self.assertEqual(contract["overlap_length"], 2048)
        self.assertEqual(contract["primary_tile_id"], "G0000-T003")
        self.assertEqual(contract["shifted_tile_id"], "G0800-T002")

    def test_clustered_copy_is_phase_stable_and_enriched(self):
        report = _analyze()
        profile = report["rz012"]
        self.assertGreaterEqual(profile["equal_byte_count"], 512)
        self.assertGreaterEqual(profile["maximum_run_length"], 512)
        self.assertEqual(
            profile["spatial_classification"], "CLUSTERED_PHASE_STABLE"
        )
        self.assertEqual(
            report["classification"]["byte_equality_enrichment"],
            "CONFIRMED_UNDER_FIXED_CONTROL",
        )
        self.assertEqual(
            report["classification"]["micro_island_correspondence"],
            "STRUCTURED_CORRESPONDENCE_SUPPORTED",
        )

    def test_natural_alignment_counts_exact_units(self):
        profile = _analyze()["rz012"]
        self.assertGreaterEqual(
            profile["aligned_halfwords"]["exact_unit_count"], 256
        )
        self.assertGreaterEqual(
            profile["aligned_words"]["exact_unit_count"], 128
        )
        self.assertEqual(profile["aligned_words"]["alignment"], 4)

    def test_scattered_equal_bytes_do_not_become_structured(self):
        report = _analyze(scattered=True)
        self.assertEqual(
            report["rz012"]["spatial_classification"],
            "DISTRIBUTED_PHASE_STABLE",
        )
        self.assertEqual(
            report["classification"]["micro_island_correspondence"],
            "ENRICHED_BUT_SCATTERED",
        )
        self.assertFalse(
            report["summary"]["structured_signal_gate_passed"]
        )

    def test_contract_is_fixed_and_non_adaptive(self):
        contract = _analyze()["search_contract"]
        self.assertEqual(contract["microbin_size"], 256)
        self.assertEqual(contract["shifted_phase_offset"], 128)
        self.assertEqual(contract["byte_enrichment_minimum_ratio"], 4.0)
        self.assertFalse(contract["new_delta_search_performed"])
        self.assertFalse(contract["whole_image_search_performed"])
        self.assertFalse(contract["adaptive_threshold_used"])

    def test_hash_gate_rejects_changed_artifact(self):
        left, right, prior = _fixture()
        changed = bytearray(left)
        changed[-1] ^= 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "left principal-image"):
                analyze_micro_island(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                )

    def test_public_report_is_detached_and_omits_raw_content(self):
        report = _analyze()
        public = build_public_micro_island_report(report)
        public["classification"]["exact_section_boundary"] = "changed"
        self.assertEqual(
            report["classification"]["exact_section_boundary"], "OPEN"
        )
        safety = public["publication_safety"]
        self.assertFalse(safety["raw_overlap_bytes_included"])
        self.assertFalse(safety["instruction_bytes_included"])
        self.assertFalse(safety["mnemonic_names_included"])
        self.assertFalse(
            public["rz012"]["decoder_morphology"][
                "code_execution_asserted"
            ]
        )

    def test_graph_v30_marks_decoder_result_as_not_code_proof(self):
        report = _analyze()
        graph = update_operational_graph_v30(
            {
                "schema": "phoenix-mmi.operational-graph/v29",
                "nodes": [],
                "edges": [],
            },
            report,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v30"
        )
        self.assertEqual(
            graph["nodes"][-1]["semantic_status"], "NOT_CODE_PROOF"
        )

    def test_correlation_preserves_media_and_adds_two_graph_nodes(self):
        report = _analyze()
        prior = {
            "media": {"status": "UNCHANGED"},
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v29",
                "nodes": [],
                "edges": [],
            },
        }
        correlation = correlate_micro_island(prior, report)
        self.assertEqual(correlation["media"]["status"], "UNCHANGED")
        self.assertEqual(
            correlation["cross_domain_micro_island_edge"],
            "NOT_ASSERTED",
        )
        self.assertEqual(
            len(correlation["operational_graph"]["nodes"]), 2
        )

    def test_invalid_prior_classification_is_rejected(self):
        left, right, prior = _fixture()
        prior = copy.deepcopy(prior)
        prior["classification"]["exact_section_boundary"] = "CONFIRMED"
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "open exact boundary"):
                analyze_micro_island(
                    _reader(left, temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                )


if __name__ == "__main__":
    unittest.main()

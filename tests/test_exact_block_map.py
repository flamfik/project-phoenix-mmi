from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.exact_block_map import (
    analyze_exact_block_map,
    build_public_exact_block_map_report,
    compare_exact_block_seed_control,
    update_operational_graph_v27,
)


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _unique_bytes(length: int, salt: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(salt + counter.to_bytes(4, "big")).digest()
        )
        counter += 1
    return bytes(output[:length])


def _fixture():
    left = bytearray(b"\x11" * 0x4000)
    right = bytearray(b"\x22" * 0x4000)
    first = _unique_bytes(0x240, b"first")
    second = _unique_bytes(0x240, b"second")
    left[0x0F00:0x1140] = first
    right[0x1700:0x1940] = first
    left[0x1F00:0x2140] = second
    right[0x0300:0x0540] = second
    prior = {
        "schema": "phoenix-mmi.relocation-descriptor-comparison/v1",
        "left_artifact_sha256": hashlib.sha256(left).hexdigest(),
        "right_artifact_sha256": hashlib.sha256(right).hexdigest(),
        "classification": {
            "section_reorder_anchor": (
                "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL"
            ),
            "coherent_reorder_descriptor_table": (
                "CLOSED_BOUNDED_NEGATIVE"
            ),
        },
        "reorder_bracket": {
            "bracket_id": "RB-001",
            "classification": "SECTION_REORDER_BRACKET",
            "left_zone_id": "RZ-001",
            "right_zone_id": "RZ-002",
            "left_file_lower_bound": 0x1040,
            "left_file_upper_bound": 0x2000,
        },
        "left": {
            "zones": [
                {
                    "zone_id": "RZ-001",
                    "start": 0x1000,
                    "end": 0x1040,
                    "length": 0x40,
                },
                {
                    "zone_id": "RZ-002",
                    "start": 0x2000,
                    "end": 0x2040,
                    "length": 0x40,
                },
            ]
        },
        "right": {
            "zones": [
                {
                    "zone_id": "RZ-001",
                    "start": 0x1800,
                    "end": 0x1840,
                    "length": 0x40,
                },
                {
                    "zone_id": "RZ-002",
                    "start": 0x0400,
                    "end": 0x0440,
                    "length": 0x40,
                },
            ]
        },
    }
    return bytes(left), bytes(right), prior


class ExactBlockMapTests(unittest.TestCase):
    def _report(self):
        left, right, prior = _fixture()
        with TemporaryDirectory() as temporary:
            return analyze_exact_block_map(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                prior,
                margin=0x300,
                seed_size=64,
                stride=4,
            )

    def test_two_reordered_lanes_have_exact_block_support(self):
        report = self._report()
        self.assertEqual(
            report["classification"][
                "file_layout_reorder_exact_block_support"
            ],
            "CONFIRMED_AT_EXACT_BLOCKS",
        )
        self.assertTrue(
            all(
                lane["expected_delta_exact_block_count"] >= 1
                for lane in report["lanes"]
            )
        )

    def test_blocks_are_byte_verified_and_expected_delta(self):
        report = self._report()
        first = report["lanes"][0]["expected_delta_exact_blocks"][0]
        second = report["lanes"][1]["expected_delta_exact_blocks"][0]
        self.assertTrue(first["byte_identity_verified"])
        self.assertTrue(second["byte_identity_verified"])
        self.assertEqual(first["relocation_delta"], 0x800)
        self.assertEqual(second["relocation_delta"], -0x1C00)

    def test_transition_envelope_is_narrowed_without_exact_boundary(self):
        report = self._report()
        envelope = report["transition_envelope"]
        self.assertEqual(
            envelope["classification"], "NARROWED_BY_EXACT_BLOCKS"
        )
        self.assertLess(
            envelope["narrowed_width"], envelope["prior_width"]
        )
        self.assertFalse(envelope["exact_breakpoint_asserted"])
        self.assertEqual(
            report["classification"]["exact_section_boundary"], "OPEN"
        )

    def test_search_contract_is_fixed_and_not_whole_image(self):
        report = self._report()
        contract = report["search_contract"]
        self.assertEqual(contract["seed_size"], 64)
        self.assertEqual(contract["stride"], 4)
        self.assertFalse(contract["whole_image_search_performed"])
        self.assertFalse(contract["adaptive_threshold_used"])

    def test_hash_gate_rejects_changed_artifact(self):
        left, right, prior = _fixture()
        changed = bytearray(left)
        changed[-1] ^= 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "left principal-image"):
                analyze_exact_block_map(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                    margin=0x300,
                )

    def test_public_copy_and_graph_preserve_open_runtime_model(self):
        report = self._report()
        public = build_public_exact_block_map_report(report)
        public["classification"]["exact_section_boundary"] = "changed"
        self.assertEqual(
            report["classification"]["exact_section_boundary"], "OPEN"
        )
        graph = update_operational_graph_v27(
            {
                "schema": "phoenix-mmi.operational-graph/v26",
                "nodes": [],
                "edges": [],
            },
            report,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v27"
        )
        self.assertNotEqual(
            graph["nodes"][-1]["status"], "EXACT_BOUNDARY"
        )

    def test_strict_seed_control_preserves_transition_envelope(self):
        left, right, prior = _fixture()
        with TemporaryDirectory() as temporary:
            left_reader = _reader(left, temporary, "left.bin")
            right_reader = _reader(right, temporary, "right.bin")
            primary = analyze_exact_block_map(
                left_reader,
                right_reader,
                prior,
                margin=0x300,
                seed_size=64,
            )
            strict = analyze_exact_block_map(
                left_reader,
                right_reader,
                prior,
                margin=0x300,
                seed_size=128,
            )
        control = compare_exact_block_seed_control(primary, strict)
        self.assertEqual(
            control["classification"], "CONFIRMED_STABLE"
        )
        self.assertTrue(control["transition_envelope_equal"])


if __name__ == "__main__":
    unittest.main()

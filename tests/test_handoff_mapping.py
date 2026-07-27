from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.handoff_mapping import (
    _bounded_entry_r5_cfg,
    _leading_runtime_pointer_prefix,
    analyze_handoff_mapping,
    build_public_handoff_mapping_report,
    update_operational_graph_v22,
)


IGNORES_R5 = bytes.fromhex(
    "4f22"  # save PR
    "e100"  # constant used by the branch
    "2118"
    "8902"  # taken path reaches the second r5 overwrite
    "e500"  # fall-through path overwrites entry r5
    "a001"
    "0009"  # branch delay slot
    "e500"  # taken path overwrites entry r5
    "000b"
    "0009"
)

READS_R5 = bytes.fromhex(
    "4f22"
    "6853"  # read entry r5
    "000b"
    "0009"
)


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _image(*, right: bool) -> bytes:
    data = bytearray(0x180)
    first_words = 3 if right else 2
    second_words = 2 if right else 1
    for index in range(first_words):
        data[index * 4 : index * 4 + 4] = (
            0x0C000100 + index * 4
        ).to_bytes(4, "big")
    first_entry = first_words * 4
    data[first_entry : first_entry + len(IGNORES_R5)] = IGNORES_R5

    second = 0x40
    for index in range(second_words):
        data[second + index * 4 : second + index * 4 + 4] = (
            0x0C000200 + index * 4
        ).to_bytes(4, "big")
    second_entry = second + second_words * 4
    data[second_entry : second_entry + len(IGNORES_R5)] = IGNORES_R5
    data[0x80:0x88] = bytes.fromhex("ffffffffffffffff")
    return bytes(data)


class HandoffMappingTests(unittest.TestCase):
    def test_prefix_counter_stops_at_first_non_runtime_word(self):
        with TemporaryDirectory() as temporary:
            reader = _reader(_image(right=False), temporary, "left.bin")
            prefix = _leading_runtime_pointer_prefix(reader, 0)
            self.assertEqual(prefix["runtime_pointer_word_count"], 2)
            self.assertEqual(prefix["prefix_bytes"], 8)
            self.assertEqual(prefix["corrected_entry_file_offset"], 8)
            self.assertFalse(prefix["raw_pointer_values_included"])

    def test_prefix_counter_rejects_unaligned_target(self):
        with TemporaryDirectory() as temporary:
            reader = _reader(_image(right=False), temporary, "left.bin")
            prefix = _leading_runtime_pointer_prefix(reader, 2)
            self.assertFalse(prefix["aligned_target"])
            self.assertEqual(prefix["runtime_pointer_word_count"], 0)

    def test_cfg_proves_entry_r5_ignored_across_direct_branches(self):
        with TemporaryDirectory() as temporary:
            reader = _reader(IGNORES_R5, temporary, "function.bin")
            profile = _bounded_entry_r5_cfg(reader, 0)
            self.assertTrue(profile["bounded_direct_cfg_complete"])
            self.assertFalse(profile["entry_r5_read_confirmed"])
            self.assertTrue(
                profile["entry_r5_ignored_on_all_modeled_paths"]
            )
            self.assertEqual(
                profile["terminal_path_counts"],
                {"RETURN_AFTER_ENTRY_R5_KILL": 1},
            )

    def test_cfg_detects_entry_r5_read(self):
        with TemporaryDirectory() as temporary:
            reader = _reader(READS_R5, temporary, "function.bin")
            profile = _bounded_entry_r5_cfg(reader, 0)
            self.assertTrue(profile["bounded_direct_cfg_complete"])
            self.assertTrue(profile["entry_r5_read_confirmed"])
            self.assertFalse(
                profile["entry_r5_ignored_on_all_modeled_paths"]
            )

    def test_bilateral_prefix_correction_refines_both_handoffs(self):
        with TemporaryDirectory() as temporary:
            left = _reader(_image(right=False), temporary, "left.bin")
            right = _reader(_image(right=True), temporary, "right.bin")
            session027 = {
                "static_handoff_pairs": [
                    {
                        "flow_ordinal": 12,
                        "left_target_file_offset": 0,
                        "right_target_file_offset": 0,
                    },
                    {
                        "flow_ordinal": 13,
                        "left_target_file_offset": 0x40,
                        "right_target_file_offset": 0x40,
                    },
                ]
            }
            session026 = {
                "producer_target_pair": {
                    "left_target_file_offset": 0x80,
                    "right_target_file_offset": 0x80,
                }
            }
            result = analyze_handoff_mapping(
                left, right, session026, session027
            )
            classification = result["classification"]
            self.assertEqual(
                classification[
                    "bilateral_corrected_handoff_pair_count"
                ],
                2,
            )
            self.assertEqual(
                classification["common_corrected_entry_delta"], 4
            )
            self.assertEqual(
                classification["entry_r5_ignored_pair_count"], 2
            )
            self.assertEqual(
                classification["session026_producer_prefix_correction"],
                "NOT_APPLICABLE",
            )
            self.assertEqual(
                classification["static_handoff_registration_path"],
                "DISPROVED_FOR_TWO_CALLEES",
            )

    def test_negative_control_is_not_forward_scanned(self):
        with TemporaryDirectory() as temporary:
            left = _reader(_image(right=False), temporary, "left.bin")
            right = _reader(_image(right=True), temporary, "right.bin")
            result = analyze_handoff_mapping(
                left,
                right,
                {
                    "producer_target_pair": {
                        "left_target_file_offset": 0x80,
                        "right_target_file_offset": 0x80,
                    }
                },
                {"static_handoff_pairs": []},
            )
            self.assertFalse(
                result["producer_negative_control"][
                    "prefix_correction_applies_both"
                ]
            )
            self.assertFalse(
                result["limits"]["forward_code_entry_search_performed"]
            )

    def test_graph_and_public_copy_preserve_disproof_scope(self):
        comparison = {
            "classification": {
                "bilateral_corrected_handoff_pair_count": 2,
                "entry_r5_ignored_pair_count": 2,
            },
            "interpretation": "bounded prefix correction",
        }
        graph = update_operational_graph_v22(
            {
                "schema": "phoenix-mmi.operational-graph/v21",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v22"
        )
        self.assertEqual(
            graph["edges"][1]["status"],
            "DISPROVED_FOR_BOUNDED_CALLEE_FAMILY",
        )
        public = build_public_handoff_mapping_report(graph)
        public["nodes"][0]["status"] = "changed"
        self.assertEqual(
            graph["nodes"][0]["status"],
            "CONFIRMED_BILATERAL_STRUCTURAL_FAMILY",
        )


if __name__ == "__main__":
    unittest.main()

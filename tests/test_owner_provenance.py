from __future__ import annotations

import unittest

from phoenix_mmi.linkage_owner import _MemoryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.owner_provenance import (
    _classify_pointer_use,
    _compare_base_profiles,
    _owner_base_profile,
    _scan_direct_bsr_calls,
    build_public_owner_ingress_report,
    update_operational_graph_v15,
)


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _put_long(image: bytearray, offset: int, value: int) -> None:
    image[offset : offset + 4] = value.to_bytes(4, "big")


def _mov_l_pc_word(instruction: int, literal: int, register: int) -> int:
    base = (instruction & ~3) + 4
    displacement = literal - base
    return 0xD000 | (register << 8) | (displacement // 4)


class OwnerProvenanceTests(unittest.TestCase):
    def test_bsr_scanner_resolves_signed_in_image_target(self):
        image = bytearray(0x100)
        _put_word(image, 0x40, 0xB006)  # target 0x50
        _put_word(image, 0x60, 0xBFF6)  # target 0x50

        rows = _scan_direct_bsr_calls(bytes(image))

        self.assertIn(
            {"call_site_file_offset": 0x40, "target_file_offset": 0x50},
            rows,
        )
        self.assertIn(
            {"call_site_file_offset": 0x60, "target_file_offset": 0x50},
            rows,
        )

    def test_pointer_use_separates_control_target_from_call_argument(self):
        control = bytearray(0x300)
        _put_word(control, 0x100, _mov_l_pc_word(0x100, 0x180, 0))
        _put_word(control, 0x102, 0x6153)  # mov r5,r1
        _put_word(control, 0x104, 0x400B)  # jsr @r0
        _put_word(control, 0x106, 0x0009)
        _put_long(control, 0x180, RUNTIME_BASE + 0x200)

        argument = bytearray(0x300)
        _put_word(argument, 0x100, _mov_l_pc_word(0x100, 0x180, 5))
        _put_word(argument, 0x102, 0x410B)  # jsr @r1
        _put_word(argument, 0x104, 0x0009)
        _put_long(argument, 0x180, RUNTIME_BASE + 0x200)

        self.assertEqual(
            _classify_pointer_use(_MemoryReader(bytes(control)), 0x100)[
                "classification"
            ],
            "INDIRECT_CONTROL_TARGET",
        )
        self.assertEqual(
            _classify_pointer_use(_MemoryReader(bytes(argument)), 0x100)[
                "classification"
            ],
            "ARGUMENT_TO_OTHER_INDIRECT_CALL",
        )

    def test_owner_base_profile_traces_argument_rooted_load(self):
        image = bytearray(0x300)
        for offset in range(0x100, 0x120, 2):
            _put_word(image, offset, 0x0009)
        _put_word(image, 0x100, 0x4F22)  # sts.l pr,@-r15
        _put_word(image, 0x102, 0x6A43)  # mov r4,r10
        _put_word(image, 0x104, 0x51A2)  # mov.l @(8,r10),r1
        _put_word(image, 0x106, 0x6212)  # mov.l @r1,r2
        _put_word(image, 0x108, 0x000B)
        _put_word(image, 0x10A, 0x0009)

        profile = _owner_base_profile(bytes(image), 0x100)

        self.assertEqual(profile["memory_base_use_count"], 2)
        self.assertEqual(profile["entry_argument_rooted_use_count"], 2)
        self.assertEqual(profile["memory_load_rooted_use_count"], 1)
        self.assertEqual(profile["static_image_pointer_rooted_use_count"], 0)

    def test_base_pair_comparison_preserves_structural_boundary(self):
        image = bytearray(0x300)
        for offset in range(0x100, 0x120, 2):
            _put_word(image, offset, 0x0009)
        _put_word(image, 0x100, 0x4F22)
        _put_word(image, 0x102, 0x6A43)
        _put_word(image, 0x104, 0x51A2)
        _put_word(image, 0x106, 0x6212)
        _put_word(image, 0x108, 0x000B)
        _put_word(image, 0x10A, 0x0009)
        data = bytes(image)
        profile = _owner_base_profile(data, 0x100)

        comparison = _compare_base_profiles(
            data,
            data,
            left_profile=profile,
            right_profile=profile,
            prior_classification="CONFIRMED_TEST_PAIR",
        )

        self.assertEqual(comparison["aligned_memory_base_use_count"], 2)
        self.assertEqual(comparison["equal_canonical_expression_count"], 2)
        self.assertFalse(comparison["state_object_identity_asserted"])

    def test_graph_and_public_copy_keep_semantic_owner_open(self):
        comparison = {
            "classification": {
                "external_static_calls_into_owner_windows": (
                    "NOT_FOUND_UNDER_ADJACENT_LITERAL_JSR_AND_BSR_MODELS"
                ),
                "entry_argument_rooted_state_bases": (
                    "CONFIRMED_IN_BOTH_OWNER_PAIRS"
                ),
            },
            "interpretation": "bounded provenance only",
        }
        graph = update_operational_graph_v15(
            {
                "schema": "phoenix-mmi.operational-graph/v14",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )

        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v15")
        self.assertEqual(graph["nodes"][0]["semantic_owner"], "OPEN")
        public = build_public_owner_ingress_report(graph)
        public["nodes"][0]["semantic_owner"] = "changed"
        self.assertEqual(graph["nodes"][0]["semantic_owner"], "OPEN")


if __name__ == "__main__":
    unittest.main()

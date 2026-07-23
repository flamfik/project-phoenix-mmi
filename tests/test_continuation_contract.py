from __future__ import annotations

import unittest

from phoenix_mmi.continuation_contract import (
    _helper_store_profile,
    _internal_label_diagnostic,
    _normalized_sequence,
    _normalized_sequence_matches,
    _trace_call_argument,
    build_public_internal_continuation_report,
    update_operational_graph_v16,
)
from phoenix_mmi.linkage_owner import _MemoryReader
from phoenix_mmi.object_dispatch import _canonical_expression
from phoenix_mmi.superh import SHInstruction


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


class ContinuationContractTests(unittest.TestCase):
    def test_call_argument_applies_delay_slot_before_trace(self):
        instructions = [
            SHInstruction(0x100, "mov", "r4,r10"),
            SHInstruction(
                0x102,
                "jsr",
                "@r0",
                flow="indirect-call",
                delayed=True,
            ),
            SHInstruction(0x104, "mov", "r10,r4"),
        ]

        expression = _trace_call_argument(
            instructions, 1, 4, image_size=0x1000
        )

        self.assertEqual(_canonical_expression(expression), "ENTRY:r4")

    def test_internal_label_reports_preserved_register_live_in(self):
        image = bytearray(0x200)
        _put_word(image, 0x100, 0x6BA3)  # mov r10,r11
        _put_word(image, 0x102, 0x400B)  # jsr @r0
        _put_word(image, 0x104, 0x0009)
        _put_word(image, 0x106, 0x000B)
        _put_word(image, 0x108, 0x0009)

        diagnostic = _internal_label_diagnostic(
            _MemoryReader(bytes(image)),
            target=0x100,
            owner_start=0xF0,
        )

        self.assertIn("r10", diagnostic["live_in_registers_before_first_call"])
        self.assertEqual(
            diagnostic["address_classification"],
            "INTERNAL_LABEL_NOT_OWNER_ENTRY",
        )
        self.assertFalse(diagnostic["standalone_abi_entry_asserted"])

    def test_normalized_sequence_matches_relocated_pc_loads(self):
        image = bytearray(0x100)
        words_a = [0xD001, 0x400B, 0xA002, 0x0009]
        words_b = [0xD00A, 0x400B, 0xA00F, 0x0009]
        for index, word in enumerate(words_a):
            _put_word(image, 0x20 + index * 2, word)
        for index, word in enumerate(words_b):
            _put_word(image, 0x40 + index * 2, word)

        sequence = _normalized_sequence(bytes(image), 0x20, 4)
        matches = _normalized_sequence_matches(bytes(image), sequence)

        self.assertIn(0x20, matches)
        self.assertIn(0x40, matches)

    def test_helper_profile_keeps_field_geometry_without_path_claim(self):
        image = bytearray(0x200)
        _put_word(image, 0x100, 0x6843)  # mov r4,r8
        _put_word(image, 0x102, 0x1816)  # mov.l r1,@(24,r8)
        _put_word(image, 0x104, 0x2822)  # mov.l r2,@r8
        _put_word(image, 0x106, 0x000B)
        _put_word(image, 0x108, 0x0009)

        profile = _helper_store_profile(
            _MemoryReader(bytes(image)), 0x100
        )

        self.assertEqual(profile["entry_r4_field_offsets"], [0, 24])
        self.assertTrue(
            all(
                row["source_value_path_merged"]
                for row in profile["field_stores"]
            )
        )

    def test_graph_and_public_copy_preserve_semantic_limit(self):
        comparison = {
            "classification": {
                "generic_cross_version_address_record_family": (
                    "CONFIRMED_STRUCTURAL_CALL_FAMILY"
                ),
                "landing_pad_or_unwind_registration": (
                    "PROBABLE_NOT_CONFIRMED"
                ),
                "owner_entry_argument_producer": (
                    "NOT_ESTABLISHED_SEEDS_ARE_INTERNAL_LABELS"
                ),
            },
            "interpretation": "internal labels only",
        }
        graph = update_operational_graph_v16(
            {
                "schema": "phoenix-mmi.operational-graph/v15",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )

        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v16")
        self.assertEqual(
            graph["nodes"][0]["landing_pad_or_unwind"],
            "PROBABLE_NOT_CONFIRMED",
        )
        public = build_public_internal_continuation_report(graph)
        public["nodes"][0]["landing_pad_or_unwind"] = "changed"
        self.assertEqual(
            graph["nodes"][0]["landing_pad_or_unwind"],
            "PROBABLE_NOT_CONFIRMED",
        )


if __name__ == "__main__":
    unittest.main()

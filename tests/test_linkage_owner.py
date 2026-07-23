from __future__ import annotations

import unittest

from phoenix_mmi.linkage_owner import (
    _MemoryReader,
    _alignment_row,
    _group_calls_by_owner,
    _normalized_owner_tokens,
    build_public_linkage_owner_report,
    update_operational_graph_v14,
)
from phoenix_mmi.navigation_storage import RUNTIME_BASE


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _put_long(image: bytearray, offset: int, value: int) -> None:
    image[offset : offset + 4] = value.to_bytes(4, "big")


def _mov_l_pc_word(instruction: int, literal: int, register: int) -> int:
    base = (instruction & ~3) + 4
    displacement = literal - base
    if displacement < 0 or displacement % 4 or displacement // 4 > 0xFF:
        raise ValueError("literal outside MOV.L PC-relative range")
    return 0xD000 | (register << 8) | (displacement // 4)


def _write_owner(
    image: bytearray,
    *,
    start: int,
    calls: tuple[int, ...],
    literal: int,
    target: int,
) -> None:
    for offset in range(start, max(calls) + 12, 2):
        _put_word(image, offset, 0x0009)  # nop
    _put_word(image, start, 0x4F22)  # sts.l pr,@-r15
    for load in calls:
        _put_word(image, load, _mov_l_pc_word(load, literal, 1))
        _put_word(image, load + 2, 0x410B)  # jsr @r1
        _put_word(image, load + 4, 0x0009)  # nop (delay slot)
    _put_word(image, max(calls) + 8, 0x000B)  # rts
    _put_word(image, max(calls) + 10, 0x0009)
    _put_long(image, literal, RUNTIME_BASE + target)


class LinkageOwnerTests(unittest.TestCase):
    def test_memory_reader_has_bounded_read_semantics(self):
        reader = _MemoryReader(b"0123456789")
        self.assertEqual(reader.size, 10)
        self.assertEqual(reader.read(3, 4), b"3456")

    def test_owner_grouping_uses_latest_prologue_without_function_claim(self):
        image = bytearray(0x500)
        _write_owner(
            image,
            start=0x100,
            calls=(0x120, 0x130),
            literal=0x180,
            target=0x300,
        )
        _write_owner(
            image,
            start=0x200,
            calls=(0x220, 0x230),
            literal=0x280,
            target=0x300,
        )
        calls = [
            {"load_file_offset": offset, "target_file_offset": 0x300}
            for offset in (0x120, 0x130, 0x220, 0x230)
        ]

        owners, grouped = _group_calls_by_owner(_MemoryReader(bytes(image)), calls)

        self.assertEqual(set(owners), {0x100, 0x200})
        self.assertEqual([len(grouped[key]) for key in sorted(grouped)], [2, 2])
        self.assertTrue(all(row["prologue_code_gate_passed"] for row in owners.values()))
        self.assertTrue(all(not row["function_boundary_asserted"] for row in owners.values()))

    def test_identical_owner_alignment_maps_selected_call_loads(self):
        image = bytearray(0x400)
        _write_owner(
            image,
            start=0x100,
            calls=(0x120, 0x130),
            literal=0x180,
            target=0x300,
        )
        reader = _MemoryReader(bytes(image))
        owner = {
            "owner_start_file_offset": 0x100,
            "call_count": 2,
            "return_count": 1,
        }
        calls = [
            {"load_file_offset": offset, "target_file_offset": 0x300}
            for offset in (0x120, 0x130)
        ]

        row = _alignment_row(
            reader,
            reader,
            left_owner=owner,
            right_owner=owner,
            right_calls=calls,
            left_target_call_offsets={0x120, 0x130},
        )

        self.assertEqual(row["sequence_similarity"], 1.0)
        self.assertEqual(row["aligned_left_target_call_count"], 2)
        self.assertFalse(row["semantic_equivalence_asserted"])

    def test_normalized_owner_tokens_discard_concrete_addresses(self):
        image = bytearray(0x240)
        _put_word(image, 0x100, 0xA001)  # bra with a concrete target
        _put_word(image, 0x102, 0x0009)
        tokens = _normalized_owner_tokens(_MemoryReader(bytes(image)), 0x100)

        self.assertIn("<address>", tokens[0][1])
        self.assertNotIn("0x", tokens[0][1])

    def test_graph_and_public_copy_preserve_open_runtime_gaps(self):
        comparison = {
            "classification": {
                "residual_call_lineage": (
                    "CONFIRMED_TWO_EXACT_PLUS_TWO_PROBABLE_SEQUENCE_ALIGNED"
                ),
                "owner_pairing": {"confirmed": 1, "probable": 1},
                "runtime_patch_overlay_or_linkage_mechanism": (
                    "HYPOTHESIS_STRENGTHENED_BY_RESIDUAL_OWNER_LINEAGE"
                ),
            },
            "interpretation": "bounded structural evidence only",
        }
        graph = update_operational_graph_v14(
            {
                "schema": "phoenix-mmi.operational-graph/v13",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )

        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v14")
        self.assertEqual(graph["nodes"][0]["status"], "CONFIRMED_BOUNDED_ANALYSIS")
        public = build_public_linkage_owner_report(graph)
        public["nodes"][0]["status"] = "changed"
        self.assertEqual(graph["nodes"][0]["status"], "CONFIRMED_BOUNDED_ANALYSIS")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.optical_callgraph import (
    build_public_optical_callgraph_report,
    collect_seed_pairs,
    compare_optical_navigation_callgraph,
    summarize_bounded_entry,
)


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _mov_l_pc_word(instruction: int, literal: int, register: int) -> int:
    base = (instruction & ~3) + 4
    displacement = literal - base
    if displacement < 0 or displacement % 4 or displacement // 4 > 0xFF:
        raise ValueError("literal outside MOV.L PC-relative range")
    return 0xD000 | (register << 8) | (displacement // 4)


def _write_function(
    image: bytearray,
    *,
    entry: int,
    literal: int,
    target_one: int,
    target_two: int,
) -> None:
    words = [
        0x2FE6,  # mov.l r14,@-r15
        0x4F22,  # sts.l pr,@-r15
        0x6843,  # mov r4,r8
        0xE508,  # mov #8,r5
        _mov_l_pc_word(entry + 8, literal, 10),
        0x4A0B,  # jsr @r10
        0x6483,  # mov r8,r4 (delay slot)
        0x6903,  # mov r0,r9
        _mov_l_pc_word(entry + 16, literal + 4, 10),
        0x4A0B,  # jsr @r10
        0x6493,  # mov r9,r4 (delay slot)
        0x4F26,  # lds.l @r15+,pr
        0x000B,  # rts
        0x0009,  # nop
    ]
    for index, word in enumerate(words):
        _put_word(image, entry + index * 2, word)
    image[literal : literal + 4] = (RUNTIME_BASE + target_one).to_bytes(4, "big")
    image[literal + 4 : literal + 8] = (RUNTIME_BASE + target_two).to_bytes(4, "big")


def _fixture(path: Path, *, entry: int, anchor: int) -> None:
    image = bytearray(0x1000)
    _write_function(
        image,
        entry=entry,
        literal=entry + 0x80,
        target_one=entry + 0x300,
        target_two=entry + 0x340,
    )
    image[anchor - 4 : anchor] = (RUNTIME_BASE + entry).to_bytes(4, "big")
    path.write_bytes(image)


class OpticalCallgraphTests(unittest.TestCase):
    def test_delay_slot_arguments_and_return_forwarding_are_traced(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.bin"
            _fixture(path, entry=0x100, anchor=0x700)
            summary = summarize_bounded_entry(
                BinaryReader(path), 0x100, source="TEST"
            )

        self.assertTrue(summary["bounded_code_gate_passed"])
        self.assertEqual(summary["resolved_static_call_count"], 2)
        first, second = summary["calls"][:2]
        self.assertEqual(first["arguments"]["r4"]["status"], "ENTRY_ARGUMENT")
        self.assertEqual(first["arguments"]["r5"], {"status": "CONSTANT", "value": 8, "derivation_depth": 1})
        self.assertEqual(second["arguments"]["r4"]["status"], "CALL_RETURN")
        self.assertEqual(
            second["arguments"]["r4"]["producer_call_site_offset"],
            first["call_site_offset"],
        )
        self.assertEqual(len(first["result_forwarded_to"]), 1)

    def test_record_pointers_are_seeds_only_after_bounded_code_gate(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root / "left.bin", entry=0x100, anchor=0x700)
            _fixture(root / "right.bin", entry=0x200, anchor=0x800)
            contract = {
                "callsite_window_pairs": [],
                "neighborhood_pairs": [
                    {
                        "category": "optical-service",
                        "anchor_id": "cdrom-event",
                        "left_anchor_offset": 0x700,
                        "right_anchor_offset": 0x800,
                    }
                ],
            }
            seeds = collect_seed_pairs(
                BinaryReader(root / "left.bin"),
                BinaryReader(root / "right.bin"),
                contract,
            )

        self.assertEqual(seeds["census"]["optical_paired_pointer_slot_count"], 1)
        self.assertEqual(seeds["census"]["optical_bounded_code_seed_pair_count"], 1)
        self.assertEqual(
            seeds["accepted_optical_seed_pairs"][0]["classification"],
            "CONFIRMED_RECORD_POINTER_PAIRED_BOUNDED_CODE",
        )

    def test_comparison_keeps_sector_abi_and_buffer_owner_open(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root / "left-private.bin", entry=0x100, anchor=0x700)
            _fixture(root / "right-private.bin", entry=0x200, anchor=0x800)
            contract = {
                "callsite_window_pairs": [],
                "neighborhood_pairs": [
                    {
                        "category": "optical-service",
                        "anchor_id": "cdrom-event",
                        "left_anchor_offset": 0x700,
                        "right_anchor_offset": 0x800,
                    }
                ],
            }
            report = compare_optical_navigation_callgraph(
                BinaryReader(root / "left-private.bin"),
                BinaryReader(root / "right-private.bin"),
                contract,
            )
            public = build_public_optical_callgraph_report(report)

        self.assertEqual(report["classification"]["sector_read_abi"], "OPEN")
        self.assertEqual(report["classification"]["optical_buffer_owner"], "OPEN")
        serialized = json.dumps(public)
        self.assertNotIn("left-private", serialized)
        self.assertNotIn("right-private", serialized)
        self.assertFalse(public["publication_safety"]["firmware_bytes_included"])
        self.assertFalse(public["publication_safety"]["local_paths_included"])


if __name__ == "__main__":
    unittest.main()

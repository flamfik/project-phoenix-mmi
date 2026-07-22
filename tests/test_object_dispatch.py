from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.object_dispatch import (
    _descriptor_contract,
    correlate_dispatch_context,
    summarize_contextual_dispatch_calls,
)
from phoenix_mmi.optical_callgraph import summarize_bounded_entry


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _mov_l_pc_word(instruction: int, literal: int, register: int) -> int:
    base = (instruction & ~3) + 4
    displacement = literal - base
    if displacement < 0 or displacement % 4 or displacement // 4 > 0xFF:
        raise ValueError("literal outside MOV.L PC-relative range")
    return 0xD000 | (register << 8) | (displacement // 4)


class ObjectDispatchTests(unittest.TestCase):
    def test_predecessor_context_recovers_callee_saved_literal_target(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "context.bin"
            image = bytearray(0x800)
            source = 0x100
            entry = 0x120
            literal = 0x180
            target = 0x300
            _put_word(image, source, 0x4F22)  # sts.l pr,@-r15
            _put_word(image, source + 2, _mov_l_pc_word(source + 2, literal, 12))
            for offset in range(source + 4, entry, 2):
                _put_word(image, offset, 0x0009)
            _put_word(image, entry, 0x4C0B)  # jsr @r12
            _put_word(image, entry + 2, 0xE501)  # mov #1,r5
            _put_word(image, entry + 4, 0x4F26)  # lds.l @r15+,pr
            _put_word(image, entry + 6, 0x000B)
            _put_word(image, entry + 8, 0x0009)
            image[literal : literal + 4] = (RUNTIME_BASE + target).to_bytes(4, "big")
            _put_word(image, target, 0x4F22)
            _put_word(image, target + 2, 0x6483)
            _put_word(image, target + 4, 0x0009)
            _put_word(image, target + 6, 0x000B)
            _put_word(image, target + 8, 0x0009)
            path.write_bytes(image)

            reader = BinaryReader(path)
            original = summarize_bounded_entry(reader, entry, source="TEST")
            contextual = summarize_contextual_dispatch_calls(reader, entry, original)
            target_summary = summarize_bounded_entry(reader, target, source="TEST_TARGET")

        call = contextual["calls"][0]
        self.assertEqual(contextual["context_start_reason"], "LATEST_SAVE_PR_PROLOGUE")
        self.assertEqual(call["target_static_status"], "RESOLVED_IN_IMAGE_POINTER")
        self.assertEqual(call["target_file_offset"], target)
        self.assertTrue(call["target_code_gate_passed"], target_summary)
        self.assertEqual(call["arguments"]["r5"]["constant"], 1)

    def test_dynamic_descriptor_path_and_receiver_adjustment_are_explicit(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "descriptor.bin"
            image = bytearray(0x600)
            entry = 0x100
            words = [
                0x4F22,  # sts.l pr,@-r15
                0x6242,  # mov.l @r4,r2
                0x6123,  # mov r2,r1
                0x7108,  # add #8,r1
                0x6111,  # mov.w @r1,r1
                0x341C,  # add r1,r4
                0x5123,  # mov.l @(12,r2),r1
                0x410B,  # jsr @r1
                0xE503,  # mov #3,r5
                0x4F26,  # lds.l @r15+,pr
                0x000B,
                0x0009,
            ]
            for index, word in enumerate(words):
                _put_word(image, entry + index * 2, word)
            path.write_bytes(image)

            reader = BinaryReader(path)
            original = summarize_bounded_entry(reader, entry, source="TEST")
            contextual = summarize_contextual_dispatch_calls(reader, entry, original)

        call = contextual["calls"][0]
        self.assertEqual(
            call["target_path"],
            "LOAD32[12](LOAD32[0](ENTRY:r4))",
        )
        self.assertEqual(call["target_static_status"], "DYNAMIC_OR_UNSUPPORTED")
        self.assertEqual(
            call["target_load_offsets"],
            [
                {"width_bits": 32, "displacement": 12},
                {"width_bits": 32, "displacement": 0},
            ],
        )
        self.assertIn("CONST:8", call["arguments"]["r4"]["path"])
        self.assertEqual(call["arguments"]["r5"]["constant"], 3)
        contract = _descriptor_contract(call, call)
        self.assertIsNotNone(contract)
        self.assertFalse(contract["vtable_semantics_asserted"])

    def test_correlation_keeps_parser_and_sector_contract_open(self):
        prior = {
            "media": {"container": "FLDB"},
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v8",
                "nodes": [],
                "edges": [],
            },
        }
        comparison = {
            "analysis_mode": "read-only-static-bounded-predecessor-context",
            "classification": {
                "paired_contextual_static_target_count": 2,
                "new_graph_expandable_target_pair_count": 0,
                "matched_dynamic_descriptor_contract_count": 2,
            },
            "interpretation": "bounded",
            "publication_safety": {"firmware_bytes_included": False},
        }
        report = correlate_dispatch_context(prior, comparison)
        self.assertEqual(report["correlation"]["actual_fldb_parser"], "OPEN")
        self.assertEqual(report["correlation"]["sector_read_abi"], "OPEN")
        node = report["operational_graph"]["nodes"][0]
        self.assertEqual(node["dynamic_target_status"], "UNRESOLVED")


if __name__ == "__main__":
    unittest.main()

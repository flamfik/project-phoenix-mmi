from __future__ import annotations

import unittest

from phoenix_mmi.accessor_dispatch import _literal_jsr_calls
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.runtime_slot import (
    _branch_feasibility,
    _map_left_slot_to_right,
    _scan_bounded_direct_writers,
    correlate_runtime_slot_lineage,
)


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _mov_l_pc_word(instruction: int, literal: int, register: int) -> int:
    base = (instruction & ~3) + 4
    displacement = literal - base
    if displacement < 0 or displacement % 4 or displacement // 4 > 0xFF:
        raise ValueError("literal outside MOV.L PC-relative range")
    return 0xD000 | (register << 8) | (displacement // 4)


def _write_literal_call(
    image: bytearray,
    *,
    load: int,
    literal: int,
    target: int,
    register: int = 2,
) -> None:
    _put_word(image, load, _mov_l_pc_word(load, literal, register))
    _put_word(image, load + 2, 0x400B | (register << 8))
    _put_word(image, load + 4, 0x0009)
    image[literal : literal + 4] = (RUNTIME_BASE + target).to_bytes(4, "big")


class RuntimeSlotTests(unittest.TestCase):
    def test_writer_scan_finds_pointer_add_and_displaced_store(self):
        image = bytearray(0x1000)
        run_start = 0x700
        literal = 0x180
        load = 0x100
        _put_word(image, load, _mov_l_pc_word(load, literal, 1))
        _put_word(image, load + 2, 0x7104)  # add #4,r1
        _put_word(image, load + 4, 0x2122)  # mov.l r2,@r1
        image[literal : literal + 4] = (RUNTIME_BASE + run_start).to_bytes(
            4, "big"
        )

        report = _scan_bounded_direct_writers(
            bytes(image), run_start=run_start, run_end=run_start + 0x50
        )

        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(
            report["candidates"][0]["destination_file_offset"], run_start + 4
        )
        self.assertEqual(
            report["candidates"][0]["seed_address_model"], "runtime"
        )

    def test_call_use_is_not_misclassified_as_writer(self):
        image = bytearray(0x1000)
        run_start = 0x700
        _write_literal_call(
            image, load=0x100, literal=0x180, target=run_start + 8, register=1
        )

        report = _scan_bounded_direct_writers(
            bytes(image), run_start=run_start, run_end=run_start + 0x50
        )

        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["helper_mediated_copy_modeled"])

    def test_left_slot_contexts_select_one_right_target(self):
        left = bytearray(b"\x00\x09" * 0x1000)
        right = bytearray(b"\x00\x09" * 0x1000)
        left_target = 0x1800
        right_target = 0x1900
        for index in range(40):
            block = 0x100 + index * 0x30
            load = block + 0x10
            literal = block + 0x20
            _put_word(left, load - 2, 0xE100 | index)
            _put_word(right, load - 2, 0xE100 | index)
            _write_literal_call(
                left, load=load, literal=literal, target=left_target
            )
            _write_literal_call(
                right, load=load, literal=literal, target=right_target
            )
        left_calls = _literal_jsr_calls(bytes(left), image_size=len(left))
        right_calls = _literal_jsr_calls(bytes(right), image_size=len(right))

        report = _map_left_slot_to_right(
            bytes(left),
            bytes(right),
            left_calls,
            right_calls,
            left_target=left_target,
        )

        self.assertEqual(report["dominant_right_target_file_offset"], right_target)
        self.assertEqual(report["dominant_right_target_consensus_count"], 40)
        self.assertEqual(report["dominant_right_target_consensus_coverage"], 1.0)
        self.assertFalse(report["runtime_equivalence_asserted"])

    def test_branch_feasibility_does_not_assert_runtime_stub(self):
        report = _branch_feasibility(0x700, 0x590, 0x710)

        self.assertTrue(report["signed_12_bit_branch_range_satisfied"])
        self.assertTrue(report["footprint_fits"])
        self.assertFalse(report["instruction_encoding_observed_on_disk"])
        self.assertFalse(report["runtime_branch_stub_asserted"])

    def test_correlation_keeps_runtime_mechanism_and_media_open(self):
        prior = {
            "media": {"container": "FLDB"},
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v11",
                "nodes": [],
                "edges": [],
            },
        }
        comparison = {
            "analysis_mode": "read-only-static-bounded-runtime-slot-lineage",
            "classification": {
                "active_zero_tail_slots": "CONFIRMED_THREE_LITERAL_BACKED_CALL_TARGETS",
                "direct_static_writer": "NOT_FOUND_UNDER_BOUNDED_PC_RELATIVE_ADDRESS_MODEL",
                "runtime_patch_overlay_or_linkage_mechanism": "HYPOTHESIS_STRENGTHENED_BY_SHADOW_LAYOUT",
            },
            "interpretation": "bounded",
            "publication_safety": {"firmware_bytes_included": False},
        }

        report = correlate_runtime_slot_lineage(prior, comparison)

        self.assertEqual(report["correlation"]["actual_fldb_parser"], "OPEN")
        self.assertEqual(report["correlation"]["sector_read_abi"], "OPEN")
        self.assertEqual(report["correlation"]["dynamic_compatibility"], "NOT_ESTABLISHED")
        self.assertEqual(
            report["operational_graph"]["schema"],
            "phoenix-mmi.operational-graph/v12",
        )


if __name__ == "__main__":
    unittest.main()

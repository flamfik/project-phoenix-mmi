from __future__ import annotations

import unittest

from phoenix_mmi.accessor_dispatch import (
    _compare_call_families,
    _find_zero_tail_record_run,
    _literal_jsr_calls,
    _target_reference_profile,
    correlate_accessor_dispatch,
)
from phoenix_mmi.navigation_storage import RUNTIME_BASE


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


class AccessorDispatchTests(unittest.TestCase):
    def test_reference_profile_separates_literal_calls_from_data_words(self):
        image = bytearray(0x1000)
        target = 0x700
        _write_literal_call(image, load=0x100, literal=0x180, target=target)
        _write_literal_call(image, load=0x200, literal=0x280, target=target)
        image[0x300:0x304] = (RUNTIME_BASE + target).to_bytes(4, "big")
        calls = _literal_jsr_calls(bytes(image), image_size=len(image))
        profile = _target_reference_profile(
            bytes(image), calls, target=target, image_size=len(image)
        )

        self.assertEqual(profile["exact_word_occurrence_count"], 3)
        self.assertEqual(profile["adjacent_literal_jsr_count"], 2)
        self.assertEqual(profile["data_only_aligned_occurrence_count"], 1)
        self.assertFalse(profile["all_aligned_occurrences_are_pc_relative_literals"])

    def test_strong_contexts_promote_only_target_convergence(self):
        left = bytearray(b"\x00\x09" * 0x2000)
        right = bytearray(b"\x00\x09" * 0x2000)
        left_target = 0x3000
        right_target = 0x3400
        for index in range(40):
            block = 0x100 + index * 0x40
            load = block + 0x10
            literal = block + 0x30
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
        report, _ = _compare_call_families(
            bytes(left),
            bytes(right),
            left_calls,
            right_calls,
            right_target=right_target,
        )

        self.assertEqual(report["unique_left_context_match_count"], 40)
        self.assertEqual(report["dominant_left_target_file_offset"], left_target)
        self.assertEqual(report["dominant_left_target_consensus_count"], 40)
        self.assertTrue(report["cross_version_call_family_promoted"])
        self.assertFalse(report["runtime_equivalence_asserted"])

    def test_zero_tail_run_is_structural_not_trampoline_proof(self):
        image = bytearray(0x1000)
        start = 0x200
        for ordinal in range(5):
            record = start + ordinal * 16
            image[record : record + 4] = (
                RUNTIME_BASE + 0x700 - ordinal * 0x20
            ).to_bytes(4, "big")
        target = start + 16 + 8
        report = _find_zero_tail_record_run(
            bytes(image), target=target, image_size=len(image)
        )

        self.assertIsNotNone(report)
        self.assertEqual(report["record_count"], 5)
        self.assertEqual(report["target_record_ordinal"], 1)
        self.assertEqual(report["target_offset_within_record"], 8)
        self.assertEqual(
            report["runtime_patch_or_trampoline_semantics"], "HYPOTHESIS"
        )

    def test_correlation_keeps_dynamic_and_media_boundaries_open(self):
        prior = {
            "media": {"container": "FLDB"},
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v10",
                "nodes": [],
                "edges": [],
            },
        }
        comparison = {
            "analysis_mode": "read-only-static-bounded-accessor-call-family",
            "classification": {
                "cross_version_call_family": "CONFIRMED_BOUNDED_TARGET_CONVERGENCE",
                "accepted_optical_graph_edge": "NOT_FOUND_UNDER_REGISTERED_NODE_MODEL",
            },
            "interpretation": "bounded",
            "publication_safety": {"firmware_bytes_included": False},
        }
        report = correlate_accessor_dispatch(prior, comparison)

        self.assertEqual(report["correlation"]["actual_fldb_parser"], "OPEN")
        self.assertEqual(report["correlation"]["sector_read_abi"], "OPEN")
        self.assertEqual(report["correlation"]["dynamic_compatibility"], "NOT_ESTABLISHED")
        self.assertEqual(report["operational_graph"]["schema"], "phoenix-mmi.operational-graph/v11")


if __name__ == "__main__":
    unittest.main()

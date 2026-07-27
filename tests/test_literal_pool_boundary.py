from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.literal_pool_boundary import (
    _maximal_runtime_pool_containing,
    _pool_reference_profile,
    analyze_literal_pool_boundaries,
    build_public_literal_pool_boundary_report,
    update_operational_graph_v23,
)
from phoenix_mmi.linkage_owner import _MemoryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE


SUCCESSOR = bytes.fromhex(
    "4f22"
    "e000"
    "0009"
    "000b"
    "0009"
)


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _mov_l_literal(referrer: int, literal: int, register: int) -> bytes:
    base = (referrer & ~3) + 4
    displacement, remainder = divmod(literal - base, 4)
    if remainder or not 0 <= displacement <= 0xFF:
        raise ValueError("synthetic literal is not encodable")
    word = 0xD000 | (register << 8) | displacement
    return word.to_bytes(2, "big")


def _write_pool(
    data: bytearray,
    start: int,
    word_count: int,
) -> None:
    referrer_start = start - 0x60
    for index in range(word_count):
        literal = start + index * 4
        referrer = referrer_start + index * 8
        data[referrer : referrer + 2] = _mov_l_literal(
            referrer, literal, 0
        )
        data[referrer + 2 : referrer + 8] = bytes.fromhex(
            "400b00090009"
        )
        value = RUNTIME_BASE + 0x300 + index * 4
        data[literal : literal + 4] = value.to_bytes(4, "big")
    end = start + word_count * 4
    data[end : end + len(SUCCESSOR)] = SUCCESSOR


def _write_runtime_target_reference(
    data: bytearray,
    *,
    literal: int,
    referrer: int,
    target: int,
) -> None:
    data[referrer : referrer + 2] = _mov_l_literal(
        referrer, literal, 0
    )
    data[referrer + 2 : referrer + 8] = bytes.fromhex(
        "400b00090009"
    )
    data[literal : literal + 4] = (
        RUNTIME_BASE + target
    ).to_bytes(4, "big")


def _image(*, right: bool) -> tuple[bytes, tuple[int, int]]:
    data = bytearray(0x500)
    shift = 0x20 if right else 0
    first_start = 0x100 + shift
    second_start = 0x200 + shift
    _write_pool(data, first_start, 4)
    _write_pool(data, second_start, 6)
    first_target = first_start + (0 if right else 1) * 4
    second_target = second_start + (3 if right else 4) * 4
    _write_runtime_target_reference(
        data,
        literal=0x3C0 + shift,
        referrer=0x3A0 + shift,
        target=first_target,
    )
    _write_runtime_target_reference(
        data,
        literal=0x400 + shift,
        referrer=0x3E0 + shift,
        target=second_target,
    )
    return bytes(data), (first_target, second_target)


def _session029(
    left_targets: tuple[int, int],
    right_targets: tuple[int, int],
) -> dict[str, object]:
    return {
        "handoff_pairs": [
            {
                "flow_ordinal": ordinal,
                "left": {
                    "raw_target_file_offset": left,
                },
                "right": {
                    "raw_target_file_offset": right,
                },
            }
            for ordinal, left, right in zip(
                (12, 13), left_targets, right_targets
            )
        ]
    }


class LiteralPoolBoundaryTests(unittest.TestCase):
    def test_pool_scan_extends_before_and_after_registered_target(self):
        data, targets = _image(right=False)
        with TemporaryDirectory() as temporary:
            reader = _reader(data, temporary, "left.bin")
            profile = _maximal_runtime_pool_containing(
                reader, targets[0]
            )
            self.assertTrue(profile["pool_found"])
            self.assertEqual(profile["pool_word_count"], 4)
            self.assertEqual(
                profile["registered_target_word_index"], 1
            )
            self.assertEqual(
                profile[
                    "words_from_registered_target_to_pool_end"
                ],
                3,
            )

    def test_pool_scan_rejects_bound_exhaustion(self):
        data = bytearray(0x100)
        for index in range(10):
            data[0x20 + index * 4 : 0x24 + index * 4] = (
                RUNTIME_BASE + index * 4
            ).to_bytes(4, "big")
        with TemporaryDirectory() as temporary:
            reader = _reader(bytes(data), temporary, "run.bin")
            profile = _maximal_runtime_pool_containing(
                reader,
                0x30,
                maximum_words_each_direction=2,
            )
            self.assertFalse(profile["pool_found"])
            self.assertTrue(
                profile["backward_bound_exhausted"]
                or profile["forward_bound_exhausted"]
            )

    def test_pool_profile_requires_one_preceding_referrer_per_word(self):
        data, targets = _image(right=False)
        with TemporaryDirectory() as temporary:
            reader = _reader(data, temporary, "left.bin")
            pool = _maximal_runtime_pool_containing(
                reader, targets[1]
            )
            profile = _pool_reference_profile(
                reader, _MemoryReader(data), pool
            )
            self.assertEqual(profile["pool_word_count"], 6)
            self.assertEqual(
                profile["pc_relative_referrer_count"], 6
            )
            self.assertTrue(
                profile[
                    "all_pool_words_have_one_pc_relative_referrer"
                ]
            )
            self.assertTrue(profile["all_referrers_precede_pool"])
            self.assertEqual(
                profile["use_classification_counts"],
                {"INDIRECT_CONTROL_TARGET": 6},
            )

    def test_bilateral_analysis_corrects_prefix_interpretation(self):
        left_data, left_targets = _image(right=False)
        right_data, right_targets = _image(right=True)
        with TemporaryDirectory() as temporary:
            left = _reader(left_data, temporary, "left.bin")
            right = _reader(right_data, temporary, "right.bin")
            report = analyze_literal_pool_boundaries(
                left,
                right,
                _session029(left_targets, right_targets),
            )
            classification = report["classification"]
            self.assertEqual(
                classification[
                    "bilateral_literal_pool_pair_count"
                ],
                2,
            )
            self.assertEqual(
                classification["pool_word_counts"], [4, 6]
            )
            self.assertTrue(
                classification[
                    "all_registered_targets_are_single_indirect_control_targets"
                ]
            )
            self.assertEqual(
                classification[
                    "common_structural_pool_relocation_delta"
                ],
                0x20,
            )
            self.assertEqual(
                classification[
                    "common_raw_target_relocation_delta"
                ],
                0x1C,
            )
            self.assertEqual(
                classification[
                    "common_structural_vs_raw_relocation_skew"
                ],
                4,
            )
            self.assertTrue(
                all(
                    pair["gates"][
                        "boundary_correction_gate_passed"
                    ]
                    for pair in report["target_pairs"]
                )
            )

    def test_pool_end_is_adjacent_code_not_runtime_callee(self):
        left_data, left_targets = _image(right=False)
        right_data, right_targets = _image(right=True)
        with TemporaryDirectory() as temporary:
            report = analyze_literal_pool_boundaries(
                _reader(left_data, temporary, "left.bin"),
                _reader(right_data, temporary, "right.bin"),
                _session029(left_targets, right_targets),
            )
            for pair in report["target_pairs"]:
                self.assertTrue(
                    pair["gates"][
                        "pool_end_successor_code_gate_both"
                    ]
                )
                self.assertTrue(
                    pair["gates"][
                        "pool_end_has_no_static_runtime_reference_both"
                    ]
                )
                self.assertFalse(
                    pair["pool_end_runtime_callee_established"]
                )
            self.assertEqual(
                report["classification"][
                    "static_handoff_registration_path"
                ],
                "OPEN_ACTUAL_TARGET_UNRESOLVED",
            )

    def test_graph_v23_withdraws_callee_disproof_edge(self):
        comparison = {
            "classification": {
                "bilateral_literal_pool_pair_count": 2,
            },
            "interpretation": "literal-pool correction",
        }
        graph = update_operational_graph_v23(
            {
                "schema": "phoenix-mmi.operational-graph/v22",
                "nodes": [
                    {
                        "id": "prefix-corrected-static-callees",
                        "status": "CONFIRMED",
                    }
                ],
                "edges": [
                    {
                        "source": "prefix-corrected-static-callees",
                        "target": "runtime-linkage-owner-ingress",
                        "status": "DISPROVED_FOR_BOUNDED_CALLEE_FAMILY",
                    }
                ],
            },
            comparison,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v23"
        )
        self.assertNotIn(
            "prefix-corrected-static-callees",
            {node["id"] for node in graph["nodes"]},
        )
        self.assertEqual(graph["edges"][-1]["status"], "OPEN")
        self.assertEqual(graph["disproved_edge_count"], 0)

    def test_public_copy_is_detached(self):
        report = {
            "publication_safety": {
                "raw_pointer_values_included": False
            },
            "classification": {"pool_end_runtime_callee": "OPEN"},
        }
        public = build_public_literal_pool_boundary_report(report)
        public["classification"]["pool_end_runtime_callee"] = "changed"
        self.assertEqual(
            report["classification"]["pool_end_runtime_callee"],
            "OPEN",
        )


if __name__ == "__main__":
    unittest.main()

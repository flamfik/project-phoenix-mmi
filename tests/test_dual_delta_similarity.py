from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.dual_delta_similarity import (
    analyze_dual_delta_similarity,
    build_public_dual_delta_similarity_report,
    compare_similarity_grid_control,
    finalize_dual_delta_similarity,
    update_operational_graph_v28,
)


def _stream(length: int, salt: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(salt + counter.to_bytes(4, "big")).digest()
        )
        counter += 1
    return bytes(output[:length])


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _fixture():
    left = bytearray(_stream(0x7000, b"left"))
    right = bytearray(_stream(0x9000, b"right"))
    lower = 0x2000
    upper = 0x3800
    left_delta = 0x3000
    right_delta = -0x1000
    prefix_end = 0x2A00
    suffix_start = 0x2E00
    right[
        lower + left_delta : prefix_end + left_delta
    ] = left[lower:prefix_end]
    right[
        suffix_start + right_delta : upper + right_delta
    ] = left[suffix_start:upper]
    prior = {
        "schema": "phoenix-mmi.exact-block-map-comparison/v1",
        "left_artifact_sha256": hashlib.sha256(left).hexdigest(),
        "right_artifact_sha256": hashlib.sha256(right).hexdigest(),
        "classification": {
            "file_layout_reorder_exact_block_support": (
                "CONFIRMED_AT_EXACT_BLOCKS"
            ),
            "strict_seed_control": "CONFIRMED_STABLE",
            "exact_section_boundary": "OPEN",
        },
        "transition_envelope": {
            "classification": "NARROWED_BY_EXACT_BLOCKS",
            "narrowed_lower_bound": lower,
            "narrowed_upper_bound": upper,
            "narrowed_width": upper - lower,
            "exact_breakpoint_asserted": False,
        },
        "lanes": [
            {
                "zone_id": "RZ-012",
                "expected_zone_delta": left_delta,
            },
            {
                "zone_id": "RZ-013",
                "expected_zone_delta": right_delta,
            },
        ],
    }
    return bytes(left), bytes(right), prior


class DualDeltaSimilarityTests(unittest.TestCase):
    def _reports(self):
        left, right, prior = _fixture()
        with TemporaryDirectory() as temporary:
            left_reader = _reader(left, temporary, "left.bin")
            right_reader = _reader(right, temporary, "right.bin")
            primary = analyze_dual_delta_similarity(
                left_reader,
                right_reader,
                prior,
                window_sizes=(256, 512, 1024),
                step=128,
            )
            shifted = analyze_dual_delta_similarity(
                left_reader,
                right_reader,
                prior,
                window_sizes=(256, 512, 1024),
                step=128,
                grid_offset=64,
            )
        return primary, shifted

    def test_all_fixed_scales_find_one_forward_change(self):
        primary, _ = self._reports()
        self.assertEqual(
            primary["multiscale"]["classification"],
            "REPRODUCIBLE_MULTISCALE_DOMINANCE_CHANGE",
        )
        self.assertTrue(
            all(
                profile["summary"]["classification"]
                == "SINGLE_FORWARD_DOMINANCE_CHANGE"
                for profile in primary["profiles"]
            )
        )

    def test_search_contract_has_only_two_prior_deltas(self):
        primary, _ = self._reports()
        contract = primary["search_contract"]
        self.assertEqual(contract["left_delta"], 0x3000)
        self.assertEqual(contract["right_delta"], -0x1000)
        self.assertEqual(contract["window_sizes"], [256, 512, 1024])
        self.assertEqual(contract["step"], 128)
        self.assertFalse(contract["new_delta_search_performed"])
        self.assertFalse(contract["whole_image_search_performed"])
        self.assertFalse(contract["adaptive_threshold_used"])

    def test_grid_shift_control_is_stable(self):
        primary, shifted = self._reports()
        control = compare_similarity_grid_control(primary, shifted)
        self.assertEqual(
            control["classification"], "CONFIRMED_POSITIVE_GRID_STABLE"
        )
        self.assertTrue(control["crossing_hulls_overlap"])

    def test_finalize_closes_only_the_fixed_model_when_unstable(self):
        primary, shifted = self._reports()
        primary["multiscale"]["classification"] = (
            "NOT_STABLE_ACROSS_WINDOW_SIZES"
        )
        shifted["multiscale"]["classification"] = (
            "NOT_STABLE_ACROSS_WINDOW_SIZES"
        )
        for primary_profile, shifted_profile in zip(
            primary["profiles"], shifted["profiles"], strict=True
        ):
            primary_profile["summary"]["classification"] = (
                "MULTIPLE_OR_REVERSED_DOMINANCE_CHANGES"
            )
            shifted_profile["summary"]["classification"] = (
                "MULTIPLE_OR_REVERSED_DOMINANCE_CHANGES"
            )
        finalized = finalize_dual_delta_similarity(primary, shifted)
        self.assertEqual(
            finalized["classification"][
                "single_dominance_change_model"
            ],
            "CLOSED_BOUNDED_NEGATIVE",
        )
        self.assertEqual(
            finalized["classification"]["transition_envelope"],
            "UNCHANGED_FROM_SESSION034",
        )
        self.assertEqual(
            finalized["classification"]["exact_section_boundary"], "OPEN"
        )

    def test_exact_boundary_and_runtime_remain_open(self):
        primary, _ = self._reports()
        self.assertFalse(
            primary["multiscale"]["exact_breakpoint_asserted"]
        )
        self.assertEqual(
            primary["classification"]["exact_section_boundary"], "OPEN"
        )
        self.assertFalse(
            primary["classification"]["runtime_execution_observed"]
        )
        self.assertEqual(
            primary["classification"]["runtime_loader_transform"],
            "NOT_OBSERVED",
        )

    def test_public_report_removes_per_window_metrics(self):
        primary, _ = self._reports()
        public = build_public_dual_delta_similarity_report(primary)
        self.assertTrue(all("windows" not in row for row in public["profiles"]))
        public["classification"]["exact_section_boundary"] = "changed"
        self.assertEqual(
            primary["classification"]["exact_section_boundary"], "OPEN"
        )

    def test_hash_gate_rejects_changed_artifact(self):
        left, right, prior = _fixture()
        changed = bytearray(left)
        changed[-1] ^= 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "left principal-image"):
                analyze_dual_delta_similarity(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                )

    def test_graph_v28_adds_non_exact_transition(self):
        primary, _ = self._reports()
        graph = update_operational_graph_v28(
            {
                "schema": "phoenix-mmi.operational-graph/v27",
                "nodes": [],
                "edges": [],
            },
            primary,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v28"
        )
        self.assertFalse(graph["nodes"][-1]["exact_boundary"])
        self.assertEqual(
            graph["edges"][-1]["relation"],
            "locates-non-exact-dominance-change",
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.relocation_breakpoints import (
    analyze_relocation_breakpoints,
    build_public_relocation_breakpoint_report,
    update_operational_graph_v25,
)


CODE = bytes.fromhex("4f22e0000009000b0009")


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _fixture() -> tuple[bytes, bytes, dict[str, object]]:
    left = bytearray(0x3000)
    right = bytearray(0x3200)
    core = bytes(range(64))
    bitmap = bytes(reversed(range(80)))
    left[0x1800:0x1840] = core
    right[0x1900:0x1940] = core
    left[0x1A00:0x1A50] = bitmap
    right[0x1B00:0x1B50] = bitmap

    code_pairs = [(0x400, 0x500), (0x440, 0x540)]
    for left_offset, right_offset in code_pairs:
        left[left_offset : left_offset + len(CODE)] = CODE
        right[right_offset : right_offset + len(CODE)] = CODE

    pool_left = 0x100
    pool_right = 0x200
    pool_pairs = [code_pairs[0], (0x900, 0xA00)]
    for index, (left_target, right_target) in enumerate(pool_pairs):
        left[pool_left + index * 4 : pool_left + index * 4 + 4] = (
            RUNTIME_BASE + left_target
        ).to_bytes(4, "big")
        right[
            pool_right + index * 4 : pool_right + index * 4 + 4
        ] = (RUNTIME_BASE + right_target).to_bytes(4, "big")

    entries = [
        {
            "uses": [
                {"classification": "INDIRECT_CONTROL_TARGET"}
            ]
        }
        for _ in pool_pairs
    ]
    reports = {
        "session005_left": {
            "core_bundle": {
                "offset": 0x1800,
                "length": len(core),
                "sha256": hashlib.sha256(core).hexdigest(),
            }
        },
        "session005_right": {
            "core_bundle": {
                "offset": 0x1900,
                "length": len(core),
                "sha256": hashlib.sha256(core).hexdigest(),
            }
        },
        "session008": {
            "bitmap_atlas": {
                "equal_region": {
                    "left_offset": 0x1A00,
                    "right_offset": 0x1B00,
                    "length": len(bitmap),
                    "sha256": hashlib.sha256(bitmap).hexdigest(),
                }
            }
        },
        "session009": {
            "relocation_bands": [
                {
                    "constant_relocation_delta": True,
                    "structural_status": "CONFIRMED_ORDERED",
                    "minimum_relocation_delta": 0x100,
                    "maximum_relocation_delta": 0x100,
                    "left_start": 0x300,
                    "left_end": 0x380,
                    "right_start": 0x400,
                    "right_end": 0x480,
                    "pair_count": 4,
                    "dominant_domain": "test",
                    "dual_release_code_referenced_pair_count": 1,
                }
            ]
        },
        "session015": {
            "navigation_seed_pairs": [
                {
                    "left_entry_file_offset": code_pairs[0][0],
                    "right_entry_file_offset": code_pairs[0][1],
                    "classification": "CONFIRMED_TEST",
                    "occurrence_count": 1,
                }
            ],
            "optical_seed_pairs": [
                {
                    "left_entry_file_offset": code_pairs[1][0],
                    "right_entry_file_offset": code_pairs[1][1],
                    "classification": "CONFIRMED_TEST",
                    "occurrence_count": 1,
                }
            ],
        },
        "session030": {
            "target_pairs": [
                {
                    "flow_ordinal": 12,
                    "left": {
                        "pool": {
                            "pool_start_file_offset": pool_left,
                            "pool_word_count": len(pool_pairs),
                        },
                        "pool_references": {"entries": entries},
                    },
                    "right": {
                        "pool": {
                            "pool_start_file_offset": pool_right,
                            "pool_word_count": len(pool_pairs),
                        },
                        "pool_references": {"entries": entries},
                    },
                }
            ]
        },
        "session031": {
            "classification": {"unique_link_pair_count": 2},
            "unique_pairs": [
                {
                    "pair_id": f"LP-{index + 1:03d}",
                    "link_relocation_delta": right - left,
                    "use_classification": (
                        "INDIRECT_CONTROL_TARGET"
                    ),
                    "occurrences": [
                        {
                            "flow_ordinal": 12,
                            "word_index": index,
                        }
                    ],
                }
                for index, (left, right) in enumerate(pool_pairs)
            ],
        },
    }
    return bytes(left), bytes(right), reports


class RelocationBreakpointTests(unittest.TestCase):
    def _report(self) -> dict[str, object]:
        left, right, reports = _fixture()
        with TemporaryDirectory() as temporary:
            return analyze_relocation_breakpoints(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                **reports,
            )

    def test_exact_regions_are_raw_verified(self):
        report = self._report()
        self.assertEqual(
            report["classification"]["exact_data_region_count"], 2
        )
        self.assertTrue(
            all(
                region["byte_identity_verified"]
                for region in report["exact_data_regions"]
            )
        )

    def test_two_code_anchors_form_non_interpolated_plateau(self):
        report = self._report()
        plateau = report["direct_code_plateaus"][0]
        self.assertEqual(plateau["anchor_count"], 2)
        self.assertEqual(plateau["relocation_delta"], 0x100)
        self.assertFalse(
            plateau["continuous_interval_mapping_asserted"]
        )

    def test_cross_class_support_requires_equal_delta(self):
        report = self._report()
        support = report["cross_class_delta_support"][0]
        self.assertEqual(support["relocation_delta"], 0x100)
        self.assertEqual(support["direct_code_anchor_count"], 2)

    def test_pool_pair_separates_identity_from_delta_only(self):
        report = self._report()
        rows = report["pool_pair_reconciliation"]
        self.assertEqual(
            rows[0]["status"],
            "CONFIRMED_EXACT_PRIOR_DIRECT_CODE_ANCHOR",
        )
        self.assertFalse(rows[0]["original_handoff_callee_asserted"])
        self.assertEqual(
            rows[1]["status"], "DELTA_FAMILY_ONLY_NOT_IDENTITY"
        )

    def test_public_copy_is_detached(self):
        report = {
            "classification": {
                "continuous_universal_file_map": "OPEN"
            },
            "publication_safety": {
                "raw_pointer_values_included": False
            },
        }
        public = build_public_relocation_breakpoint_report(report)
        public["classification"][
            "continuous_universal_file_map"
        ] = "changed"
        self.assertEqual(
            report["classification"][
                "continuous_universal_file_map"
            ],
            "OPEN",
        )

    def test_graph_v25_keeps_original_handoff_open(self):
        graph = update_operational_graph_v25(
            {
                "schema": "phoenix-mmi.operational-graph/v24",
                "nodes": [],
                "edges": [],
            },
            {
                "classification": {
                    "direct_link_code_anchor_count": 2,
                    "support_zone_count": 3,
                    "breakpoint_bracket_count": 2,
                    "pool_exact_direct_code_anchor_match_count": 1,
                },
                "interpretation": "anchors only",
            },
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v25"
        )
        self.assertEqual(graph["edges"][-1]["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()

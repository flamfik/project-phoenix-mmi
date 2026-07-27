from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.piecewise_link_map import (
    analyze_piecewise_link_map,
    build_public_piecewise_link_map_report,
    update_operational_graph_v24,
)


CODE = bytes.fromhex("4f22e0000009000b0009")


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _session030() -> dict[str, object]:
    entries = [
        {
            "word_index": index,
            "uses": [
                {
                    "classification": (
                        "ARGUMENT_TO_OTHER_INDIRECT_CALL"
                        if index == 2
                        else "INDIRECT_CONTROL_TARGET"
                    )
                }
            ],
        }
        for index in range(3)
    ]
    return {
        "target_pairs": [
            {
                "flow_ordinal": 12,
                "pool_start_file_offset_delta": 0x100,
                "left": {
                    "pool": {
                        "pool_start_file_offset": 0x100,
                        "pool_word_count": 3,
                    },
                    "pool_references": {"entries": entries},
                },
                "right": {
                    "pool": {
                        "pool_start_file_offset": 0x200,
                        "pool_word_count": 3,
                    },
                    "pool_references": {"entries": entries},
                },
            }
        ]
    }


def _images(*, duplicate_first: bool = False) -> tuple[bytes, bytes]:
    left = bytearray(0x2000)
    right = bytearray(0x2200)
    left_links = [0x400, 0x600, 0x800]
    right_links = [
        left_links[0] + 0x120,
        left_links[1] + 0x120,
        left_links[2] + 0x140,
    ]
    if duplicate_first:
        left_links[1] = left_links[0]
        right_links[1] = right_links[0]
    for index, value in enumerate(left_links):
        left[0x100 + index * 4 : 0x104 + index * 4] = (
            RUNTIME_BASE + value
        ).to_bytes(4, "big")
    for index, value in enumerate(right_links):
        right[0x200 + index * 4 : 0x204 + index * 4] = (
            RUNTIME_BASE + value
        ).to_bytes(4, "big")
    for value in left_links[:2]:
        left[value + 0x20 : value + 0x20 + len(CODE)] = CODE
    for value in right_links[:2]:
        right[value : value + len(CODE)] = CODE
    return bytes(left), bytes(right)


class PiecewiseLinkMapTests(unittest.TestCase):
    def test_two_independent_pairs_confirm_one_piece(self):
        left_data, right_data = _images()
        with TemporaryDirectory() as temporary:
            report = analyze_piecewise_link_map(
                _reader(left_data, temporary, "left.bin"),
                _reader(right_data, temporary, "right.bin"),
                _session030(),
                search_radius=0x40,
            )
        classification = report["classification"]
        self.assertEqual(
            classification["link_relocation_family_count"], 2
        )
        self.assertEqual(
            classification["confirmed_piecewise_family_count"], 1
        )
        family = next(
            row
            for row in report["families"]
            if row["link_relocation_delta"] == 0x120
        )
        self.assertEqual(family["link_relocation_delta"], 0x120)
        self.assertEqual(family["relative_file_correction"], -0x20)
        self.assertEqual(family["selected_common_correction"], 0x20)
        self.assertEqual(
            family["status"],
            "CONFIRMED_TWO_INDEPENDENT_CODE_ANCHORS",
        )

    def test_duplicate_occurrence_is_not_independent_anchor(self):
        left_data, right_data = _images(duplicate_first=True)
        with TemporaryDirectory() as temporary:
            report = analyze_piecewise_link_map(
                _reader(left_data, temporary, "left.bin"),
                _reader(right_data, temporary, "right.bin"),
                _session030(),
                search_radius=0x40,
            )
        family = next(
            row
            for row in report["families"]
            if row["link_relocation_delta"] == 0x120
        )
        self.assertEqual(family["occurrence_count"], 2)
        self.assertEqual(family["unique_pair_count"], 1)
        self.assertEqual(
            family["status"],
            "PROVISIONAL_SINGLE_PAIR_OR_INCOMPLETE_FAMILY",
        )

    def test_argument_literal_is_not_code_searched(self):
        left_data, right_data = _images()
        with TemporaryDirectory() as temporary:
            report = analyze_piecewise_link_map(
                _reader(left_data, temporary, "left.bin"),
                _reader(right_data, temporary, "right.bin"),
                _session030(),
                search_radius=0x40,
            )
        argument = next(
            pair
            for pair in report["unique_pairs"]
            if pair["use_classification"]
            == "ARGUMENT_TO_OTHER_INDIRECT_CALL"
        )
        self.assertFalse(argument["code_anchor_eligible"])
        self.assertFalse(argument["bounded_search"]["performed"])

    def test_public_report_excludes_raw_link_values(self):
        report = {
            "publication_safety": {
                "raw_pointer_values_included": False
            },
            "classification": {"piecewise_link_to_file_map": "OPEN"},
        }
        public = build_public_piecewise_link_map_report(report)
        public["classification"]["piecewise_link_to_file_map"] = "changed"
        self.assertEqual(
            report["classification"]["piecewise_link_to_file_map"],
            "OPEN",
        )

    def test_graph_v24_keeps_runtime_callee_open(self):
        graph = update_operational_graph_v24(
            {
                "schema": "phoenix-mmi.operational-graph/v23",
                "nodes": [],
                "edges": [],
            },
            {
                "classification": {
                    "link_relocation_family_count": 3,
                    "piecewise_link_to_file_map": "NOT_ESTABLISHED",
                    "confirmed_piecewise_family_count": 0,
                },
                "interpretation": "bounded map",
            },
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v24"
        )
        self.assertEqual(graph["edges"][-1]["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()

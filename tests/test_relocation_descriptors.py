from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.relocation_descriptors import (
    analyze_relocation_descriptors,
    build_public_relocation_descriptor_report,
    update_operational_graph_v26,
)


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _put_reference(data: bytearray, instruction: int, literal: int, target: int):
    displacement = (literal - ((instruction & ~3) + 4)) // 4
    data[instruction : instruction + 2] = (
        0xD000 | displacement
    ).to_bytes(2, "big")
    data[literal : literal + 4] = (
        RUNTIME_BASE + target
    ).to_bytes(4, "big")


def _put_table(
    data: bytearray,
    table: int,
    records: list[tuple[int, int, int]],
):
    for ordinal, (source, destination, length) in enumerate(records):
        offset = table + ordinal * 12
        data[offset : offset + 12] = b"".join(
            (
                (RUNTIME_BASE + source).to_bytes(4, "big"),
                (RUNTIME_BASE + destination).to_bytes(4, "big"),
                length.to_bytes(4, "big"),
            )
        )


def _fixture(*, reference_tables: bool = True):
    left = bytearray(0x2000)
    right = bytearray(0x2000)
    left_table = 0x100
    right_table = 0x140
    _put_table(
        left,
        left_table,
        [(0x400, 0x1000, 0x20), (0x800, 0x1100, 0x20)],
    )
    _put_table(
        right,
        right_table,
        [(0x500, 0x1000, 0x20), (0x200, 0x1100, 0x20)],
    )
    if reference_tables:
        _put_reference(left, 0x40, 0x80, left_table)
        _put_reference(right, 0x40, 0x80, right_table)
    prior = {
        "schema": "phoenix-mmi.relocation-breakpoint-comparison/v1",
        "left_artifact_sha256": hashlib.sha256(left).hexdigest(),
        "right_artifact_sha256": hashlib.sha256(right).hexdigest(),
        "support_zones": [
            {
                "zone_id": "RZ-001",
                "source_id": "MB-001",
                "evidence_class": "CONSTANT_DELTA_ORDERED_MARKER_BAND",
                "left_start": 0x400,
                "left_end": 0x420,
                "right_start": 0x500,
                "right_end": 0x520,
            },
            {
                "zone_id": "RZ-002",
                "source_id": "MB-002",
                "evidence_class": "CONSTANT_DELTA_ORDERED_MARKER_BAND",
                "left_start": 0x800,
                "left_end": 0x820,
                "right_start": 0x200,
                "right_end": 0x220,
            },
        ],
        "breakpoint_brackets": [
            {
                "bracket_id": "RB-001",
                "classification": "SECTION_REORDER_BRACKET",
                "left_zone_id": "RZ-001",
                "right_zone_id": "RZ-002",
                "right_order_monotonic": False,
            }
        ],
    }
    return bytes(left), bytes(right), prior


class RelocationDescriptorTests(unittest.TestCase):
    def _report(self, *, reference_tables: bool = True):
        left, right, prior = _fixture(
            reference_tables=reference_tables
        )
        with TemporaryDirectory() as temporary:
            return analyze_relocation_descriptors(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                prior,
            )

    def test_bilateral_referenced_two_record_table_passes(self):
        report = self._report()
        self.assertGreaterEqual(
            report["classification"][
                "bilateral_descriptor_pair_count"
            ],
            1,
        )
        self.assertEqual(
            report["classification"][
                "coherent_reorder_descriptor_table"
            ],
            "PROBABLE_BILATERAL_STRUCTURAL",
        )
        pair = report["bilateral_descriptor_pairs"][0]
        self.assertEqual(pair["record_count"], 2)
        self.assertTrue(pair["both_tables_pc_relative_referenced"])

    def test_unreferenced_geometry_is_not_promoted(self):
        report = self._report(reference_tables=False)
        self.assertEqual(
            report["classification"][
                "bilateral_descriptor_pair_count"
            ],
            0,
        )
        self.assertEqual(
            report["classification"][
                "coherent_reorder_descriptor_table"
            ],
            "CLOSED_BOUNDED_NEGATIVE",
        )

    def test_search_contract_excludes_arbitrary_tuple_scan(self):
        report = self._report()
        self.assertFalse(
            report["search_contract"][
                "arbitrary_whole_image_tuple_scan_performed"
            ]
        )
        self.assertEqual(
            report["search_contract"]["minimum_record_count"], 2
        )
        self.assertGreater(
            report["left"]["bounded_decode_attempt_count"], 0
        )

    def test_hash_gate_rejects_changed_artifact(self):
        left, right, prior = _fixture()
        changed = bytearray(left)
        changed[-1] = 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "left principal-image"):
                analyze_relocation_descriptors(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                )

    def test_public_copy_is_detached(self):
        report = self._report()
        public = build_public_relocation_descriptor_report(report)
        public["classification"][
            "exact_section_boundary"
        ] = "changed"
        self.assertEqual(
            report["classification"]["exact_section_boundary"], "OPEN"
        )

    def test_graph_v26_preserves_bounded_negative(self):
        comparison = self._report(reference_tables=False)
        graph = update_operational_graph_v26(
            {
                "schema": "phoenix-mmi.operational-graph/v25",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v26"
        )
        self.assertEqual(
            graph["edges"][-1]["status"], "BOUNDED_NEGATIVE"
        )


if __name__ == "__main__":
    unittest.main()

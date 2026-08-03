from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_dataflow import (
    analyze_navigation_dataflow,
    build_public_navigation_dataflow_report,
    compare_navigation_dataflow,
    discover_contract_anchors,
    summarize_code_window,
    summarize_runtime_neighborhood,
    update_operational_graph_v3,
)
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.strings import StringRecord


def _mov_l_pc_word(instruction_offset: int, literal_offset: int, register: int) -> int:
    base = (instruction_offset & ~3) + 4
    displacement = literal_offset - base
    if displacement < 0 or displacement % 4 or displacement // 4 > 0xFF:
        raise ValueError("literal is outside MOV.L PC-relative range")
    return 0xD000 | (register << 8) | (displacement // 4)


def _synthetic_image(
    path: Path,
    *,
    code_offset: int,
    literal_offset: int,
    anchor_offset: int,
    call_target: int,
) -> None:
    data = bytearray(0x1000)
    data[code_offset : code_offset + 2] = _mov_l_pc_word(
        code_offset, literal_offset, 1
    ).to_bytes(2, "big")
    data[code_offset + 2 : code_offset + 4] = (0x0009).to_bytes(2, "big")
    data[code_offset + 4 : code_offset + 6] = _mov_l_pc_word(
        code_offset + 4, literal_offset + 4, 0
    ).to_bytes(2, "big")
    data[code_offset + 6 : code_offset + 8] = (0x400B).to_bytes(2, "big")
    data[code_offset + 8 : code_offset + 10] = (0x0009).to_bytes(2, "big")
    data[literal_offset : literal_offset + 4] = (
        RUNTIME_BASE + anchor_offset
    ).to_bytes(4, "big")
    data[literal_offset + 4 : literal_offset + 8] = (
        RUNTIME_BASE + call_target
    ).to_bytes(4, "big")
    anchor = b"Navigation internal data"
    data[anchor_offset : anchor_offset + len(anchor)] = anchor
    path.write_bytes(data)


class NavigationDataflowTests(unittest.TestCase):
    def test_anchor_discovery_uses_semantic_substring_and_omits_text(self):
        records = [
            StringRecord(0x100, "ascii", "%LCCDROMAccessEvent"),
            StringRecord(0x200, "ascii", "routeact.dat"),
        ]
        hits = discover_contract_anchors(records)
        self.assertEqual(hits[0]["anchor_id"], "cdrom-access-event")
        self.assertEqual(hits[0]["offset"], 0x102)
        self.assertEqual(hits[1]["anchor_id"], "routeact-dat")
        self.assertNotIn("text", repr(hits))

    def test_runtime_pointer_normalization_matches_relocated_records(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = bytearray(b"\x00" * 0x400)
            right = bytearray(b"\x00" * 0x400)
            anchor = b"routeact.dat"
            left[0x100 : 0x100 + len(anchor)] = anchor
            right[0x100 : 0x100 + len(anchor)] = anchor
            left[0xE0:0xE4] = (RUNTIME_BASE + 0x120).to_bytes(4, "big")
            right[0xE0:0xE4] = (RUNTIME_BASE + 0x220).to_bytes(4, "big")
            (root / "left.bin").write_bytes(left)
            (root / "right.bin").write_bytes(right)
            left_summary = summarize_runtime_neighborhood(
                BinaryReader(root / "left.bin"), 0x100, radius=0x40
            )
            right_summary = summarize_runtime_neighborhood(
                BinaryReader(root / "right.bin"), 0x100, radius=0x40
            )
            self.assertNotEqual(left_summary["raw_sha256"], right_summary["raw_sha256"])
            self.assertEqual(
                left_summary["normalized_sha256"], right_summary["normalized_sha256"]
            )
            self.assertEqual(left_summary["aligned_runtime_pointer_count"], 1)
            self.assertFalse(left_summary["raw_bytes_included"])

    def test_adjacent_mov_l_jsr_target_is_resolved_without_function_claim(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.bin"
            _synthetic_image(
                path,
                code_offset=0x80,
                literal_offset=0x100,
                anchor_offset=0x300,
                call_target=0x200,
            )
            window = summarize_code_window(
                BinaryReader(path), 0x80, before=0, after=0x20
            )
            self.assertEqual(len(window["resolved_adjacent_indirect_calls"]), 1)
            self.assertEqual(
                window["resolved_adjacent_indirect_calls"][0]["target_file_offset"],
                0x200,
            )
            self.assertFalse(window["function_boundary_asserted"])
            self.assertFalse(window["instruction_bytes_included"])

    def test_cross_version_code_coupling_and_public_redaction(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            _synthetic_image(
                root / "left.bin",
                code_offset=0x80,
                literal_offset=0x100,
                anchor_offset=0x300,
                call_target=0x200,
            )
            _synthetic_image(
                root / "right.bin",
                code_offset=0x180,
                literal_offset=0x200,
                anchor_offset=0x500,
                call_target=0x400,
            )
            left = analyze_navigation_dataflow(BinaryReader(root / "left.bin"))
            right = analyze_navigation_dataflow(BinaryReader(root / "right.bin"))
            comparison = compare_navigation_dataflow(left, right)
            public = build_public_navigation_dataflow_report(left)
            self.assertEqual(len(comparison["callsite_window_pairs"]), 1)
            self.assertTrue(
                comparison["callsite_window_pairs"][0][
                    "normalized_instruction_shape_equal"
                ]
            )
            self.assertNotIn("_internal_record_key", repr(public))
            self.assertNotIn("Navigation internal data", repr(public))
            self.assertNotIn("source_member_path", repr(public))

    def test_graph_v3_preserves_open_media_and_consumer_edges(self):
        prior = {
            "schema": "phoenix-mmi.operational-graph/v2",
            "nodes": [
                {"id": "startup-runtime", "status": "CONFIRMED"},
                {"id": "navigation-runtime", "status": "CONFIRMED"},
                {"id": "optical-volume-reader", "status": "PROBABLE"},
                {"id": "map-media-format", "status": "OPEN"},
            ],
            "edges": [],
        }
        graph = update_operational_graph_v3(prior, {})
        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v3")
        map_media = next(
            node for node in graph["nodes"] if node["id"] == "map-media-format"
        )
        unresolved = next(
            edge
            for edge in graph["edges"]
            if edge["source"] == "route-data-records"
        )
        self.assertEqual(map_media["status"], "OPEN")
        self.assertEqual(unresolved["status"], "HYPOTHESIS")


if __name__ == "__main__":
    unittest.main()

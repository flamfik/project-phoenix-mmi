from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.operational_model import (
    analyze_relocated_bitmap_atlas,
    build_operational_graph,
    find_bounded_equal_relocated_region,
    sparse_row_metrics,
)


GLYPH_PATTERN = bytes((0x00, 0x3C, 0x42, 0x42, 0x42, 0x3C, 0x00, 0x00))


class OperationalModelTests(unittest.TestCase):
    def test_sparse_row_classifier_separates_bitmap_morphology(self):
        glyph_data = GLYPH_PATTERN * 8
        glyph = sparse_row_metrics(glyph_data, image_size=0x10000)
        dense = sparse_row_metrics(bytes(range(64)), image_size=0x10000)
        self.assertTrue(glyph["sparse_row_bitmap_candidate"])
        self.assertEqual(glyph["aligned_runtime_pointer_count"], 0)
        self.assertEqual(glyph["flow_control_halfword_count"], 0)
        self.assertFalse(dense["sparse_row_bitmap_candidate"])

    def test_bounded_equal_region_tracks_relocated_extent(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left_data = bytearray([0x11] * 0x1000)
            right_data = bytearray([0x22] * 0x1000)
            common = bytes((index * 17) & 0xFF for index in range(0x200))
            left_data[0x300:0x500] = common
            right_data[0x500:0x700] = common
            (root / "left.bin").write_bytes(left_data)
            (root / "right.bin").write_bytes(right_data)
            result = find_bounded_equal_relocated_region(
                BinaryReader(root / "left.bin"),
                BinaryReader(root / "right.bin"),
                left_anchor=0x380,
                right_anchor=0x580,
                max_backward=0x400,
                max_forward=0x400,
            )
            self.assertEqual(result["left_offset"], 0x300)
            self.assertEqual(result["right_offset"], 0x500)
            self.assertEqual(result["length"], 0x200)
            self.assertTrue(result["byte_equal"])

    def test_atlas_and_operational_graph_keep_semantics_probable(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left_data = bytearray([0xAA] * 0x10000)
            right_data = bytearray([0x55] * 0x10000)
            atlas = GLYPH_PATTERN * (0x2000 // len(GLYPH_PATTERN))
            left_data[0x2000:0x4000] = atlas
            right_data[0x4000:0x6000] = atlas
            (root / "left.bin").write_bytes(left_data)
            (root / "right.bin").write_bytes(right_data)
            fields = [
                {"field_relative_offset": 0, "target_delta_from_block": -0x400},
                {"field_relative_offset": 4, "target_delta_from_block": 0},
                {"field_relative_offset": 8, "target_delta_from_block": 0x400},
            ]
            _, _, comparison = analyze_relocated_bitmap_atlas(
                BinaryReader(root / "left.bin"),
                BinaryReader(root / "right.bin"),
                left_block_offset=0x2800,
                right_block_offset=0x4800,
                descriptor_fields=fields,
            )
            self.assertEqual(
                comparison["structural_status"],
                "CONFIRMED_RELOCATED_SPARSE_ROW_BITMAP_REGION",
            )
            self.assertEqual(
                comparison["semantic_status"], "PROBABLE_1BPP_GLYPH_ATLAS"
            )
            self.assertFalse(comparison["semantic_confirmation"])
            graph = build_operational_graph(atlas_comparison=comparison)
            atlas_node = next(node for node in graph["nodes"] if node["id"] == "bitmap-atlas")
            navigation = next(
                node for node in graph["nodes"] if node["id"] == "navigation-runtime"
            )
            self.assertEqual(
                atlas_node["status"],
                "CONFIRMED_RELOCATED_SPARSE_ROW_BITMAP_REGION",
            )
            self.assertEqual(atlas_node["semantic_status"], "PROBABLE_1BPP_GLYPH_ATLAS")
            self.assertEqual(navigation["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()

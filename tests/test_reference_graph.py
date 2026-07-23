from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.reference_graph import (
    RUNTIME_BASE,
    analyze_reference_graph,
    build_public_reference_graph,
    compare_reference_graphs,
    scan_runtime_anchor,
)


def _bundle(island_offset: int) -> dict[str, object]:
    return {
        "core_bundle": {"offset": island_offset, "end": island_offset + 0x100},
        "island": {"offset": island_offset, "end": island_offset + 0x300},
        "post_cluster": {
            "pointer_runs": [
                {"island_offset": 0x100, "count": 4},
                {"island_offset": 0x180, "count": 1},
            ]
        },
    }


def _fixture(
    path: Path,
    *,
    block_offset: int,
    island_offset: int,
    descriptor_offset: int,
) -> BinaryReader:
    data = bytearray(0x6000)
    source = island_offset + 0x100
    block_start = RUNTIME_BASE + block_offset
    data[source : source + 4] = block_start.to_bytes(4, "big")
    data[source + 8 : source + 12] = block_start.to_bytes(4, "big")
    data[descriptor_offset : descriptor_offset + 4] = (
        RUNTIME_BASE + block_offset + 0x100
    ).to_bytes(4, "big")
    data[descriptor_offset + 0x0C : descriptor_offset + 0x10] = (
        RUNTIME_BASE + block_offset + 0x220
    ).to_bytes(4, "big")
    data[descriptor_offset + 0x10 : descriptor_offset + 0x14] = (
        RUNTIME_BASE + block_offset + 0x240
    ).to_bytes(4, "big")
    marker_blob = b"html http gif jpeg browser url"
    data[block_offset - 0x200 : block_offset - 0x200 + len(marker_blob)] = marker_blob
    path.write_bytes(data)
    return BinaryReader(path)


class ReferenceGraphTests(unittest.TestCase):
    def test_exact_runtime_word_can_be_linked_to_pc_relative_mov_l(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "literal.bin"
            data = bytearray(0x100)
            data[0:2] = (0xD407).to_bytes(2, "big")
            data[0x20:0x24] = (RUNTIME_BASE + 0x40).to_bytes(4, "big")
            path.write_bytes(data)
            report = scan_runtime_anchor(
                BinaryReader(path),
                {"label": "target", "file_offset": 0x40},
                boundaries={
                    "browser_core_start": 0x80,
                    "browser_core_end": 0x90,
                    "browser_island_end": 0xA0,
                },
            )
            self.assertEqual(report["exact_runtime_word_occurrence_count"], 1)
            self.assertEqual(report["pc_relative_mov_l_referrer_count"], 1)

    def test_relocated_descriptor_graph_is_normalized_across_releases(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = analyze_reference_graph(
                _fixture(
                    root / "left.bin",
                    block_offset=0x1000,
                    island_offset=0x3000,
                    descriptor_offset=0x800,
                ),
                _bundle(0x3000),
                record_block_offset=0x1000,
                record_block_length=0x100,
            )
            right = analyze_reference_graph(
                _fixture(
                    root / "right.bin",
                    block_offset=0x1400,
                    island_offset=0x3400,
                    descriptor_offset=0xC00,
                ),
                _bundle(0x3400),
                record_block_offset=0x1400,
                record_block_length=0x100,
            )
            comparison = compare_reference_graphs(left, right)
            descriptor = comparison["descriptor_graph"]
            self.assertEqual(
                descriptor["status"], "CONFIRMED_RELOCATED_DESCRIPTOR_GRAPH"
            )
            self.assertTrue(descriptor["relocates_with_record_block"])
            self.assertGreaterEqual(descriptor["common_normalized_field_count"], 3)

    def test_contextual_owner_evidence_never_claims_confirmed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = analyze_reference_graph(
                _fixture(
                    root / "left.bin",
                    block_offset=0x1000,
                    island_offset=0x3000,
                    descriptor_offset=0x800,
                ),
                _bundle(0x3000),
                record_block_offset=0x1000,
                record_block_length=0x100,
            )
            right = analyze_reference_graph(
                _fixture(
                    root / "right.bin",
                    block_offset=0x1400,
                    island_offset=0x3400,
                    descriptor_offset=0xC00,
                ),
                _bundle(0x3400),
                record_block_offset=0x1400,
                record_block_length=0x100,
            )
            comparison = compare_reference_graphs(left, right)
            owner = comparison["owner_evidence"]
            self.assertEqual(owner["status"], "PROBABLE_BROWSER_SUPPORT_REGION")
            self.assertFalse(owner["confirmed"])
            self.assertFalse(owner["signals"]["direct_code_referrer_identifies_owner"])

            public = build_public_reference_graph(left)
            self.assertNotIn("_internal_occurrences", public["browser_marker_profile"])
            self.assertTrue(
                all(
                    "_internal_normalized_fields" not in candidate
                    for candidate in public["descriptor_candidates"]
                )
            )
            serialized = json.dumps(public)
            self.assertNotIn("_internal_occurrences", serialized)
            self.assertNotIn("_internal_normalized_fields", serialized)
            self.assertFalse(public["publication_safety"]["raw_strings_included"])


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.runtime_map import (
    analyze_runtime_map,
    build_public_runtime_map,
    compare_runtime_maps,
    find_link_base_evidence,
)


BASE = 0x0C000000


def _write_fixture(path: Path, *, record_offset: int) -> BinaryReader:
    data = bytearray(0x1000)
    data[0:2] = (0xD407).to_bytes(2, "big")
    data[2:4] = (0xD808).to_bytes(2, "big")
    data[4:6] = (0x480B).to_bytes(2, "big")
    data[6:8] = (0x0009).to_bytes(2, "big")
    data[0x20:0x24] = BASE.to_bytes(4, "big")
    data[0x24:0x28] = (BASE + 0x40).to_bytes(4, "big")
    records = bytes(range(48))
    data[record_offset : record_offset + len(records)] = records
    path.write_bytes(data)
    return BinaryReader(path)


def _bundle(record_offset: int) -> dict[str, object]:
    return {
        "island": {"offset": 0x800, "end": 0x900},
        "core_bundle": {"offset": 0x800, "end": 0x850},
        "_internal_pointer_runs": [
            {
                "offset": 0,
                "end": 12,
                "values": [
                    BASE + record_offset,
                    BASE + record_offset + 0x10,
                    BASE + record_offset + 0x20,
                ],
            },
            {"offset": 16, "end": 20, "values": [BASE]},
        ],
    }


class RuntimeMapTests(unittest.TestCase):
    def test_link_base_requires_coherent_load_and_call_sequence(self):
        with TemporaryDirectory() as temporary:
            reader = _write_fixture(Path(temporary) / "image.bin", record_offset=0x100)
            evidence = find_link_base_evidence(reader, search_end=0x100)
            self.assertEqual(evidence["base_literal_load_count"], 1)
            self.assertEqual(evidence["coherent_indirect_call_sequence_count"], 1)
            sequence = evidence["coherent_indirect_call_sequences"][0]
            self.assertEqual(sequence["target_file_offset"], 0x40)
            self.assertEqual(sequence["call_register"], 8)

    def test_selected_model_is_explicit_and_public_report_is_safe(self):
        with TemporaryDirectory() as temporary:
            reader = _write_fixture(Path(temporary) / "image.bin", record_offset=0x100)
            report = analyze_runtime_map(reader, _bundle(0x100), filler_runs=[])
            self.assertEqual(
                report["selected_model"]["status"], "CONFIRMED_BOUNDED_STATIC_MODEL"
            )
            selected = next(
                item
                for item in report["address_model_evaluations"]
                if item["model"]["name"] == "runtime-link-base"
            )
            self.assertEqual(selected["in_image_count"], 4)
            self.assertTrue(selected["maps_model_base_value_to_entry"])
            public = build_public_runtime_map(report)
            self.assertNotIn("_internal_pointer_runs", public)
            serialized = json.dumps(public)
            self.assertNotIn("firmware-bytes", serialized)
            self.assertFalse(
                public["publication_safety"]["raw_pointer_run_values_included"]
            )

    def test_cross_version_relocated_record_block(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left_reader = _write_fixture(root / "left.bin", record_offset=0x100)
            right_reader = _write_fixture(root / "right.bin", record_offset=0x200)
            left = analyze_runtime_map(left_reader, _bundle(0x100), filler_runs=[])
            right = analyze_runtime_map(right_reader, _bundle(0x200), filler_runs=[])
            left["artifact"]["label"] = "left"
            right["artifact"]["label"] = "right"
            comparison = compare_runtime_maps(left_reader, right_reader, left, right)
            self.assertEqual(comparison["selected_model"]["both_in_image_count"], 4)
            self.assertEqual(len(comparison["relocated_record_blocks"]), 1)
            block = comparison["relocated_record_blocks"][0]
            self.assertEqual(block["unique_record_count"], 3)
            self.assertEqual(block["record_stride"], 16)
            self.assertTrue(block["blocks_equal"])


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.layout import analyze_resource_references, analyze_vxworks_layout


class LayoutTests(unittest.TestCase):
    def test_resource_cluster_filler_correlation_and_direct_reference(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "layout.bin"
            data = bytearray(0x200)
            data[0x20:0x24] = (0x100).to_bytes(4, "big")
            data[0x100:0x104] = b"GIF8"
            path.write_bytes(data)
            result = analyze_resource_references(
                BinaryReader(path),
                [{"offset": 0x100, "length": 4}],
                [
                    {"offset": 0x80, "end": 0xC0, "length": 0x40, "value": "0x00"},
                    {"offset": 0x140, "end": 0x180, "length": 0x40, "value": "0x00"},
                ],
                flash_base=0x60000,
            )
            self.assertEqual(result["gap_after_preceding_filler"], 0x40)
            self.assertEqual(result["gap_before_following_filler"], 0x3C)
            self.assertEqual(result["direct_reference_candidate_count"], 1)

    def test_vxworks_table_probe_does_not_overclaim(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "vx.bin"
            path.write_bytes(b"VxWorks\x00taskSpawn\x00" + b"\x00" * 64)
            result = analyze_vxworks_layout(BinaryReader(path), flash_base=0x60000)
            self.assertEqual(result["runtime_markers"]["VxWorks"]["count"], 1)
            self.assertIn("taskSpawn", result["symbol_probes_present"])
            self.assertEqual(result["symbol_or_module_table_status"], "NOT_CONFIRMED")


if __name__ == "__main__":
    unittest.main()

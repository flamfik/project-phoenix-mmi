from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.analysis import AnalysisConfig, analyze_file, compare_reports
from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.checksum import (
    CandidateRegion,
    ChecksumExpectation,
    crc32_bytes,
    detect_sequential_crc32_layouts,
    map_crc32_expectations,
    parse_metainfo_checksums,
)
from phoenix_mmi.entropy import entropy_profile, shannon_entropy
from phoenix_mmi.fingerprint import scan_fingerprints
from phoenix_mmi.segments import build_candidate_segments, find_filler_runs
from phoenix_mmi.strings import extract_strings, summarize_strings
from phoenix_mmi.report import build_public_summary


def superh_elf_header() -> bytes:
    header = bytearray(52)
    header[:6] = b"\x7fELF\x01\x02"
    header[18:20] = (42).to_bytes(2, "big")
    return bytes(header)


class AnalysisTests(unittest.TestCase):
    def test_fingerprint_entropy_segments_and_safe_strings(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.bin"
            path.write_bytes(
                b"\x00" * 65536
                + superh_elf_header()
                + b"QNX VxWorks Wind River MOST EEPROM NAV /etc/config\x00"
                + bytes(range(256)) * 256
                + b"-rom1fs-"
            )
            reader = BinaryReader(path)
            hits = scan_fingerprints(reader)
            elf = next(hit for hit in hits if hit.name == "ELF")
            self.assertEqual(elf.details["machine"], 42)
            self.assertEqual(elf.details["machine_name"], "Renesas SuperH")
            self.assertTrue(elf.details["validated"])
            self.assertTrue(any(hit.name == "ROMFS" for hit in hits))

            windows = entropy_profile(reader, window_size=65536, step=65536)
            self.assertLess(windows[0].entropy, 0.01)
            self.assertGreater(windows[1].entropy, 7.0)
            segments = build_candidate_segments(reader.size, hits, windows, entropy_delta=1.0)
            self.assertGreaterEqual(len(segments), 2)
            filler_runs = find_filler_runs(reader)
            self.assertEqual(filler_runs[0].value, "0x00")
            self.assertEqual(filler_runs[0].length, 65536)

            summary = summarize_strings(extract_strings(reader))
            self.assertIn("QNX", summary["technical_markers"])
            self.assertIn("VxWorks", summary["technical_markers"])
            self.assertIn("EEPROM", summary["technical_markers"])
            self.assertFalse(summary["raw_strings_included"])

    def test_checksum_metadata_and_region_mapping(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"header" + b"A" * 64 + b"B" * 64
            image = root / "MMI.BIN"
            image.write_bytes(payload)
            expected = crc32_bytes(payload[6:70])
            metainfo = root / "METAINFO.TXT"
            metainfo.write_text(
                "[MMI Hi\\MMI\\42\\default\\Application]\n"
                'FileName = "MMI.BIN"\n'
                f'CheckSum1 = "{expected:08x}"\n'
                'CheckSum24 = "1234567"\n'
                'FlashStartAddress = "393216"\n',
                encoding="latin1",
            )

            metadata = parse_metainfo_checksums(metainfo, "MMI.BIN")
            self.assertEqual([item.index for item in metadata.expectations], [1, 24])
            self.assertEqual(metadata.flash_start_address, 393216)
            by_section = parse_metainfo_checksums(
                metainfo,
                section_name=r"MMI Hi\MMI\42\default\Application",
            )
            self.assertEqual(by_section.filename, "MMI.BIN")
            matches = map_crc32_expectations(
                BinaryReader(image),
                metadata.expectations,
                [CandidateRegion(6, 70, "test-region")],
            )
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].index, 1)

    def test_end_to_end_report_and_comparison_exclude_raw_strings(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left_path = root / "left.bin"
            right_path = root / "right.bin"
            left_path.write_bytes(b"\x00" * 128 + b"QNX PRIVATE_DIAGNOSTIC_TEXT")
            right_path.write_bytes(b"\x00" * 128 + b"MMI MOST PRIVATE_DIAGNOSTIC_TEXT")
            config = AnalysisConfig(entropy_window=64, entropy_step=64)
            left = analyze_file(left_path, config=config)
            right = analyze_file(right_path, config=config)

            self.assertFalse(left["publication_safety"]["raw_strings_included"])
            self.assertNotIn("PRIVATE_DIAGNOSTIC_TEXT", str(left))
            public = build_public_summary(left)
            self.assertNotIn("PRIVATE_DIAGNOSTIC_TEXT", str(public))
            self.assertNotIn("header_preview_hex", str(left))
            self.assertNotIn("header_preview_hex", str(public))
            self.assertFalse(public["strings"]["raw_strings_included"])
            comparison = compare_reports(left, right)
            self.assertFalse(comparison["same_sha256"])
            self.assertIn("MMI", comparison["technical_markers_added"])

    def test_entropy_known_extremes(self):
        self.assertEqual(shannon_entropy(b"\x00" * 1024), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 4), 8.0, places=6)

    def test_complete_sequential_checksum_layout(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "chunks.bin"
            data = b"A" * 16 + b"B" * 16 + b"tail"
            path.write_bytes(data)
            expectations = tuple(
                ChecksumExpectation(index, crc32_bytes(data[index * 16 : (index + 1) * 16]), f"CheckSum{index}")
                for index in range(3)
            )
            layouts = detect_sequential_crc32_layouts(
                BinaryReader(path), expectations, block_sizes=(8, 16, 32)
            )
            self.assertEqual(len(layouts), 1)
            self.assertEqual(layouts[0]["block_size"], 16)
            self.assertEqual(layouts[0]["tail_length"], 4)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.parser_search import (
    build_public_global_parser_report,
    compare_global_fldb_parser_search,
    scan_global_fldb_parser_candidates,
)


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _write_fixture(path: Path, *, shift: int) -> None:
    image = bytearray(0x1000)

    # Write-only 36-byte fixed-record initializer.
    start = 0x100 + shift
    for index, word in enumerate((0x2022, 0x1011, 0x1065, 0x1076, 0x1047, 0x1038, 0x7101, 0x3153)):
        _put_word(image, start + index * 2, word)
    branch = start + 16
    displacement = ((start - (branch + 4)) // 2) & 0xFF
    _put_word(image, branch, 0x8F00 | displacement)
    _put_word(image, branch + 2, 0x7024)

    # Read-side loop with one-base header offsets and explicit endian work.
    start = 0x200 + shift
    for index in range(6):
        _put_word(image, start + index * 2, 0x5000 | (index << 8) | (4 << 4) | index)
    _put_word(image, start + 12, 0x6108)  # swap.b r0,r1
    _put_word(image, start + 14, 0x6019)  # swap.w r1,r0
    branch = start + 16
    displacement = ((start - (branch + 4)) // 2) & 0xFF
    _put_word(image, branch, 0x8F00 | displacement)
    _put_word(image, branch + 2, 0x7424)

    # Navigation-adjacent false positive: 36 is a call-field offset, while
    # the backward loop's actual delay-slot step is 40.
    start = 0x400 + shift
    _put_word(image, start, 0x400B)
    _put_word(image, start + 2, 0x7424)
    _put_word(image, start + 4, 0x400B)
    _put_word(image, start + 6, 0x7524)
    displacement = ((start - (start + 8 + 4)) // 2) & 0xFF
    _put_word(image, start + 8, 0x8F00 | displacement)
    _put_word(image, start + 10, 0x7928)

    path.write_bytes(image)


def _contract(shift: int) -> dict[str, object]:
    return {
        "callsite_window_pairs": [
            {
                "left_center": 0x400,
                "right_center": 0x400 + shift,
                "resolved_call_pairs": [],
            }
        ],
        "neighborhood_pairs": [],
    }


class ParserSearchTests(unittest.TestCase):
    def test_role_sensitive_loop_classification(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.bin"
            _write_fixture(path, shift=0)
            report = scan_global_fldb_parser_candidates(
                BinaryReader(path), _contract(0), side="left"
            )

        candidates = report["record_stride_loop_candidates"]
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            candidates[0]["classification"],
            "PROBABLE_FIXED_RECORD_ARRAY_INITIALIZER",
        )
        self.assertEqual(candidates[0]["stepped_register_load_count"], 0)
        self.assertGreaterEqual(candidates[0]["stepped_register_store_count"], 6)
        self.assertEqual(
            candidates[1]["classification"], "REQUIRES_TARGETED_BUFFER_DATAFLOW"
        )
        self.assertEqual(candidates[1]["header_access"]["best_header_read_offsets"], [0, 4, 8, 12, 16, 20])
        self.assertEqual(candidates[1]["endian_instruction_count"], 2)
        self.assertEqual(report["classification"]["parser_status"], "NOT_IDENTIFIED_UNDER_MULTI_SIGNAL_GATE")

    def test_cross_version_pairing_and_false_positive_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left_path = root / "left.bin"
            right_path = root / "right.bin"
            _write_fixture(left_path, shift=0)
            _write_fixture(right_path, shift=0x100)
            contract = _contract(0x100)
            left = scan_global_fldb_parser_candidates(
                BinaryReader(left_path), contract, side="left"
            )
            right = scan_global_fldb_parser_candidates(
                BinaryReader(right_path), contract, side="right"
            )
            comparison = compare_global_fldb_parser_search(left, right)

        self.assertEqual(
            comparison["classification"]["cross_version_record_stride_loop_pair_count"],
            2,
        )
        self.assertEqual(
            comparison["classification"]["cross_version_write_only_initializer_pair_count"],
            1,
        )
        self.assertGreaterEqual(
            comparison["classification"]["cross_version_rejected_navigation_numeric_pair_count"],
            1,
        )
        self.assertEqual(
            comparison["classification"]["promoted_fldb_parser_pair_count"], 0
        )
        self.assertEqual(comparison["classification"]["actual_fldb_parser"], "OPEN")

    def test_public_report_contains_no_bytes_paths_or_strings(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private-name.bin"
            _write_fixture(path, shift=0)
            report = scan_global_fldb_parser_candidates(
                BinaryReader(path), _contract(0), side="left"
            )
            public = build_public_global_parser_report(report)

        serialized = json.dumps(public)
        self.assertNotIn("private-name", serialized)
        self.assertNotIn("instruction_bytes", serialized.lower().replace('"instruction_bytes_included": false', ""))
        self.assertFalse(public["publication_safety"]["firmware_bytes_included"])
        self.assertFalse(public["publication_safety"]["local_paths_included"])


if __name__ == "__main__":
    unittest.main()

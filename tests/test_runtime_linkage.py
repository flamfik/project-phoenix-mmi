from __future__ import annotations

import unittest
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_storage import RUNTIME_BASE
from phoenix_mmi.runtime_linkage import (
    _find_normalized_run_pair,
    _pointer_zero_runs,
    _scan_bounded_gbr_writers,
    _scan_coherent_copy_tables,
    _scan_helper_mediated_destinations,
    analyze_runtime_linkage_family,
    correlate_runtime_linkage_family,
)


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _put_long(image: bytearray, offset: int, value: int) -> None:
    image[offset : offset + 4] = value.to_bytes(4, "big")


def _mov_l_pc_word(instruction: int, literal: int, register: int) -> int:
    base = (instruction & ~3) + 4
    displacement = literal - base
    if displacement < 0 or displacement % 4 or displacement // 4 > 0xFF:
        raise ValueError("literal outside MOV.L PC-relative range")
    return 0xD000 | (register << 8) | (displacement // 4)


def _write_run(image: bytearray, start: int, first_pointer: int) -> None:
    for ordinal in range(5):
        _put_long(
            image,
            start + ordinal * 16,
            RUNTIME_BASE + first_pointer - ordinal * 576,
        )


def _write_literal_call(
    image: bytearray,
    *,
    load: int,
    literal: int,
    target: int,
    register: int = 2,
) -> None:
    _put_word(image, load, _mov_l_pc_word(load, literal, register))
    _put_word(image, load + 2, 0x400B | (register << 8))
    _put_word(image, load + 4, 0x0009)
    _put_long(image, literal, RUNTIME_BASE + target)


class RuntimeLinkageTests(unittest.TestCase):
    def test_normalized_run_pair_requires_equal_pointer_geometry(self):
        left = bytearray(0x3000)
        right = bytearray(0x3000)
        _write_run(left, 0x1000, 0x1E24)
        _write_run(right, 0x1100, 0x1F24)

        left_run = next(
            row
            for row in _pointer_zero_runs(bytes(left))
            if row["run_start_file_offset"] == 0x1000
        )
        right_runs = _pointer_zero_runs(bytes(right))
        pair = _find_normalized_run_pair(left_run, right_runs)

        self.assertTrue(pair["unique_pair_found"])
        self.assertEqual(pair["run_start_translation_delta"], 0x100)
        self.assertTrue(pair["all_pointer_translations_equal_run_translation"])
        self.assertFalse(pair["runtime_semantics_asserted"])

    def test_gbr_scan_finds_resolved_displaced_store(self):
        image = bytearray(0x2000)
        run_start = 0x1000
        load = 0x100
        literal = 0x180
        _put_word(image, load, _mov_l_pc_word(load, literal, 1))
        _put_word(image, load + 2, 0x411E)  # ldc r1,gbr
        _put_word(image, load + 4, 0xC201)  # mov.l r0,@(4,gbr)
        _put_long(image, literal, RUNTIME_BASE + run_start)

        report = _scan_bounded_gbr_writers(
            bytes(image), run_start=run_start, run_end=run_start + 0x50
        )

        self.assertEqual(report["candidate_store_count"], 1)
        self.assertEqual(
            report["candidates"][0]["destination_file_offset"], run_start + 4
        )
        self.assertFalse(report["memory_loaded_gbr_base_modeled"])

    def test_helper_scan_requires_run_address_in_argument_register(self):
        image = bytearray(0x2000)
        run_start = 0x1000
        load = 0x100
        literal = 0x180
        _put_word(image, load, _mov_l_pc_word(load, literal, 1))
        _put_word(image, load + 2, 0x6413)  # mov r1,r4
        _put_word(image, load + 4, 0x420B)  # jsr @r2
        _put_long(image, literal, RUNTIME_BASE + run_start)

        report = _scan_helper_mediated_destinations(
            bytes(image), run_start=run_start, run_end=run_start + 0x50
        )

        self.assertEqual(report["helper_mediated_candidate_count"], 1)
        self.assertEqual(report["candidates"][0]["argument_register"], 4)
        self.assertFalse(report["helper_identity_resolved"])

    def test_copy_table_requires_one_address_model_pair_across_records(self):
        coherent = bytearray(0x3000)
        table = 0x300
        for ordinal in range(2):
            offset = table + ordinal * 12
            _put_long(coherent, offset, RUNTIME_BASE + 0x800 + ordinal * 0x40)
            _put_long(
                coherent, offset + 4, RUNTIME_BASE + 0x1000 + ordinal * 0x40
            )
            _put_long(coherent, offset + 8, 0x40)
        _put_word(coherent, 0x100, _mov_l_pc_word(0x100, 0x180, 1))
        _put_long(coherent, 0x180, RUNTIME_BASE + table)

        accepted = _scan_coherent_copy_tables(
            bytes(coherent), run_start=0x1000, run_end=0x1050
        )

        self.assertEqual(
            accepted["referenced_covering_coherent_table_count"], 1
        )

        mixed = bytearray(coherent)
        _put_long(mixed, table + 12, 0x840)
        _put_long(mixed, table + 16, 0x1040)
        rejected = _scan_coherent_copy_tables(
            bytes(mixed), run_start=0x1000, run_end=0x1050
        )

        self.assertEqual(
            rejected["referenced_covering_coherent_table_count"], 0
        )

    def test_analysis_and_correlation_preserve_runtime_gaps(self):
        left = bytearray(0x4000)
        right = bytearray(0x4000)
        _write_run(left, 0x2000, 0x2E24)
        _write_run(right, 0x2100, 0x2F24)
        _write_literal_call(
            left, load=0x100, literal=0x180, target=0x2000 + 4
        )
        _write_literal_call(
            right, load=0x100, literal=0x180, target=0x2100 + 4
        )
        with tempfile.TemporaryDirectory(prefix="phoenix-runtime-linkage-test-") as root:
            left_path = Path(root) / "left.bin"
            right_path = Path(root) / "right.bin"
            left_path.write_bytes(left)
            right_path.write_bytes(right)
            comparison = analyze_runtime_linkage_family(
                BinaryReader(left_path),
                BinaryReader(right_path),
                {"record_run": {"run_start_file_offset": 0x2000}},
            )

        self.assertEqual(
            comparison["classification"]["cross_version_record_run"],
            "CONFIRMED_UNIQUE_NORMALIZED_BILATERAL_RUN",
        )
        self.assertEqual(
            comparison["classification"]["specific_writer_or_loader_chain"],
            "OPEN",
        )

        prior = {
            "media": {"container": "FLDB"},
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v12",
                "nodes": [],
                "edges": [],
            },
        }
        correlation = correlate_runtime_linkage_family(prior, comparison)
        self.assertEqual(
            correlation["operational_graph"]["schema"],
            "phoenix-mmi.operational-graph/v13",
        )
        self.assertEqual(correlation["correlation"]["sector_read_abi"], "OPEN")
        self.assertEqual(
            correlation["correlation"]["dynamic_compatibility"],
            "NOT_ESTABLISHED",
        )


if __name__ == "__main__":
    unittest.main()

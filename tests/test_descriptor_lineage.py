from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.descriptor_lineage import (
    _find_field12_accessors,
    _initializer_census,
    _static_descriptor_census,
    correlate_descriptor_lineage,
    trace_dispatch_producer,
)
from phoenix_mmi.navigation_storage import RUNTIME_BASE


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _mov_l_pc_word(instruction: int, literal: int, register: int) -> int:
    base = (instruction & ~3) + 4
    displacement = literal - base
    if displacement < 0 or displacement % 4 or displacement // 4 > 0xFF:
        raise ValueError("literal outside MOV.L PC-relative range")
    return 0xD000 | (register << 8) | (displacement // 4)


def _write_field12_accessor(image: bytearray, offset: int) -> None:
    words = [0x2008, 0x8D01, 0xE000, 0x5043, 0x7E04, 0x6FE3, 0x000B, 0x6EF6]
    for index, word in enumerate(words):
        _put_word(image, offset + index * 2, word)


class DescriptorLineageTests(unittest.TestCase):
    def test_nearest_producer_literal_and_argument_contract_are_traced(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "producer.bin"
            image = bytearray(0x800)
            entry = 0x100
            literal = 0x180
            producer_target = 0x300
            words = [
                0x4F22,  # sts.l pr,@-r15
                _mov_l_pc_word(entry + 2, literal, 11),
                0xE500,  # mov #0,r5
                0x4B0B,  # jsr @r11
                0x6443,  # mov r4,r4
                0x6402,  # mov.l @r0,r4
                0x6242,  # mov.l @r4,r2
                0x5123,  # mov.l @(12,r2),r1
                0x410B,  # jsr @r1
                0xE503,  # mov #3,r5
                0x4F26,
                0x000B,
                0x0009,
            ]
            for index, word in enumerate(words):
                _put_word(image, entry + index * 2, word)
            image[literal : literal + 4] = (
                RUNTIME_BASE + producer_target
            ).to_bytes(4, "big")
            _put_word(image, producer_target, 0x4F22)
            _put_word(image, producer_target + 2, 0x0009)
            _put_word(image, producer_target + 4, 0x0009)
            _put_word(image, producer_target + 6, 0x000B)
            _put_word(image, producer_target + 8, 0x0009)
            path.write_bytes(image)

            row = trace_dispatch_producer(
                BinaryReader(path),
                {
                    "call_site_offset": entry + 16,
                    "relative_call_offset": 16,
                },
            )

        self.assertEqual(row["producer_call_site_offset"], entry + 6)
        self.assertEqual(row["producer_target_file_offset"], producer_target)
        self.assertEqual(row["producer_target_path"], "IN_IMAGE_POINTER")
        self.assertEqual(row["arguments"]["r5"]["constant"], 0)
        self.assertFalse(row["function_boundary_asserted"])

    def test_accessor_cluster_and_static_descriptor_census_are_structural(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "descriptors.bin"
            image = bytearray(0x1000)
            _write_field12_accessor(image, 0x300)
            _write_field12_accessor(image, 0x340)
            base = 0x200
            image[base + 8 : base + 10] = (8).to_bytes(2, "big", signed=True)
            image[base + 12 : base + 16] = (RUNTIME_BASE + 0x300).to_bytes(4, "big")
            image[0x100:0x104] = (RUNTIME_BASE + base).to_bytes(4, "big")
            path.write_bytes(image)
            reader = BinaryReader(path)
            data = reader.read(0, reader.size)
            clusters = _find_field12_accessors(reader, data)
            census, _ = _static_descriptor_census(reader, data, {0x300})

        self.assertEqual(sum(row["occurrence_count"] for row in clusters), 2)
        self.assertEqual(clusters[0]["relative_gap_vector"], [0x40])
        self.assertGreaterEqual(census["raw_candidate_count"], 1)
        self.assertEqual(census["candidate_targeting_accepted_optical_node_count"], 1)
        self.assertEqual(
            census["candidate_base_referenced_as_aligned_runtime_word_count"], 1
        )
        self.assertFalse(census["descriptor_identity_asserted"])

    def test_mixed_width_initializer_requires_executable_context_gate(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "initializer.bin"
            image = bytearray(0x800)
            entry = 0x100
            literal = 0x180
            words = [
                0x4F22,  # sts.l pr,@-r15
                0xE008,  # mov #8,r0
                0x8441,  # mov.w r0,@(8,r4)
                _mov_l_pc_word(entry + 6, literal, 2),
                0x1423,  # mov.l r2,@(12,r4)
                0x4F26,
                0x000B,
                0x0009,
            ]
            for index, word in enumerate(words):
                _put_word(image, entry + index * 2, word)
            image[literal : literal + 4] = (RUNTIME_BASE + 0x300).to_bytes(4, "big")
            path.write_bytes(image)
            reader = BinaryReader(path)
            census, signatures = _initializer_census(
                reader, reader.read(0, reader.size)
            )

        self.assertEqual(census["same_base_within_0x100_raw_pair_count"], 1)
        self.assertEqual(census["analyzable_pair_count"], 1)
        self.assertEqual(census["bounded_code_gate_pair_count"], 1)
        self.assertEqual(sum(signatures.values()), 1)

    def test_correlation_keeps_parser_sector_and_owner_open(self):
        prior = {
            "media": {"container": "FLDB"},
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v9",
                "nodes": [],
                "edges": [],
            },
        }
        comparison = {
            "analysis_mode": "read-only-static-bounded-producer-and-field-lineage",
            "classification": {
                "producer_call_pair_count": 2,
                "cross_version_producer_target_promoted_count": 0,
            },
            "interpretation": "bounded",
            "publication_safety": {"firmware_bytes_included": False},
        }
        report = correlate_descriptor_lineage(prior, comparison)
        self.assertEqual(report["correlation"]["actual_fldb_parser"], "OPEN")
        self.assertEqual(report["correlation"]["sector_read_abi"], "OPEN")
        self.assertEqual(report["correlation"]["optical_buffer_owner"], "OPEN")


if __name__ == "__main__":
    unittest.main()

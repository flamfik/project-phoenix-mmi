from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.parser_dataflow import (
    analyze_fldb_candidate_dataflow,
    build_public_fldb_candidate_report,
    compare_fldb_candidate_dataflow,
    correlate_corrected_parser_model,
    update_operational_graph_v6,
)


def _pc_mov_l(offset: int, literal: int, register: int) -> bytes:
    displacement = (literal - ((offset & ~3) + 4)) // 4
    if not 0 <= displacement <= 0xFF:
        raise ValueError("literal is outside SH MOV.L displacement range")
    return (0xD000 | register << 8 | displacement).to_bytes(2, "big")


def _probe_fixture(path: Path, base: int) -> dict[str, object]:
    data = bytearray(base + 0x80)
    words = {
        0x00: 0x2F86,
        0x02: 0x2F96,
        0x04: 0x4F22,
        0x06: 0x7FFC,
        0x08: 0x6EF3,
        0x0E: 0x6893,
        0x10: 0x781A,
        0x14: 0x4A0B,
        0x16: 0x6583,
        0x18: 0x2008,
        0x1C: 0x4A0B,
        0x1E: 0x6583,
        0x20: 0x2008,
        0x24: 0x4A0B,
        0x26: 0x6583,
        0x28: 0x2008,
        0x2C: 0x4A0B,
        0x2E: 0x6583,
        0x30: 0x2008,
    }
    for relative, word in words.items():
        data[base + relative : base + relative + 2] = word.to_bytes(2, "big")
    literals = {
        base + 0x40: 0x90000000,
        base + 0x44: 0x00000244,
        base + 0x48: 0x00000220,
        base + 0x4C: 0x00000204,
    }
    for offset, value in literals.items():
        data[offset : offset + 4] = value.to_bytes(4, "big")
    for relative, literal, register in (
        (0x0A, base + 0x40, 9),
        (0x0C, base + 0x44, 10),
        (0x12, base + 0x48, 4),
        (0x1A, base + 0x4C, 4),
        (0x22, base + 0x48, 4),
        (0x2A, base + 0x4C, 4),
    ):
        offset = base + relative
        data[offset : offset + 2] = _pc_mov_l(offset, literal, register)
    path.write_bytes(data)
    return {
        "constants": [
            {
                "constant_id": "fldb-directory-offset",
                "mov_l_references": [
                    {"load_offset": base + 0x12},
                    {"load_offset": base + 0x22},
                ],
            }
        ]
    }


class ParserDataflowTests(unittest.TestCase):
    def test_expected_value_and_pointer_roles_disprove_offset_use(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.bin"
            constants = _probe_fixture(path, 0x100)
            report = analyze_fldb_candidate_dataflow(
                BinaryReader(path), constants
            )
            self.assertGreater(report["bounded_block"]["known_ratio"], 0.7)
            self.assertEqual(
                report["classification"]["former_0x220_fldb_interpretation"],
                "DISPROVED_FOR_SESSION012_REFERENCE_PAIR",
            )
            self.assertTrue(
                report["fldb_counterevidence"][
                    "directory_offset_used_as_expected_argument"
                ]
            )
            self.assertEqual(
                report["fldb_counterevidence"][
                    "alternative_expected_values_at_same_pointer"
                ],
                [0x204],
            )
            self.assertFalse(
                report["fldb_counterevidence"][
                    "directory_offset_used_as_additive_offset"
                ]
            )

    def test_relocated_probe_blocks_pair_by_bytes_and_call_topology(self):
        with TemporaryDirectory() as temporary:
            left_path = Path(temporary) / "left.bin"
            right_path = Path(temporary) / "right.bin"
            left_constants = _probe_fixture(left_path, 0x100)
            right_constants = _probe_fixture(right_path, 0x300)
            left = analyze_fldb_candidate_dataflow(
                BinaryReader(left_path), left_constants
            )
            right = analyze_fldb_candidate_dataflow(
                BinaryReader(right_path), right_constants
            )
            comparison = compare_fldb_candidate_dataflow(left, right)
            self.assertEqual(comparison["bounded_block"]["relocation_delta"], 0x200)
            self.assertTrue(comparison["bounded_block"]["raw_bytes_identical_by_hash"])
            self.assertTrue(comparison["bounded_block"]["call_topology_equal"])

    def test_graph_v6_marks_old_edge_disproved_and_parser_open(self):
        prior = {
            "nodes": [
                {"id": "startup-runtime", "status": "CONFIRMED"},
                {
                    "id": "fldb-directory-offset-candidate",
                    "status": "PROBABLE_STATIC_CONSTANT_COUPLING",
                },
                {"id": "fldb-container-set", "status": "CONFIRMED"},
                {"id": "navigation-runtime", "status": "CONFIRMED"},
            ],
            "edges": [
                {
                    "source": "fldb-directory-offset-candidate",
                    "target": "fldb-container-set",
                    "status": "PROBABLE_NUMERIC_COUPLING",
                },
                {
                    "source": "fldb-container-set",
                    "target": "navigation-runtime",
                    "status": "HYPOTHESIS",
                },
            ],
        }
        graph = update_operational_graph_v6(prior, {})
        former_edge = next(
            edge
            for edge in graph["edges"]
            if edge["source"] == "fldb-directory-offset-candidate"
            and edge["target"] == "fldb-container-set"
        )
        parser = next(
            node for node in graph["nodes"] if node["id"] == "fldb-parser-routine"
        )
        self.assertEqual(former_edge["status"], "DISPROVED")
        self.assertEqual(parser["status"], "OPEN")
        self.assertEqual(graph["disproved_edge_count"], 1)

    def test_public_report_and_correlation_preserve_safety_and_open_abi(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.bin"
            constants = _probe_fixture(path, 0x100)
            report = analyze_fldb_candidate_dataflow(
                BinaryReader(path), constants
            )
            public = build_public_fldb_candidate_report(report)
            comparison = compare_fldb_candidate_dataflow(report, report)
            prior = {
                "media": {"partition_model": "CONFIRMED"},
                "operational_graph": {
                    "nodes": [
                        {"id": "startup-runtime", "status": "CONFIRMED"},
                        {
                            "id": "fldb-directory-offset-candidate",
                            "status": "PROBABLE",
                        },
                        {"id": "fldb-container-set", "status": "CONFIRMED"},
                        {"id": "navigation-runtime", "status": "CONFIRMED"},
                    ],
                    "edges": [
                        {
                            "source": "fldb-directory-offset-candidate",
                            "target": "fldb-container-set",
                            "status": "PROBABLE",
                        },
                        {
                            "source": "fldb-container-set",
                            "target": "navigation-runtime",
                            "status": "HYPOTHESIS",
                        },
                    ],
                },
            }
            correlation = correlate_corrected_parser_model(prior, comparison)
            self.assertFalse(public["publication_safety"]["firmware_bytes_included"])
            self.assertNotIn("a0020000", repr(public).lower())
            self.assertEqual(correlation["correction"]["sector_read_abi"], "OPEN")
            self.assertEqual(
                correlation["correction"]["dynamic_compatibility"],
                "NOT_ESTABLISHED",
            )


if __name__ == "__main__":
    unittest.main()

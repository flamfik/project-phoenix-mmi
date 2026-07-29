from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.evidence_cycle import build_session060_evidence_map
from phoenix_mmi.lod_research import (
    analyze_lod_alignment,
    analyze_lod_fill_regions,
    analyze_lod_grid_reuse,
    analyze_lod_record_hypothesis,
    analyze_lod_shared_regions,
)
from phoenix_mmi.yim import decode_yim_rle
from phoenix_mmi.yim_research import (
    _catalog16,
    _catalog32,
    analyze_embedded_xim2,
    analyze_yim_field_relations,
    analyze_yim_integrity_catalog,
    build_yim_integrity_decision,
    expanded_yim_integrity_candidates,
)


def _literal_yim(
    raster: bytes,
    *,
    width: int,
    height: int,
    integrity32: int = 0x12345678,
    integrity16: int = 0x9ABC,
) -> bytes:
    units = len(raster) // 2
    if len(raster) != width * height * 2 or not units:
        raise ValueError("fixture raster geometry differs")
    encoded = (0x8000 | units).to_bytes(2, "big") + raster
    size = 60 + len(encoded)
    preamble = (
        f"{integrity32:08x}{integrity16:04x}{size:08x}{1:04x}"
    ).encode("ascii")
    return (
        preamble
        + b"XIM2"
        + (size - 24).to_bytes(4, "big")
        + width.to_bytes(2, "big")
        + height.to_bytes(2, "big")
        + (28).to_bytes(4, "big")
        + bytes(12)
        + (size - 52).to_bytes(4, "big")
        + (0x00100001).to_bytes(4, "big")
        + encoded
    )


def _yim_results():
    rows = []
    for index in range(5):
        raster = bytes(
            (value + index) & 0xFF for value in range(16)
        )
        data = _literal_yim(
            raster,
            width=4,
            height=2,
            integrity32=0x12345678 + index,
            integrity16=0x9ABC + index,
        )
        rows.append(
            (
                {
                    "source_id": f"YIM-U{index + 1:02d}",
                    "data": data,
                },
                decode_yim_rle(data),
            )
        )
    return rows


def _lod_sources():
    common_a = bytes(range(256))
    common_b = bytes(reversed(range(256)))
    rows = []
    for index in range(5):
        variable = bytes([65 + index]) * (256 + index * 3)
        data = (
            b"ABC"
            + common_a
            + common_b
            + bytes([index]) * 253
            + b"\xff" * 192
            + variable
            + b"\x00" * 4096
            + common_a
            + common_b
        )
        rows.append(
            {
                "source_id": f"LOD-U{index + 1:02d}",
                "extension": ".LOD",
                "data": data,
                "members": [],
            }
        )
    return rows


class YimResearchTests(unittest.TestCase):
    def test_crc_catalogues_match_standard_check_vectors(self):
        material = b"123456789"
        self.assertEqual(
            _catalog32(material),
            {
                "CRC32_ISO_HDLC": 0xCBF43926,
                "CRC32_JAMCRC": 0x340BC6D9,
                "CRC32_C": 0xE3069283,
                "CRC32_BZIP2": 0xFC891918,
                "CRC32_MPEG2": 0x0376E6E7,
                "CRC32_POSIX": 0x765E7680,
                "CRC32_Q": 0x3010BF7F,
            },
        )
        self.assertEqual(
            _catalog16(material),
            {
                "CRC16_ARC": 0xBB3D,
                "CRC16_MODBUS": 0x4B37,
                "CRC16_MAXIM_DOW": 0x44C2,
                "CRC16_KERMIT": 0x2189,
                "CRC16_X25": 0x906E,
                "CRC16_DNP": 0xEA82,
                "CRC16_XMODEM": 0x31C3,
                "CRC16_CCITT_FALSE": 0x29B1,
                "CRC16_AUG_CCITT": 0xE5CC,
            },
        )

    def test_expanded_catalog_is_frozen_and_omits_field_values(self):
        source, result = _yim_results()[0]
        report = expanded_yim_integrity_candidates(
            source["data"], result
        )
        self.assertEqual(report["candidate_32bit_algorithms_tested"], 7)
        self.assertEqual(report["candidate_16bit_algorithms_tested"], 9)
        self.assertTrue(report["catalog_was_frozen_before_corpus_run"])
        self.assertNotIn("integrity32", report)
        self.assertNotIn("integrity16", report)

    def test_sessions_051_and_052_are_corpus_bounded(self):
        results = _yim_results()
        catalog = analyze_yim_integrity_catalog(results)
        relations = analyze_yim_field_relations(results)
        self.assertEqual(catalog["session"], "051")
        self.assertEqual(relations["session"], "052")
        self.assertEqual(catalog["unique_source_count"], 5)
        self.assertFalse(
            catalog["publication_safety"][
                "integrity_field_values_included"
            ]
        )

    def test_embedded_xim2_validates_and_correlates_standalone(self):
        results = _yim_results()
        blob = bytes(results[0][0]["data"])[24:]
        with TemporaryDirectory() as temporary:
            readers = {}
            for disc in ("cd1", "cd3"):
                path = Path(temporary) / f"{disc}.bin"
                path.write_bytes(b"prefix" + blob + b"suffix")
                readers[disc] = BinaryReader(path)
            report = analyze_embedded_xim2(readers, results)
        self.assertEqual(
            report["classification"]["embedded_xim2"],
            "CONFIRMED_IN_CD1_AND_CD3_MAIN_IMAGES",
        )
        self.assertEqual(
            report["cross_version"]["shared_encoded_content_count"], 1
        )
        self.assertEqual(
            report["standalone_yim_correlation"][
                "cd1_encoded_match_count"
            ],
            1,
        )
        self.assertFalse(
            report["publication_safety"]["decoded_raster_bytes_included"]
        )

    def test_integrity_gate_blocks_write_model(self):
        results = _yim_results()
        session051 = analyze_yim_integrity_catalog(results)
        session052 = analyze_yim_field_relations(results)
        blob = bytes(results[0][0]["data"])[24:]
        with TemporaryDirectory() as temporary:
            readers = {}
            for disc in ("cd1", "cd3"):
                path = Path(temporary) / f"{disc}.bin"
                path.write_bytes(blob)
                readers[disc] = BinaryReader(path)
            session053 = analyze_embedded_xim2(readers, results)
        decision = build_yim_integrity_decision(
            session051, session052, session053
        )
        self.assertEqual(decision["decision"]["yim_repack"], "BLOCKED")
        self.assertFalse(
            decision["classification"]["safe_mutation_ready"]
        )


class LodResearchTests(unittest.TestCase):
    def test_alignment_and_delimiters_remain_structural(self):
        sources = _lod_sources()
        alignment = analyze_lod_alignment(sources)
        regions = analyze_lod_fill_regions(sources)
        self.assertEqual(alignment["classification"]["record_width"], "NOT_ESTABLISHED")
        self.assertEqual(regions["delimiter_sequence_count"], 1)
        self.assertEqual(
            regions["classification"]["semantic_region_roles"],
            "UNRESOLVED",
        )

    def test_grid_and_shared_region_reports_omit_content(self):
        sources = _lod_sources()
        reuse = analyze_lod_grid_reuse(sources)
        shared = analyze_lod_shared_regions(sources)
        self.assertGreater(
            shared["shared_all_unique_content_count"], 0
        )
        self.assertFalse(
            shared["publication_safety"]["payload_bytes_included"]
        )
        self.assertEqual(
            reuse["classification"]["reuse_interpretation"],
            "CONTENT_RELATION_ONLY",
        )

    def test_record_hypothesis_does_not_create_decoder(self):
        sources = _lod_sources()
        alignment = analyze_lod_alignment(sources)
        regions = analyze_lod_fill_regions(sources)
        report = analyze_lod_record_hypothesis(
            sources, alignment, regions
        )
        self.assertEqual(
            report["classification"]["three_byte_record_model"],
            "NOT_ESTABLISHED",
        )
        self.assertFalse(report["tests"]["validated_record_header_present"])


class EvidenceCycleTests(unittest.TestCase):
    def test_session060_extends_graph_without_enabling_mutation(self):
        results = _yim_results()
        session051 = analyze_yim_integrity_catalog(results)
        session052 = analyze_yim_field_relations(results)
        blob = bytes(results[0][0]["data"])[24:]
        with TemporaryDirectory() as temporary:
            readers = {}
            for disc in ("cd1", "cd3"):
                path = Path(temporary) / f"{disc}.bin"
                path.write_bytes(blob)
                readers[disc] = BinaryReader(path)
            session053 = analyze_embedded_xim2(readers, results)
        session054 = build_yim_integrity_decision(
            session051, session052, session053
        )
        lods = _lod_sources()
        session055 = analyze_lod_alignment(lods)
        session056 = analyze_lod_fill_regions(lods)
        session057 = analyze_lod_grid_reuse(lods)
        session058 = analyze_lod_record_hypothesis(
            lods, session055, session056
        )
        session059 = analyze_lod_shared_regions(lods)
        session050 = {
            "schema": "phoenix-mmi.firmware-evidence-map/v1",
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v42",
                "nodes": [],
                "edges": [],
            },
        }
        report = build_session060_evidence_map(
            session050,
            [
                session051,
                session052,
                session053,
                session054,
                session055,
                session056,
                session057,
                session058,
                session059,
            ],
        )
        self.assertEqual(report["operational_graph"]["node_count"], 10)
        self.assertEqual(report["operational_graph"]["edge_count"], 10)
        self.assertEqual(
            report["operational_graph"]["confirmed_node_count"], 4
        )
        self.assertEqual(report["operational_graph"]["open_node_count"], 2)
        self.assertEqual(
            report["operational_graph"]["bounded_negative_edge_count"], 2
        )
        self.assertFalse(
            report["classification"]["safe_mutation_ready"]
        )
        self.assertFalse(
            report["publication_safety"]["installable_artifacts_included"]
        )

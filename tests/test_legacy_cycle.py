from __future__ import annotations

import hashlib
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.legacy_cycle import (
    LegacyPayloadInput,
    analyze_legacy_corpus,
    analyze_lod_topology,
    analyze_yim_decoded_homolog,
    analyze_yim_envelopes,
    analyze_yim_integrity,
    analyze_yim_rle,
    build_firmware_evidence_map,
    legacy_member_eligible,
)
from phoenix_mmi.yim import (
    decode_yim_rle,
    parse_yim_envelope,
    public_yim_envelope,
    public_yim_rle,
    yim_integrity_candidates,
)
from tests.test_record_normalization import (
    _components,
    _fixture,
    _reader,
    _session040,
)


def _literal_yim(
    raster: bytes,
    *,
    width: int,
    height: int,
    integrity32: int = 0x12345678,
    integrity16: int = 0x9ABC,
) -> bytes:
    if len(raster) != width * height * 2:
        raise ValueError("fixture raster geometry differs")
    units = len(raster) // 2
    if not 0 < units <= 0x7FFF:
        raise ValueError("fixture unit count differs")
    encoded = (0x8000 | units).to_bytes(2, "big") + raster
    size = 60 + len(encoded)
    preamble = (
        f"{integrity32:08x}{integrity16:04x}{size:08x}{1:04x}"
    ).encode("ascii")
    binary = (
        b"XIM2"
        + (size - 24).to_bytes(4, "big")
        + width.to_bytes(2, "big")
        + height.to_bytes(2, "big")
        + (28).to_bytes(4, "big")
        + bytes(12)
        + (size - 52).to_bytes(4, "big")
        + (0x00100001).to_bytes(4, "big")
        + encoded
    )
    return preamble + binary


def _repeat_yim(unit: bytes, count: int, *, width: int, height: int) -> bytes:
    encoded = count.to_bytes(2, "big") + unit
    size = 60 + len(encoded)
    preamble = f"{0:08x}{0:04x}{size:08x}{1:04x}".encode("ascii")
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


def _session042() -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.distributed-homolog-comparison/v1",
        "classification": {
            "distributed_near_homolog": (
                "NOT_FOUND_UNDER_FIXED_DISTRIBUTED_MODEL"
            )
        },
    }


class YimTests(unittest.TestCase):
    def test_envelope_validates_ascii_and_binary_length_contracts(self):
        data = _literal_yim(bytes(range(16)), width=4, height=2)
        envelope = parse_yim_envelope(data)
        self.assertEqual(envelope.declared_file_size, len(data))
        self.assertEqual((envelope.width, envelope.height), (4, 2))
        self.assertEqual(envelope.outer_span, len(data) - 24)
        self.assertEqual(envelope.payload_block_span, len(data) - 52)

    def test_envelope_rejects_declared_size_change(self):
        data = bytearray(
            _literal_yim(bytes(range(16)), width=4, height=2)
        )
        data[12:20] = b"00000001"
        with self.assertRaisesRegex(ValueError, "file size differs"):
            parse_yim_envelope(bytes(data))

    def test_envelope_rejects_nonzero_reserved_area(self):
        data = bytearray(
            _literal_yim(bytes(range(16)), width=4, height=2)
        )
        data[40] = 1
        with self.assertRaisesRegex(ValueError, "reserved"):
            parse_yim_envelope(bytes(data))

    def test_literal_rle_decodes_exact_raster(self):
        raster = bytes(range(16))
        result = decode_yim_rle(
            _literal_yim(raster, width=4, height=2)
        )
        self.assertEqual(result.raster, raster)
        self.assertEqual(result.literal_command_count, 1)
        self.assertEqual(result.repeat_command_count, 0)

    def test_repeat_rle_decodes_exact_raster(self):
        result = decode_yim_rle(
            _repeat_yim(b"\x12\x34", 8, width=4, height=2)
        )
        self.assertEqual(result.raster, b"\x12\x34" * 8)
        self.assertEqual(result.repeat_command_count, 1)

    def test_rle_rejects_output_overflow(self):
        data = bytearray(_repeat_yim(b"\x12\x34", 8, width=4, height=2))
        data[60:62] = (9).to_bytes(2, "big")
        with self.assertRaisesRegex(ValueError, "exceeds"):
            decode_yim_rle(bytes(data))

    def test_integrity_candidates_do_not_assign_unknown_fields(self):
        data = _literal_yim(bytes(range(16)), width=4, height=2)
        result = decode_yim_rle(data)
        report = yim_integrity_candidates(data, result)
        self.assertFalse(report["integrity_fields_interpreted"])
        self.assertEqual(report["candidate_ranges_tested"], 4)

    def test_public_yim_views_omit_private_values_and_raster(self):
        result = decode_yim_rle(
            _literal_yim(bytes(range(16)), width=4, height=2)
        )
        envelope = public_yim_envelope(result)
        rle = public_yim_rle(result)
        self.assertFalse(envelope["integrity_values_included"])
        self.assertFalse(rle["decoded_raster_included"])
        self.assertNotIn("raster", rle)


class LegacyCycleTests(unittest.TestCase):
    def test_member_filter_is_narrow(self):
        self.assertTrue(legacy_member_eligible("A/SCREEN.YIM", 60))
        self.assertTrue(legacy_member_eligible("A/FLASH.LOD", 60))
        self.assertFalse(legacy_member_eligible("A/FLASH.BIN", 1000))
        self.assertFalse(legacy_member_eligible("A/SCREEN.YIM", 59))

    def test_census_deduplicates_cross_disc_members(self):
        yim = _literal_yim(bytes(range(16)), width=4, height=2)
        report, sources = analyze_legacy_corpus(
            [
                LegacyPayloadInput("cd1", "A/SCREEN.YIM", yim),
                LegacyPayloadInput("cd3", "B/SCREEN.YIM", yim),
                LegacyPayloadInput("cd1", "A/FLASH.LOD", bytes(range(64))),
            ]
        )
        self.assertEqual(report["member_count"], 3)
        self.assertEqual(report["unique_source_count"], 2)
        self.assertEqual(len(sources), 2)
        self.assertFalse(
            report["publication_safety"]["source_content_hashes_included"]
        )

    def test_yim_sessions_validate_decode_and_bound_integrity(self):
        yim = _literal_yim(bytes(range(16)), width=4, height=2)
        _, sources = analyze_legacy_corpus(
            [LegacyPayloadInput("cd1", "A/SCREEN.YIM", yim)]
        )
        envelope = analyze_yim_envelopes(sources)
        rle, results = analyze_yim_rle(sources)
        integrity = analyze_yim_integrity(results)
        self.assertTrue(envelope["all_length_contracts_validated"])
        self.assertEqual(rle["decoded_raster_bytes"], 16)
        self.assertEqual(
            integrity["classification"]["safe_repack"], "BLOCKED"
        )

    def test_lod_topology_reports_counts_without_payload(self):
        sources = [
            {
                "source_id": "LOD-U01",
                "extension": ".LOD",
                "data": b"\x00\x80\x00" + b"A" * 512 + bytes(16),
                "members": [{"disc": "cd1", "path": "A.LOD", "size": 531}],
            },
            {
                "source_id": "LOD-U02",
                "extension": ".LOD",
                "data": b"\x00\x80\x00" + b"B" * 512 + bytes(16),
                "members": [{"disc": "cd3", "path": "B.LOD", "size": 531}],
            },
        ]
        report = analyze_lod_topology(sources)
        self.assertEqual(report["common_prefix_length"], 3)
        self.assertEqual(report["common_suffix_length"], 16)
        self.assertEqual(
            report["classification"]["lod_record_decoder"],
            "NOT_ESTABLISHED",
        )

    def test_decoded_yim_homolog_can_promote_target(self):
        left, right, session038, session039 = _fixture()
        target, _ = _components(left)
        data = _literal_yim(target, width=120, height=1)
        source = {
            "source_id": "YIM-U01",
            "extension": ".YIM",
            "data": data,
            "members": [],
        }
        result = decode_yim_rle(data)
        session040 = _session040(
            session038["left_artifact_sha256"],
            session038["right_artifact_sha256"],
        )
        with TemporaryDirectory() as temporary:
            report = analyze_yim_decoded_homolog(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                session038,
                session039,
                session040,
                _session042(),
                [(source, result)],
            )
        self.assertEqual(
            report["classification"]["yim_decoded_homolog"],
            "YIM_RASTER_HOMOLOG_SUPPORTED",
        )

    def test_decoded_yim_homolog_negative_preserves_open_owner(self):
        left, right, session038, session039 = _fixture()
        raster = hashlib.sha256(b"unrelated").digest() * 8
        data = _literal_yim(raster, width=128, height=1)
        source = {
            "source_id": "YIM-U01",
            "extension": ".YIM",
            "data": data,
            "members": [],
        }
        session040 = _session040(
            session038["left_artifact_sha256"],
            session038["right_artifact_sha256"],
        )
        with TemporaryDirectory() as temporary:
            report = analyze_yim_decoded_homolog(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                session038,
                session039,
                session040,
                _session042(),
                [(source, decode_yim_rle(data))],
            )
        self.assertEqual(
            report["classification"]["yim_decoded_homolog"],
            "NOT_FOUND_IN_VALIDATED_YIM_RASTERS",
        )
        self.assertEqual(report["classification"]["semantic_owner"], "OPEN")

    def test_firmware_map_requires_order_and_advances_graph(self):
        reports = []
        keys = [
            "legacy_family_census",
            "yim_envelope",
            "yim_payload_codec",
            "yim_integrity_fields",
            "lod_structure",
            "yim_decoded_homolog",
        ]
        for session, key in zip(range(44, 50), keys):
            reports.append(
                {
                    "session": f"{session:03d}",
                    "classification": {key: "TEST"},
                }
            )
        prior = {
            "schema": "phoenix-mmi.distributed-homolog-correlation/v1",
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v35",
                "nodes": [],
                "edges": [],
            },
        }
        report = build_firmware_evidence_map(prior, reports)
        self.assertEqual(
            report["operational_graph"]["schema"],
            "phoenix-mmi.operational-graph/v42",
        )
        self.assertFalse(report["classification"]["safe_mutation_ready"])


if __name__ == "__main__":
    unittest.main()

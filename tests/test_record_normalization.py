from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.record_normalization import (
    RecordPayloadInput,
    analyze_record_normalized_homologs,
    build_public_record_normalized_homolog_report,
    correlate_record_normalized_homologs,
    decode_intel_hex,
    decode_srecord_envelope,
    normalize_record_payload,
    record_member_eligible,
    update_operational_graph_v34,
)


_RELATIVES = (2, 32, 104, 140, 196)


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _stream(length: int, salt: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(salt + counter.to_bytes(4, "big")).digest()
        )
        counter += 1
    return bytes(output[:length])


def _fixture():
    left = bytearray(_stream(0x5000, b"record-normalized-left"))
    right = bytearray(_stream(0x6000, b"record-normalized-right"))
    control_start = 0x1000
    left_start = 0x2000
    right_start = 0x3000
    component = bytearray(_stream(240, b"record-normalized-component"))
    left[left_start : left_start + 240] = component
    right[right_start : right_start + 240] = component
    anchor_positions = {
        index
        for relative in _RELATIVES
        for index in range(relative, relative + 25)
    }
    for index in range(0, 240, 13):
        if index not in anchor_positions:
            right[right_start + index] ^= 0x5A
    left_bytes = bytes(left)
    right_bytes = bytes(right)
    left_hash = hashlib.sha256(left_bytes).hexdigest()
    right_hash = hashlib.sha256(right_bytes).hexdigest()
    runs = [
        {
            "run_id": f"RZ012-RUN-{ordinal + 1:03d}",
            "start": left_start + relative,
            "end": left_start + relative + 25,
            "length": 25,
        }
        for ordinal, relative in enumerate(_RELATIVES)
    ]
    session038 = {
        "schema": "phoenix-mmi.run-gap-topology-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "search_contract": {"overlap_start": control_start},
        "rz012": {
            "runs": runs,
            "dominant_promoted_component": {
                "component_id": "RZ012-G1-C001",
                "start": left_start,
                "end": left_start + 240,
                "span": 240,
                "promotion_gate_passed": True,
                "run_ids": [run["run_id"] for run in runs],
            },
        },
        "classification": {
            "micro_island_structural_model": (
                "STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON"
            ),
        },
    }
    session039 = {
        "schema": "phoenix-mmi.registered-provenance-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "target": {
            "component_id": "RZ012-G1-C001",
            "left": {"start": left_start, "end": left_start + 240},
            "rz012_right": {
                "start": right_start,
                "end": right_start + 240,
            },
        },
        "classification": {
            "registered_external_provenance": (
                "NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES"
            ),
            "semantic_owner": "OPEN",
        },
    }
    return left_bytes, right_bytes, session038, session039


def _components(left: bytes):
    return (
        left[0x2000 : 0x2000 + 240],
        left[0x1000 : 0x1000 + 240],
    )


def _intel_record(
    record_type: int,
    address: int,
    payload: bytes = b"",
) -> bytes:
    body = (
        bytes([len(payload)])
        + address.to_bytes(2, "big")
        + bytes([record_type])
        + payload
    )
    checksum = (-sum(body)) & 0xFF
    return b":" + (body + bytes([checksum])).hex().upper().encode()


def _intel_payload(
    data: bytes,
    *,
    address: int = 0x2000,
    vendor_type: int | None = None,
) -> bytes:
    lines = []
    if vendor_type is not None:
        lines.append(_intel_record(vendor_type, 0, b"\x01\x02\x03\x04"))
    for offset in range(0, len(data), 16):
        lines.append(
            _intel_record(
                0,
                address + offset,
                data[offset : offset + 16],
            )
        )
    lines.append(_intel_record(1, 0))
    return b"\r\n".join(lines) + b"\r\n"


def _srecord(record_type: int, address: int, payload: bytes = b"") -> bytes:
    address_length = {
        1: 2,
        2: 3,
        3: 4,
        7: 4,
        8: 3,
        9: 2,
    }[record_type]
    body = address.to_bytes(address_length, "big") + payload
    count = len(body) + 1
    checksum = (~(count + sum(body))) & 0xFF
    return (
        f"S{record_type}".encode()
        + (bytes([count]) + body + bytes([checksum]))
        .hex()
        .upper()
        .encode()
    )


def _srecord_payload(data: bytes, *, opaque_gap: bool = False) -> bytes:
    lines = []
    address = 0x00400000
    for index, offset in enumerate(range(0, len(data), 30)):
        lines.append(
            _srecord(3, address + offset, data[offset : offset + 30])
        )
        if opaque_gap and index == 1:
            lines.append(b"S3NOT-VALID-RECORD")
    lines.append(_srecord(7, address))
    return b"\n".join(lines) + b"\n"


def _session040(left_hash: str, right_hash: str) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.cross-payload-homolog-comparison/v1",
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "signature_contract": {
            "anchor_count": 5,
            "raw_signature_bytes_included": False,
        },
        "classification": {
            "cross_payload_homolog": (
                "NOT_FOUND_UNDER_FIXED_SIGNATURE_MODEL"
            ),
        },
    }


class RecordNormalizationTests(unittest.TestCase):
    def test_intel_hex_reconstructs_address_contiguous_data(self):
        payload = _intel_payload(bytes(range(64)))
        result = decode_intel_hex(payload)
        self.assertTrue(result.fully_validated)
        self.assertEqual(result.format_name, "INTEL_HEX")
        self.assertEqual(len(result.decoded_regions), 1)
        self.assertEqual(result.decoded_regions[0].data, bytes(range(64)))
        self.assertEqual(result.metrics["eof_record_count"], 1)

    def test_intel_vendor_metadata_is_opaque_and_bounded(self):
        payload = _intel_payload(
            bytes(range(32)),
            vendor_type=0x10,
        )
        result = decode_intel_hex(payload)
        self.assertEqual(
            result.classification,
            "VALID_WITH_OPAQUE_VENDOR_METADATA",
        )
        self.assertEqual(
            result.metrics["vendor_metadata_record_count"], 1
        )
        self.assertFalse(
            result.metrics["vendor_metadata_payload_interpreted"]
        )

    def test_intel_hex_rejects_checksum_change(self):
        payload = bytearray(_intel_payload(bytes(range(32))))
        payload[20] = ord("F") if payload[20] != ord("F") else ord("E")
        with self.assertRaisesRegex(ValueError, "checksum"):
            decode_intel_hex(bytes(payload))

    def test_srecord_stream_validates_count_checksum_and_termination(self):
        data = bytes(range(240))
        result = decode_srecord_envelope(_srecord_payload(data))
        self.assertTrue(result.fully_validated)
        self.assertEqual(result.format_name, "MOTOROLA_S_RECORD")
        self.assertEqual(len(result.decoded_regions), 1)
        self.assertEqual(result.decoded_regions[0].data, data)
        self.assertTrue(
            result.metrics["termination_contract_validated"]
        )

    def test_srecord_opaque_line_is_never_used_to_bridge_regions(self):
        data = bytes(range(240))
        result = decode_srecord_envelope(
            _srecord_payload(data, opaque_gap=True)
        )
        self.assertFalse(result.fully_validated)
        self.assertEqual(
            result.classification,
            "PARTIAL_VALIDATED_RECORD_RUNS",
        )
        self.assertEqual(len(result.decoded_regions), 2)
        self.assertFalse(
            result.metrics["opaque_bytes_used_to_bridge_regions"]
        )

    def test_unsupported_binary_containers_are_not_guessed(self):
        result = normalize_record_payload("A/B.LOD", bytes(1024))
        self.assertEqual(
            result.classification, "NO_VALIDATED_RECORD_DECODER"
        )
        self.assertEqual(result.decoded_regions, ())
        self.assertFalse(result.metrics["raw_fallback_rescanned"])

    def test_record_member_filter_is_frozen(self):
        self.assertTrue(record_member_eligible("A/B.HEX", 240))
        self.assertTrue(record_member_eligible("A/B.sw", 240))
        self.assertFalse(record_member_eligible("A/B.BIN", 1000))
        self.assertFalse(record_member_eligible("A/B.YIM", 239))

    def test_normalized_intel_payload_can_promote_fixed_homolog(self):
        left, right, session038, session039 = _fixture()
        target, _ = _components(left)
        session040 = _session040(
            session038["left_artifact_sha256"],
            session038["right_artifact_sha256"],
        )
        with TemporaryDirectory() as temporary:
            report = analyze_record_normalized_homologs(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                session038,
                session039,
                session040,
                [
                    RecordPayloadInput(
                        "cd1",
                        "MODULE/APP.HEX",
                        _intel_payload(target),
                    )
                ],
            )
        self.assertEqual(
            report["classification"]["record_normalized_homolog"],
            "NORMALIZED_CROSS_PAYLOAD_HOMOLOG_SUPPORTED",
        )
        self.assertEqual(
            report["summary"]["target_strong_hit_unique_region_count"], 1
        )
        self.assertEqual(
            report["summary"]["control_geometry_hit_unique_region_count"], 0
        )

    def test_hash_gate_and_public_graph_preserve_open_owner(self):
        left, right, session038, session039 = _fixture()
        session040 = _session040(
            session038["left_artifact_sha256"],
            session038["right_artifact_sha256"],
        )
        with TemporaryDirectory() as temporary:
            left_reader = _reader(left, temporary, "left.bin")
            right_reader = _reader(right, temporary, "right.bin")
            report = analyze_record_normalized_homologs(
                left_reader,
                right_reader,
                session038,
                session039,
                session040,
                [],
            )
            changed = dict(session040)
            changed["left_artifact_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                ValueError, "left principal-image hash differs"
            ):
                analyze_record_normalized_homologs(
                    left_reader,
                    right_reader,
                    session038,
                    session039,
                    changed,
                    [],
                )
        public = build_public_record_normalized_homolog_report(report)
        public["classification"]["semantic_owner"] = "changed"
        self.assertEqual(report["classification"]["semantic_owner"], "OPEN")
        graph = update_operational_graph_v34(
            {
                "schema": "phoenix-mmi.operational-graph/v33",
                "nodes": [],
                "edges": [],
            },
            report,
        )
        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v34")
        correlation = correlate_record_normalized_homologs(
            {
                "media": {"status": "UNCHANGED"},
                "operational_graph": {
                    "schema": "phoenix-mmi.operational-graph/v33",
                    "nodes": [],
                    "edges": [],
                },
            },
            report,
        )
        self.assertEqual(
            correlation["cross_domain_homolog_edge"], "NOT_ASSERTED"
        )
        self.assertFalse(
            correlation["publication_safety"][
                "decoded_region_bytes_included"
            ]
        )


if __name__ == "__main__":
    unittest.main()

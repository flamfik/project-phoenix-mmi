from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.map_payload import classify_payload_header
from phoenix_mmi.parser_contract import (
    compare_parser_constants,
    correlate_payload_parser_contract,
    scan_parser_constants,
)


def _verysmart_payload(*, suffix_class: str) -> bytes:
    stride = 16 if suffix_class == "suffix-b" else 12
    payload = bytearray(128)
    payload[:16] = b"VERYSMART XAC HD"
    payload[16:20] = (4 + stride).to_bytes(4, "big")
    payload[21] = 1
    payload[22:24] = (1).to_bytes(2, "big")
    payload[24:28] = (7).to_bytes(4, "big")
    payload[28:32] = (64).to_bytes(4, "big")
    payload[32:36] = (16).to_bytes(4, "big")
    return bytes(payload)


def _speech_payload() -> bytes:
    index_size = 128
    data_size = 32
    index = (
        b"_type_ synthetic\n"
        b"_size_of_index_ 000128\n"
        b"_size_of_data_ 000032\n"
        b"_revision_ 1\n"
        b"_encoding_ test\n"
        b"token 0 4\n"
    )
    return index.ljust(index_size, b" ") + bytes(data_size)


def _firmware_fixture(path: Path, *, relocation: int) -> None:
    data = bytearray(b"\x00\x09" * 0x300)
    literal = 0x200 + relocation
    first = 0x100 + relocation
    second = 0x120 + relocation
    for offset, register in ((first, 0), (second, 1)):
        displacement = (literal - ((offset & ~3) + 4)) // 4
        word = 0xD000 | register << 8 | displacement
        data[offset : offset + 2] = word.to_bytes(2, "big")
    data[literal : literal + 4] = (0x220).to_bytes(4, "big")
    path.write_bytes(data)


class MapPayloadTests(unittest.TestCase):
    def test_b_and_v_fixed_record_directories_are_validated(self):
        for suffix_class, stride in (("suffix-b", 16), ("suffix-v", 12)):
            payload = _verysmart_payload(suffix_class=suffix_class)
            report = classify_payload_header(
                suffix_class, payload, size=len(payload)
            )
            directory = report["internal_directory"]
            self.assertEqual(
                directory["status"],
                "CONFIRMED_BIG_ENDIAN_FIXED_RECORD_DIRECTORY",
            )
            self.assertEqual(directory["record_stride"], stride)
            self.assertFalse(directory["raw_tags_or_records_included"])

    def test_xac_header_exposes_only_structural_fields(self):
        payload = bytearray(256)
        payload[:16] = b"XAC HEADER      "
        payload[16:20] = (176).to_bytes(4, "big")
        payload[44:58] = b"20170510134824"
        payload[60:74] = b"20170510134824"
        payload[176:180] = (2).to_bytes(4, "big")
        payload[180:182] = (7).to_bytes(2, "big")
        report = classify_payload_header("suffix-xac", bytes(payload), size=256)
        self.assertEqual(
            report["xac_header"]["header_size_status"],
            "CONFIRMED_FIXED_176_BYTES",
        )
        self.assertEqual(report["xac_header"]["partition_id"], 7)
        self.assertTrue(report["xac_header"]["raw_timestamps_or_identifiers_included"] is False)

    def test_speech_index_declared_split_and_references_are_validated(self):
        payload = _speech_payload()
        report = classify_payload_header("suffix-sm5", payload, size=len(payload))
        speech = report["speech_index"]
        self.assertEqual(
            speech["status"],
            "CONFIRMED_DECLARED_TEXT_INDEX_AND_BINARY_DATA_SPLIT",
        )
        self.assertEqual(speech["numeric_reference_row_count"], 1)
        self.assertEqual(speech["numeric_reference_rows_in_bounds"], 1)

    def test_cross_version_constant_windows_pair_without_claiming_parser(self):
        with TemporaryDirectory() as temporary:
            left_path = Path(temporary) / "left.bin"
            right_path = Path(temporary) / "right.bin"
            _firmware_fixture(left_path, relocation=0)
            _firmware_fixture(right_path, relocation=0x200)
            left = scan_parser_constants(BinaryReader(left_path))
            right = scan_parser_constants(BinaryReader(right_path))
            comparison = compare_parser_constants(left, right)
            self.assertEqual(
                comparison["classification"]["fldb_directory_offset_coupling"],
                "PROBABLE_CROSS_VERSION_CODE_COUPLED_CONSTANT",
            )
            self.assertEqual(
                comparison["classification"]["fldb_parser_edge"],
                "NOT_CONFIRMED",
            )

    def test_correlation_keeps_consumer_abi_and_compatibility_open(self):
        prior = {
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v4",
                "nodes": [{"id": "map-media-format", "status": "PARTIAL"}],
                "edges": [],
            }
        }
        payload = {
            "classification": {
                "inner_payload_schema": "PARTIAL_PROPRIETARY_FAMILY_HEADERS_AND_DIRECTORIES",
                "partition_model": "CONFIRMED_CROSS_FAMILY_16_PARTITION_TOPOLOGY",
                "speech_payload_model": "CONFIRMED_DECLARED_TEXT_INDEX_AND_BINARY_DATA_SPLIT",
            },
            "publication_safety": {
                "payload_bytes_included": False,
                "member_or_internal_names_included": False,
            },
        }
        constants = {
            "classification": {
                "fldb_directory_offset_coupling": "PROBABLE_CROSS_VERSION_CODE_COUPLED_CONSTANT",
                "fldb_record_size_coupling": "BOUNDED_AMBIGUOUS",
                "logical_sector_size_coupling": "BOUNDED_AMBIGUOUS",
                "fldb_parser_edge": "NOT_CONFIRMED",
                "sector_read_abi": "OPEN",
            }
        }
        report = correlate_payload_parser_contract(prior, payload, constants)
        self.assertEqual(report["correlation"]["partition_consumer"], "OPEN")
        self.assertEqual(report["correlation"]["sector_read_abi"], "OPEN")
        self.assertEqual(
            report["correlation"]["dynamic_compatibility"], "NOT_ESTABLISHED"
        )
        self.assertEqual(
            report["operational_graph"]["schema"],
            "phoenix-mmi.operational-graph/v5",
        )


if __name__ == "__main__":
    unittest.main()

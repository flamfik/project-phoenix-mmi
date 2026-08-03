from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image, SECTOR_SIZE
from phoenix_mmi.map_media import (
    analyze_navigation_media,
    build_public_navigation_media_report,
    correlate_firmware_and_media,
    parse_fldb_container,
    probe_firmware_media_markers,
)


def _both_u16(value: int) -> bytes:
    return value.to_bytes(2, "little") + value.to_bytes(2, "big")


def _both_u32(value: int) -> bytes:
    return value.to_bytes(4, "little") + value.to_bytes(4, "big")


def _directory_record(name: bytes, extent: int, size: int, directory: bool) -> bytes:
    length = 33 + len(name) + (0 if len(name) % 2 else 1)
    record = bytearray(length)
    record[0] = length
    record[2:10] = _both_u32(extent)
    record[10:18] = _both_u32(size)
    record[25] = 2 if directory else 0
    record[28:32] = _both_u16(1)
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def _fldb_payload(*, overlapping: bool = False) -> bytes:
    entry_count = 2 if overlapping else 1
    content = bytearray(3 * SECTOR_SIZE)
    content[0:4] = (0x220).to_bytes(4, "little")
    content[4:8] = (1).to_bytes(4, "little")
    content[8:12] = (1_500_000_000).to_bytes(4, "little")
    content[12:16] = entry_count.to_bytes(4, "little")
    content[16:20] = (36).to_bytes(4, "little")
    content[20:24] = b"FLDB"
    metadata = b"!dbinfo0001 EHE721 navcd !enddbinfo"
    content[32 : 32 + len(metadata)] = metadata
    for ordinal in range(entry_count):
        base = 0x220 + ordinal * 36
        payload_offset = 0x800 if overlapping else 0x800 + ordinal * 0x800
        content[base : base + 4] = payload_offset.to_bytes(4, "little")
        content[base + 4 : base + 8] = (256).to_bytes(4, "little")
        name = f"EHE721_{ordinal}.poi".encode("ascii")
        content[base + 8 : base + 32] = name.ljust(24, b"\x00")
        content[base + 32 : base + 36] = (0x12345678 + ordinal).to_bytes(
            4, "little"
        )
        content[payload_offset : payload_offset + 32] = (
            b"20170510134824 synthetic payload"
        )
    return bytes(content)


def _make_navigation_iso(path: Path, *, overlapping: bool = False) -> None:
    fldb = _fldb_payload(overlapping=overlapping)
    volume_sectors = 21 + len(fldb) // SECTOR_SIZE
    image = bytearray(volume_sectors * SECTOR_SIZE)
    pvd = memoryview(image)[16 * SECTOR_SIZE : 17 * SECTOR_SIZE]
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = b"WIN32".ljust(32, b" ")
    pvd[40:72] = b"20180215_112901".ljust(32, b" ")
    pvd[80:88] = _both_u32(volume_sectors)
    pvd[120:124] = _both_u16(1)
    pvd[124:128] = _both_u16(1)
    pvd[128:132] = _both_u16(SECTOR_SIZE)
    pvd[132:140] = _both_u32(10)
    pvd[156 : 156 + 34] = _directory_record(
        b"\x00", 20, SECTOR_SIZE, True
    )
    pvd[574:702] = b"ULTRAISO V9.6".ljust(128, b" ")
    pvd[813:830] = b"2018021511330700\x08"
    pvd[830:847] = b"2018021511330700\x08"
    pvd[881] = 1

    svd = memoryview(image)[17 * SECTOR_SIZE : 18 * SECTOR_SIZE]
    svd[:] = pvd
    svd[0] = 2
    svd[88:91] = b"%/E"
    terminator = memoryview(image)[18 * SECTOR_SIZE : 19 * SECTOR_SIZE]
    terminator[0] = 255
    terminator[1:6] = b"CD001"
    terminator[6] = 1

    root = memoryview(image)[20 * SECTOR_SIZE : 21 * SECTOR_SIZE]
    records = (
        _directory_record(b"\x00", 20, SECTOR_SIZE, True)
        + _directory_record(b"\x01", 20, SECTOR_SIZE, True)
        + _directory_record(b"MAP.DB;1", 21, len(fldb), False)
    )
    root[: len(records)] = records
    image[21 * SECTOR_SIZE :] = fldb
    path.write_bytes(image)


class MapMediaTests(unittest.TestCase):
    def test_navigation_medium_and_fldb_table_are_structurally_valid(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "map.iso"
            _make_navigation_iso(path)
            report = analyze_navigation_media(
                ISO9660Image(path), artifact_id="synthetic-map"
            )
            public = build_public_navigation_media_report(report)
            self.assertEqual(
                report["classification"]["optical_filesystem"],
                "CONFIRMED_ISO9660_WITH_JOLIET",
            )
            self.assertEqual(report["aggregate"]["internal_record_count"], 1)
            self.assertEqual(
                report["containers"][0]["structural_status"],
                "CONFIRMED_FLDB_HEADER_AND_FIXED_RECORD_TABLE",
            )
            self.assertEqual(
                report["classification"]["provenance"],
                "UNVERIFIED_PROVENANCE_ULTRAISO_AUTHORED_IMAGE",
            )
            self.assertNotIn("MAP.DB", repr(public))
            self.assertNotIn("EHE721_0.poi", repr(public))
            self.assertFalse(public["publication_safety"]["map_payload_included"])

    def test_overlapping_fldb_ranges_are_not_confirmed(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "overlap.iso"
            _make_navigation_iso(path, overlapping=True)
            image = ISO9660Image(path)
            entry = image.entries()[0]
            report, _ = parse_fldb_container(image, entry, member_id="member-001")
            self.assertEqual(report["record_table"]["overlap_count"], 1)
            self.assertEqual(report["structural_status"], "PARTIAL_OR_INVALID")

    def test_firmware_probe_is_fixed_and_publication_safe(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "firmware.bin"
            path.write_bytes(b"\x00FLDB\x00!dbinfo0001\x00EHE721\x00")
            probe = probe_firmware_media_markers(BinaryReader(path))
            self.assertEqual(probe["marker_counts"]["fldb-magic"], 1)
            self.assertEqual(probe["marker_counts"]["dbinfo-header"], 1)
            self.assertFalse(probe["raw_strings_or_offsets_included"])

    def test_contract_correlation_keeps_parser_and_abi_open(self):
        prior = {
            "classification": {
                "navigation_data_lifecycle": "CONFIRMED",
                "optical_service_contract": "CONFIRMED",
                "navigation_to_optical_direct_edge": "NOT_CONFIRMED",
            },
            "operational_graph": {
                "schema": "phoenix-mmi.operational-graph/v3",
                "nodes": [
                    {"id": "map-media-format", "status": "OPEN"},
                    {"id": "optical-volume-reader", "status": "PROBABLE"},
                    {"id": "navigation-runtime", "status": "CONFIRMED"},
                    {"id": "internal-filesystem", "status": "OPEN"},
                ],
                "edges": [],
            },
        }
        media = {
            "classification": {
                "optical_filesystem": "CONFIRMED_ISO9660_WITH_JOLIET",
                "map_container_format": "CONFIRMED_FLDB_HEADER_AND_FIXED_RECORD_TABLE",
                "inner_payload_schema": "PARTIAL_SUFFIX_FAMILIES_ONLY",
                "routeact_filename_bridge": "NOT_FOUND_UNDER_EXACT_ASCII_PROBE",
            },
            "publication_safety": {
                "map_payload_included": False,
                "member_or_internal_names_included": False,
            },
        }
        probes = {
            "cd1": {"marker_counts": {"fldb-magic": 0}},
            "cd3": {"marker_counts": {"fldb-magic": 0}},
        }
        comparison = correlate_firmware_and_media(prior, media, probes)
        self.assertEqual(comparison["correlation"]["inner_payload_consumer"], "OPEN")
        self.assertEqual(comparison["correlation"]["sector_read_abi"], "OPEN")
        map_node = next(
            node
            for node in comparison["operational_graph"]["nodes"]
            if node["id"] == "map-media-format"
        )
        self.assertEqual(map_node["status"], "PARTIAL_CONFIRMED_OUTER_FORMAT")
        internal = next(
            node
            for node in comparison["operational_graph"]["nodes"]
            if node["id"] == "internal-filesystem"
        )
        self.assertEqual(internal["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()

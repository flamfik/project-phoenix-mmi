from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.navigation_storage import (
    RUNTIME_BASE,
    analyze_navigation_storage_boundary,
    build_public_navigation_storage_report,
    compare_navigation_storage_boundaries,
    discover_boundary_markers,
    scan_storage_signatures,
    update_operational_graph,
)
from phoenix_mmi.strings import StringRecord


def _fat16_sector() -> bytes:
    sector = bytearray(512)
    sector[0:3] = b"\xEB\x3C\x90"
    sector[11:13] = (512).to_bytes(2, "little")
    sector[13] = 1
    sector[14:16] = (1).to_bytes(2, "little")
    sector[16] = 2
    sector[54:59] = b"FAT16"
    sector[510:512] = b"\x55\xAA"
    return bytes(sector)


def _marker_image(path: Path, *, string_base: int) -> None:
    data = bytearray(0x1000)
    strings = tuple(
        f"Navigation route destination sample {index:02d}".encode("ascii")
        for index in range(20)
    )
    offsets = []
    cursor = string_base
    for value in strings:
        data[cursor : cursor + len(value)] = value
        offsets.append(cursor)
        cursor += 0x40
    data[0:2] = (0xD000).to_bytes(2, "big")
    data[2:4] = (0x0009).to_bytes(2, "big")
    data[4:8] = (RUNTIME_BASE + offsets[0]).to_bytes(4, "big")
    path.write_bytes(data)


class NavigationStorageTests(unittest.TestCase):
    def test_marker_discovery_never_returns_raw_text(self):
        records = [
            StringRecord(0x100, "ascii", "Navigation internal data"),
            StringRecord(0x200, "ascii", "dosFs FAT16 volume"),
        ]
        hits = discover_boundary_markers(records)
        self.assertEqual(len(hits), 2)
        self.assertIn("navigation-internal-data", hits[0]["markers"])
        self.assertIn("storage", hits[1]["categories"])
        self.assertTrue(all("text" not in hit for hit in hits))

    def test_signature_validation_rejects_constant_and_accepts_structures(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            constant = root / "constant.bin"
            constant.write_bytes(b"\xAA" * 32 + b"CD001\0" + b"\xBB" * 600)
            result = scan_storage_signatures(BinaryReader(constant))
            self.assertEqual(result["iso9660"]["validated_volume_descriptor_count"], 0)
            self.assertEqual(result["iso9660"]["status"], "IDENTIFIER_CONSTANT_ONLY")

            structured = bytearray(4096)
            structured[100:107] = b"\x01CD001\x01"
            structured[1024:1536] = _fat16_sector()
            image = root / "structured.bin"
            image.write_bytes(structured)
            result = scan_storage_signatures(BinaryReader(image))
            self.assertEqual(result["iso9660"]["validated_volume_descriptor_count"], 1)
            self.assertEqual(result["fat"]["validated_boot_sector_count"], 1)

    def test_code_coupled_markers_form_a_cross_version_band(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left_path = root / "left.bin"
            right_path = root / "right.bin"
            _marker_image(left_path, string_base=0x100)
            _marker_image(right_path, string_base=0x300)
            left = analyze_navigation_storage_boundary(BinaryReader(left_path))
            right = analyze_navigation_storage_boundary(BinaryReader(right_path))
            comparison = compare_navigation_storage_boundaries(left, right)
            public = build_public_navigation_storage_report(left)
            self.assertEqual(
                comparison["navigation"]["subsystem_presence"],
                "CONFIRMED_CROSS_VERSION_NAVIGATION_SUBSYSTEM_EVIDENCE",
            )
            self.assertEqual(comparison["relocation_band_count"], 1)
            self.assertEqual(comparison["relocation_bands"][0]["pair_count"], 20)
            self.assertEqual(
                comparison["relocation_bands"][0][
                    "dual_release_code_referenced_pair_count"
                ],
                1,
            )
            self.assertNotIn("_internal_record_key", repr(public))
            self.assertNotIn("Navigation route destination sample", repr(public))

    def test_operational_graph_preserves_map_and_volume_gaps(self):
        prior = {
            "schema": "phoenix-mmi.operational-graph/v1",
            "nodes": [
                {"id": "navigation-runtime", "status": "OPEN"},
                {"id": "internal-filesystem", "status": "OPEN"},
            ],
            "edges": [
                {
                    "source": "startup-runtime",
                    "target": "navigation-runtime",
                    "status": "HYPOTHESIS",
                },
                {
                    "source": "startup-runtime",
                    "target": "internal-filesystem",
                    "status": "HYPOTHESIS",
                },
            ],
        }
        comparison = {
            "navigation": {
                "region_boundary": "PARTIAL_MULTIPLE_RELOCATED_MARKER_BANDS",
                "map_format": "OPEN",
            },
            "storage": {
                "principal_image_embedded_volume": (
                    "NOT_FOUND_UNDER_TESTED_ISO9660_FAT_VALIDATORS"
                )
            },
        }
        graph = update_operational_graph(prior, comparison)
        navigation = next(
            node for node in graph["nodes"] if node["id"] == "navigation-runtime"
        )
        map_format = next(
            node for node in graph["nodes"] if node["id"] == "map-media-format"
        )
        internal = next(
            node for node in graph["nodes"] if node["id"] == "internal-filesystem"
        )
        self.assertEqual(navigation["status"], "CONFIRMED_SUBSYSTEM_PRESENCE")
        self.assertEqual(map_format["status"], "OPEN")
        self.assertEqual(internal["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()

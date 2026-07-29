import json
from pathlib import Path
import unittest

from phoenix_mmi.resource_catalog import (
    ResourceCatalog,
    ResourceRecord,
    build_public_resource_catalog,
    build_resource_catalog,
    scan_embedded_xim2,
    unique_decoded_records,
)
from phoenix_mmi.resource_graphics import (
    build_candidate_previews,
    build_geometry_taxonomy,
    build_public_preview_summary,
    decode_rgb16,
    evaluate_pixel_layouts,
    geometry_class,
    render_ppm,
)
from phoenix_mmi.resource_lab_audit import (
    M3_EXIT_CRITERIA,
    build_m3_baseline,
)
from phoenix_mmi.resource_lab_integration import (
    MemoryReader,
    _synthetic_sfnt,
    build_synthetic_yim,
    run_resource_lab_integration,
)
from phoenix_mmi.resource_text import (
    build_font_catalog,
    build_language_topology,
    build_resource_relationship_graph,
    build_text_catalog,
    scan_font_candidates,
)
from phoenix_mmi.yim import decode_yim_rle


def _record(
    logical_id: str,
    *,
    release: str = "cd1",
    width: int = 4,
    height: int = 2,
    digest: str = "0" * 64,
) -> ResourceRecord:
    return ResourceRecord(
        logical_id=logical_id,
        origin="embedded-main-image",
        release=release,
        ordinal=0,
        offset=8,
        span=64,
        width=width,
        height=height,
        codec_word=0x00100001,
        encoded_sha256="1" * 64,
        decoded_sha256=digest,
        decoded_bytes=width * height * 2,
    )


class ResourceCatalogTests(unittest.TestCase):
    def test_embedded_xim2_is_strictly_decoded(self):
        raster = bytes(range(16))
        yim = build_synthetic_yim(raster, width=4, height=2)
        rows = scan_embedded_xim2(
            MemoryReader(b"prefix" + yim[24:] + b"suffix"), release="cd1"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].raster, raster)
        self.assertEqual((rows[0].record.width, rows[0].record.height), (4, 2))

    def test_invalid_embedded_candidate_is_rejected(self):
        malformed = b"XIM2" + (36).to_bytes(4, "big") + bytes(28)
        self.assertEqual(
            scan_embedded_xim2(MemoryReader(malformed), release="cd1"), ()
        )

    def test_catalog_deduplicates_by_decoded_content(self):
        catalog = ResourceCatalog(
            "test",
            (
                _record("a", digest="a" * 64),
                _record("b", release="cd3", digest="a" * 64),
            ),
        )
        self.assertEqual(len(unique_decoded_records(catalog)), 1)
        public = build_public_resource_catalog(catalog)
        self.assertEqual(public["record_count"], 2)
        self.assertEqual(public["unique_decoded_content_count"], 1)
        self.assertFalse(
            public["publication_safety"]["decoded_raster_bytes_included"]
        )
        self.assertNotIn("a" * 64, json.dumps(public))

    def test_full_catalog_contains_two_embedded_and_one_standalone(self):
        raster = bytes(range(16))
        yim = build_synthetic_yim(raster, width=4, height=2)
        decoded = decode_yim_rle(yim)
        embedded = {
            release: scan_embedded_xim2(
                MemoryReader(yim[24:]), release=release
            )
            for release in ("cd1", "cd3")
        }
        source = {"data": yim}
        catalog = build_resource_catalog(embedded, [(source, decoded)])
        self.assertEqual(len(catalog.records), 3)
        self.assertEqual(
            build_public_resource_catalog(catalog)["origin_counts"],
            {"embedded-main-image": 2, "standalone-update": 1},
        )

    def test_catalog_rejects_unsorted_ids(self):
        with self.assertRaises(ValueError):
            ResourceCatalog("test", (_record("b"), _record("a")))


class ResourceGraphicsTests(unittest.TestCase):
    def test_geometry_classes_do_not_assign_ui_semantics(self):
        self.assertEqual(geometry_class(480, 240), "DISPLAY_SIZED_480X240")
        self.assertEqual(geometry_class(480, 16), "FULL_WIDTH_STRIP")
        self.assertEqual(geometry_class(16, 64), "TALL_RECTANGLE")
        self.assertEqual(geometry_class(64, 16), "WIDE_RECTANGLE")
        self.assertEqual(geometry_class(32, 32), "COMPACT_RECTANGLE")
        with self.assertRaises(ValueError):
            geometry_class(0, 4)

    def test_geometry_taxonomy_uses_unique_decoded_content(self):
        catalog = ResourceCatalog(
            "test",
            (
                _record("a", digest="a" * 64),
                _record("b", release="cd3", digest="a" * 64),
                _record(
                    "c", release="cd3", width=480, height=240, digest="b" * 64
                ),
            ),
        )
        report = build_geometry_taxonomy(catalog)
        self.assertEqual(report["unique_resource_count"], 2)
        self.assertEqual(report["classification"]["ui_semantic_roles"], "NOT_ASSIGNED")

    def test_known_rgb565_big_endian_values(self):
        rgb = decode_rgb16(bytes.fromhex("f80007e0001fffff"), "RGB565_BE")
        self.assertEqual(
            rgb,
            bytes((255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255)),
        )

    def test_pixel_evaluation_never_selects_layout(self):
        report = evaluate_pixel_layouts(
            [("fixture", bytes.fromhex("0000fffff80007e0"), 2, 2)]
        )
        self.assertEqual(report["candidate_count"], 8)
        self.assertEqual(report["classification"]["pixel_layout"], "NOT_ESTABLISHED")
        self.assertEqual(len(report["smoothness_ranking"]), 8)

    def test_ppm_preview_is_explicit_and_bounded(self):
        raster = bytes.fromhex("f80007e0001fffff")
        ppm = render_ppm(raster, 2, 2, "RGB565_BE")
        self.assertTrue(ppm.startswith(b"P6\n2 2\n255\n"))
        previews = build_candidate_previews(raster, 2, 2)
        summary = build_public_preview_summary(previews, width=2, height=2)
        self.assertEqual(summary["candidate_preview_count"], 4)
        self.assertFalse(summary["publication_safety"]["preview_files_committed"])
        with self.assertRaises(ValueError):
            render_ppm(raster, 4097, 4097, "RGB565_BE")


class ResourceTextAndFontTests(unittest.TestCase):
    def test_text_catalog_publishes_aggregates_only(self):
        readers = {
            "cd1": MemoryReader(b"SECRET_MENU /ui/path ENGLISHUK"),
            "cd3": MemoryReader(b"SECRET_MENU /ui/path GERMAN"),
        }
        report = build_text_catalog(readers)
        serialized = json.dumps(report)
        self.assertEqual(report["classification"]["text_presence"], "CONFIRMED")
        self.assertNotIn("SECRET_MENU", serialized)
        self.assertFalse(report["publication_safety"]["raw_strings_included"])

    def test_structural_sfnt_validation_accepts_complete_fixture(self):
        rows = scan_font_candidates(MemoryReader(_synthetic_sfnt()))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind, "TRUETYPE_SFNT")

    def test_sfnt_validation_rejects_header_only_magic(self):
        fake = b"\x00\x01\x00\x00" + (4).to_bytes(2, "big") + bytes(100)
        self.assertEqual(scan_font_candidates(MemoryReader(fake)), ())

    def test_sfnt_validation_rejects_missing_head_magic(self):
        fake = bytearray(_synthetic_sfnt())
        marker = fake.find(b"\x5f\x0f\x3c\xf5")
        fake[marker : marker + 4] = bytes(4)
        self.assertEqual(scan_font_candidates(MemoryReader(bytes(fake))), ())

    def test_font_catalog_compares_content_without_publishing_hashes(self):
        font = _synthetic_sfnt()
        report = build_font_catalog(
            {"cd1": MemoryReader(font), "cd3": MemoryReader(font)},
            {
                "structural_status": "PROBABLE",
                "semantic_status": "OPEN",
                "semantic_confirmation": False,
            },
        )
        self.assertEqual(
            report["cross_version"]["shared_standard_font_content_count"], 1
        )
        self.assertEqual(
            report["classification"]["standard_font_container_presence"],
            "CONFIRMED",
        )
        self.assertFalse(report["publication_safety"]["content_hashes_included"])

    def test_language_topology_maps_only_fixed_locale_markers(self):
        sources = [
            {
                "source_id": "a",
                "extension": ".LOD",
                "members": [
                    {"disc": "cd1", "path": "SDS/GERMAN/A.LOD", "size": 4},
                    {"disc": "cd3", "path": "SDS/GERMAN/A.LOD", "size": 4},
                ],
            },
            {
                "source_id": "b",
                "extension": ".YIM",
                "members": [
                    {"disc": "cd1", "path": "DATA/DEFAULT/A.YIM", "size": 8}
                ],
            },
        ]
        report = build_language_topology(sources)
        self.assertEqual(report["locale_count"], 1)
        self.assertEqual(report["locales"][0]["locale"], "de-DE")
        self.assertTrue(report["locales"][0]["present_on_cd1_and_cd3"])
        self.assertEqual(report["default_display_resource_member_count"], 1)


class ResourceLabIntegrationTests(unittest.TestCase):
    def test_m3_baseline_requires_complete_m2_gate(self):
        closure = {
            "schema": "phoenix-mmi.m2-toolkit-progress/v1",
            "classification": {
                "m2_status": "COMPLETE",
                "m2_exit": "PASS",
                "safe_mutation_ready": False,
            },
            "milestone_transition": {"m3": "READY"},
        }
        baseline = build_m3_baseline(Path(__file__).parents[1], closure)
        self.assertEqual(baseline["session"], "075")
        self.assertEqual(baseline["exit_criteria_total"], len(M3_EXIT_CRITERIA))
        self.assertEqual(baseline["classification"]["m3_status"], "IN_PROGRESS")
        self.assertFalse(baseline["classification"]["safe_mutation_ready"])
        bad = {**closure, "milestone_transition": {"m3": "BLOCKED"}}
        with self.assertRaises(ValueError):
            build_m3_baseline(Path(__file__).parents[1], bad)

    def test_resource_graph_preserves_open_runtime_and_mutation_gates(self):
        integration = run_resource_lab_integration()
        graph = integration["graph"]
        self.assertGreaterEqual(graph["node_count"], 10)
        self.assertTrue(integration["passed"])
        self.assertFalse(integration["publication_safety"]["firmware_bytes_included"])

    def test_synthetic_integration_is_deterministic(self):
        first = run_resource_lab_integration()
        second = run_resource_lab_integration()
        self.assertEqual(first, second)
        self.assertEqual(len(first["integration_fingerprint"]), 64)
        self.assertEqual(first["fixture_class"], "SYNTHETIC_NON_FIRMWARE_RESOURCE_CORPUS")

    def test_relationship_graph_does_not_claim_runtime_renderer(self):
        integration = run_resource_lab_integration()
        graph = build_resource_relationship_graph(
            {"schema": integration["catalog"]["schema"]},
            {"schema": integration["geometry"]["schema"]},
            {"schema": integration["pixels"]["schema"]},
            {"schema": integration["preview"]["schema"]},
            {"schema": integration["text"]["schema"]},
            {
                "schema": integration["fonts"]["schema"],
                "classification": {
                    "standard_font_container_presence": "CONFIRMED"
                },
            },
            {"schema": integration["language"]["schema"]},
        )
        self.assertEqual(
            graph["classification"]["runtime_renderer_model"], "NOT_ESTABLISHED"
        )
        self.assertFalse(graph["classification"]["safe_mutation_ready"])


if __name__ == "__main__":
    unittest.main()

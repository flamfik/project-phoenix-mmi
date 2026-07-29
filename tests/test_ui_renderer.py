import unittest

from phoenix_mmi.ui_model import build_phoenix_information_architecture
from phoenix_mmi.ui_reducer import initial_ui_state
from phoenix_mmi.ui_renderer import (
    build_preview_set,
    build_public_preview_catalog,
    render_screen_svg,
    validate_rendered_svg,
)


class UIRendererTests(unittest.TestCase):
    def setUp(self):
        self.model = build_phoenix_information_architecture()

    def test_renderer_is_deterministic(self):
        state = initial_ui_state(self.model)
        first = render_screen_svg(self.model, state)
        second = render_screen_svg(self.model, state)
        self.assertEqual(first, second)

    def test_svg_has_fixed_viewport_and_focus(self):
        preview = render_screen_svg(
            self.model, initial_ui_state(self.model)
        )
        validate_rendered_svg(preview.svg)
        self.assertIn('width="480"', preview.svg)
        self.assertIn('height="240"', preview.svg)
        self.assertIn('stroke="#78FFE0"', preview.svg)
        self.assertGreater(preview.draw_command_count, 0)

    def test_svg_contains_original_copy(self):
        svg = render_screen_svg(
            self.model, initial_ui_state(self.model)
        ).svg
        self.assertIn(">Phoenix</text>", svg)
        self.assertIn(">Communication</text>", svg)
        self.assertNotIn("Audi", svg)

    def test_svg_has_no_external_or_executable_content(self):
        svg = render_screen_svg(
            self.model, initial_ui_state(self.model)
        ).svg.lower()
        self.assertNotIn("<script", svg)
        self.assertNotIn("<image", svg)
        self.assertNotIn("href=", svg)
        self.assertNotIn("url(", svg)
        self.assertNotIn("data:", svg)

    def test_validator_rejects_script(self):
        with self.assertRaises(ValueError):
            validate_rendered_svg(
                '<svg width="480" height="240"><script/></svg>'
            )

    def test_preview_set_covers_every_screen(self):
        previews = build_preview_set(self.model)
        self.assertEqual(len(previews), 5)
        self.assertEqual(
            {preview.screen_id for preview in previews},
            {screen.screen_id for screen in self.model.screens},
        )

    def test_preview_catalog_is_stable_and_bounded(self):
        catalog = build_public_preview_catalog(
            build_preview_set(self.model)
        )
        self.assertEqual(catalog["preview_count"], 5)
        self.assertGreater(catalog["metrics"]["total_svg_bytes"], 0)
        self.assertGreater(catalog["metrics"]["total_draw_commands"], 0)
        self.assertEqual(catalog["metrics"]["external_reference_count"], 0)
        self.assertEqual(catalog["metrics"]["script_count"], 0)
        self.assertEqual(catalog["metrics"]["embedded_raster_count"], 0)

    def test_manifest_hashes_are_reproducible(self):
        first = build_public_preview_catalog(build_preview_set(self.model))
        second = build_public_preview_catalog(build_preview_set(self.model))
        self.assertEqual(first["manifest"], second["manifest"])

    def test_catalog_does_not_claim_firmware_compatibility(self):
        classification = build_public_preview_catalog()[
            "classification"
        ]
        self.assertEqual(
            classification["firmware_renderer_compatibility"],
            "NOT_ESTABLISHED",
        )
        self.assertEqual(
            classification["hardware_performance"], "NOT_MEASURED"
        )

    def test_catalog_is_publication_safe(self):
        safety = build_public_preview_catalog()["publication_safety"]
        self.assertTrue(safety["original_content_only"])
        for key, value in safety.items():
            if key.endswith("_included"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

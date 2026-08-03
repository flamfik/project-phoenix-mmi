from dataclasses import replace
import unittest

from phoenix_mmi.ui_model import build_phoenix_information_architecture
from phoenix_mmi.ui_theme import (
    build_original_theme_bundle,
    build_public_theme_catalog,
    color_value,
    icon_asset,
    metric_value,
    text_value,
    validate_theme_bundle,
)


class UIThemeTests(unittest.TestCase):
    def setUp(self):
        self.model = build_phoenix_information_architecture()
        self.bundle = build_original_theme_bundle(self.model)

    def test_theme_is_deterministic_and_valid(self):
        self.assertEqual(
            self.bundle,
            build_original_theme_bundle(self.model),
        )
        validate_theme_bundle(self.bundle, self.model)

    def test_theme_has_complete_original_registry(self):
        catalog = build_public_theme_catalog(self.model)
        metrics = catalog["metrics_summary"]
        self.assertEqual(metrics["color_token_count"], 8)
        self.assertEqual(metrics["metric_token_count"], 7)
        self.assertEqual(metrics["text_token_count"], 23)
        self.assertEqual(metrics["icon_asset_count"], 6)
        self.assertEqual(metrics["external_asset_count"], 0)
        self.assertGreater(metrics["synthetic_asset_bytes"], 0)

    def test_every_token_and_asset_has_original_source(self):
        self.assertTrue(
            all(token.source == "ORIGINAL" for token in self.bundle.colors)
        )
        self.assertTrue(
            all(token.source == "ORIGINAL" for token in self.bundle.metrics)
        )
        self.assertTrue(
            all(token.source == "ORIGINAL" for token in self.bundle.text)
        )
        self.assertTrue(
            all(asset.source == "ORIGINAL" for asset in self.bundle.icons)
        )

    def test_lookup_helpers_are_strict(self):
        self.assertEqual(color_value(self.bundle, "background"), "#07111C")
        self.assertEqual(metric_value(self.bundle, "body-size"), 14)
        self.assertEqual(
            text_value(self.bundle, "phoenix.screen.home"), "Phoenix"
        )
        self.assertEqual(
            icon_asset(self.bundle, "navigation").viewbox_width, 16
        )
        with self.assertRaises(ValueError):
            color_value(self.bundle, "missing")

    def test_icon_points_are_normalized(self):
        for asset in self.bundle.icons:
            for polyline in asset.polylines:
                for x, y in polyline:
                    self.assertGreaterEqual(x, 0)
                    self.assertLessEqual(x, 16)
                    self.assertGreaterEqual(y, 0)
                    self.assertLessEqual(y, 16)

    def test_validator_rejects_non_original_color(self):
        bad = replace(self.bundle.colors[0], source="FIRMWARE")
        invalid = replace(
            self.bundle, colors=(bad,) + self.bundle.colors[1:]
        )
        with self.assertRaises(ValueError):
            validate_theme_bundle(invalid, self.model)

    def test_validator_rejects_incomplete_text_registry(self):
        invalid = replace(self.bundle, text=self.bundle.text[:-1])
        with self.assertRaises(ValueError):
            validate_theme_bundle(invalid, self.model)

    def test_validator_rejects_out_of_bounds_icon(self):
        icon = self.bundle.icons[0]
        bad_icon = replace(icon, polylines=(((0, 0), (17, 16)),))
        invalid = replace(
            self.bundle, icons=(bad_icon,) + self.bundle.icons[1:]
        )
        with self.assertRaises(ValueError):
            validate_theme_bundle(invalid, self.model)

    def test_catalog_explicitly_excludes_external_assets(self):
        catalog = build_public_theme_catalog(self.model)
        classification = catalog["classification"]
        self.assertFalse(classification["firmware_asset_reuse"])
        self.assertFalse(classification["navigation_media_asset_reuse"])
        self.assertFalse(classification["external_asset_dependency"])

    def test_catalog_is_publication_safe(self):
        safety = build_public_theme_catalog(self.model)["publication_safety"]
        self.assertTrue(safety["original_content_only"])
        for key, value in safety.items():
            if key.endswith("_included"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

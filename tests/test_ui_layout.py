from dataclasses import replace
import unittest

from phoenix_mmi.ui_layout import (
    Rect,
    build_layout_catalog,
    build_screen_layout,
    validate_screen_layout,
)
from phoenix_mmi.ui_model import build_phoenix_information_architecture


class UILayoutTests(unittest.TestCase):
    def setUp(self):
        self.model = build_phoenix_information_architecture()

    def test_every_screen_has_bounded_layout(self):
        for screen in self.model.screens:
            layout = build_screen_layout(self.model, screen.screen_id)
            self.assertEqual(layout.viewport, Rect(0, 0, 480, 240))
            validate_screen_layout(
                layout,
                expected_entry_ids={
                    entry.entry_id for entry in screen.entries
                },
            )

    def test_layout_catalog_has_all_entries(self):
        catalog = build_layout_catalog(self.model)
        self.assertEqual(catalog["metrics"]["screen_layout_count"], 5)
        self.assertEqual(catalog["metrics"]["entry_rectangle_count"], 16)
        self.assertEqual(catalog["metrics"]["overflow_count"], 0)
        self.assertEqual(catalog["metrics"]["overlap_count"], 0)

    def test_entry_floor_and_screen_maximum(self):
        metrics = build_layout_catalog(self.model)["metrics"]
        self.assertGreaterEqual(metrics["minimum_entry_height"], 32)
        self.assertEqual(metrics["maximum_entries_per_screen"], 4)

    def test_entry_rectangles_are_integer_only(self):
        catalog = build_layout_catalog(self.model)
        self.assertTrue(catalog["metrics"]["integer_coordinates_only"])
        for layout in catalog["layouts"]:
            for entry in layout["entries"]:
                self.assertTrue(
                    all(
                        isinstance(value, int)
                        for value in entry["rect"].values()
                    )
                )

    def test_validator_rejects_viewport_change(self):
        layout = build_screen_layout(self.model, "home")
        invalid = replace(layout, viewport=Rect(0, 0, 481, 240))
        with self.assertRaises(ValueError):
            validate_screen_layout(invalid)

    def test_validator_rejects_content_overflow(self):
        layout = build_screen_layout(self.model, "home")
        entry = layout.entries[0]
        invalid_entry = replace(entry, rect=Rect(12, 200, 456, 34))
        invalid = replace(
            layout, entries=(invalid_entry,) + layout.entries[1:]
        )
        with self.assertRaises(ValueError):
            validate_screen_layout(invalid)

    def test_validator_rejects_entry_overlap(self):
        layout = build_screen_layout(self.model, "home")
        duplicate_rect = replace(
            layout.entries[1], rect=layout.entries[0].rect
        )
        invalid = replace(
            layout,
            entries=(layout.entries[0], duplicate_rect)
            + layout.entries[2:],
        )
        with self.assertRaises(ValueError):
            validate_screen_layout(invalid)

    def test_validator_rejects_missing_entry(self):
        layout = build_screen_layout(self.model, "home")
        with self.assertRaises(ValueError):
            validate_screen_layout(
                replace(layout, entries=layout.entries[:-1]),
                expected_entry_ids={
                    entry.entry_id
                    for entry in self.model.screens[0].entries
                },
            )

    def test_catalog_does_not_claim_firmware_layout(self):
        classification = build_layout_catalog(self.model)["classification"]
        self.assertFalse(
            classification["firmware_layout_reconstruction"]
        )
        self.assertFalse(classification["font_metrics_applied"])
        self.assertFalse(classification["renderer_implemented"])

    def test_catalog_is_deterministic(self):
        self.assertEqual(
            build_layout_catalog(self.model),
            build_layout_catalog(self.model),
        )


if __name__ == "__main__":
    unittest.main()

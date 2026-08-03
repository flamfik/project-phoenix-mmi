import unittest

from phoenix_mmi.ui_quality import (
    audit_ui_quality,
    contrast_ratio,
    relative_luminance,
)


class UIQualityTests(unittest.TestCase):
    def test_known_contrast_extremes(self):
        self.assertAlmostEqual(contrast_ratio("#000000", "#FFFFFF"), 21.0)
        self.assertAlmostEqual(contrast_ratio("#123456", "#123456"), 1.0)

    def test_luminance_is_ordered(self):
        self.assertLess(
            relative_luminance("#000000"),
            relative_luminance("#808080"),
        )
        self.assertLess(
            relative_luminance("#808080"),
            relative_luminance("#FFFFFF"),
        )

    def test_invalid_color_is_rejected(self):
        with self.assertRaises(ValueError):
            contrast_ratio("black", "#FFFFFF")

    def test_quality_audit_passes_all_eight_criteria(self):
        report = audit_ui_quality()
        self.assertEqual(report["criteria_passed"], 8)
        self.assertEqual(report["criteria_total"], 8)
        self.assertEqual(report["classification"]["quality_gate"], "PASS")

    def test_every_focus_state_has_one_indicator(self):
        focus = audit_ui_quality()["focus_audit"]
        self.assertEqual(focus["state_count"], 16)
        self.assertTrue(focus["all_states_have_one_indicator"])
        self.assertEqual(
            {row["focus_indicator_count"] for row in focus["checks"]},
            {1},
        )

    def test_contrast_thresholds_pass(self):
        contrast = audit_ui_quality()["contrast_audit"]
        self.assertTrue(contrast["passed"])
        self.assertGreaterEqual(
            contrast["ratios"]["primary_on_surface"], 4.5
        )
        self.assertGreaterEqual(
            contrast["ratios"]["focus_on_focused_surface"], 3.0
        )

    def test_complexity_is_bounded(self):
        complexity = audit_ui_quality()["complexity"]
        self.assertEqual(complexity["screen_count"], 5)
        self.assertLessEqual(complexity["maximum_entries_per_screen"], 6)
        self.assertLessEqual(complexity["maximum_draw_commands"], 32)
        self.assertLessEqual(complexity["synthetic_asset_bytes"], 8192)

    def test_audit_makes_no_hardware_claim(self):
        classification = audit_ui_quality()["classification"]
        self.assertEqual(
            classification["measurement_scope"], "HOST_PROTOTYPE_ONLY"
        )
        self.assertEqual(
            classification["target_hardware_suitability"],
            "NOT_ESTABLISHED",
        )
        self.assertFalse(
            classification["numeric_mmi_cpu_budget_claimed"]
        )
        self.assertFalse(
            classification["numeric_mmi_memory_budget_claimed"]
        )

    def test_audit_is_deterministic(self):
        self.assertEqual(audit_ui_quality(), audit_ui_quality())

    def test_audit_is_publication_safe(self):
        safety = audit_ui_quality()["publication_safety"]
        self.assertTrue(safety["host_metrics_only"])
        for key, value in safety.items():
            if key.endswith("_included"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

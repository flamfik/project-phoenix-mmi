import unittest

from phoenix_mmi.ui_integration import run_ui_prototype_integration


class UIIntegrationTests(unittest.TestCase):
    def test_integration_is_deterministic(self):
        self.assertEqual(
            run_ui_prototype_integration(),
            run_ui_prototype_integration(),
        )

    def test_all_eight_stages_pass(self):
        report = run_ui_prototype_integration()
        self.assertTrue(report["passed"])
        self.assertEqual(report["stages_passed"], 8)
        self.assertEqual(report["stages_total"], 8)
        self.assertEqual(
            {stage["passed"] for stage in report["stages"]}, {True}
        )

    def test_summary_covers_complete_m5_chain(self):
        summary = run_ui_prototype_integration()["summary"]
        self.assertEqual(summary["screen_count"], 5)
        self.assertEqual(summary["focus_state_count"], 16)
        self.assertEqual(summary["transition_count"], 80)
        self.assertEqual(summary["entry_rectangle_count"], 16)
        self.assertEqual(summary["original_icon_count"], 6)
        self.assertEqual(summary["preview_count"], 5)
        self.assertEqual(summary["quality_criteria"], "8/8")

    def test_fingerprint_is_sha256(self):
        fingerprint = run_ui_prototype_integration()[
            "integration_fingerprint"
        ]
        self.assertEqual(len(fingerprint), 64)
        int(fingerprint, 16)

    def test_integration_keeps_mutation_blocked(self):
        classification = run_ui_prototype_integration()["classification"]
        self.assertFalse(classification["safe_mutation_ready"])
        self.assertFalse(classification["installable_artifact_ready"])
        self.assertEqual(
            classification["firmware_compatibility"], "NOT_ESTABLISHED"
        )
        self.assertEqual(
            classification["hardware_suitability"], "NOT_ESTABLISHED"
        )

    def test_integration_is_publication_safe(self):
        safety = run_ui_prototype_integration()["publication_safety"]
        self.assertTrue(safety["original_or_synthetic_content_only"])
        for key, value in safety.items():
            if key.endswith("_included"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
import unittest

from phoenix_mmi.navigation_integration import (
    run_navigation_feasibility_integration,
)


ROOT = Path(__file__).resolve().parents[1]


class NavigationIntegrationTests(unittest.TestCase):
    def test_integration_is_deterministic(self):
        self.assertEqual(
            run_navigation_feasibility_integration(ROOT),
            run_navigation_feasibility_integration(ROOT),
        )

    def test_all_eight_stages_pass(self):
        report = run_navigation_feasibility_integration(ROOT)
        self.assertTrue(report["passed"])
        self.assertEqual(report["stages_passed"], 8)
        self.assertEqual(report["stages_total"], 8)

    def test_dual_track_verdict_is_explicit(self):
        decision = run_navigation_feasibility_integration(ROOT)["decision"]
        self.assertEqual(
            decision["direct_mmi_media_replacement"]["status"], "BLOCKED"
        )
        self.assertFalse(
            decision["direct_mmi_media_replacement"][
                "installable_output_authorized"
            ]
        )
        self.assertEqual(
            decision["independent_osm_host_pipeline"]["status"],
            "PROTOTYPE_FEASIBLE",
        )
        self.assertEqual(
            decision["sidecar_or_replacement_hardware"]["status"],
            "NOT_EVALUATED",
        )

    def test_summary_preserves_registered_counts(self):
        summary = run_navigation_feasibility_integration(ROOT)["summary"]
        self.assertEqual(summary["validated_fldb_container_count"], 7)
        self.assertEqual(summary["internal_record_count"], 3599)
        self.assertEqual(summary["partition_count"], 16)

    def test_fingerprint_is_sha256(self):
        value = run_navigation_feasibility_integration(ROOT)[
            "integration_fingerprint"
        ]
        self.assertEqual(len(value), 64)
        int(value, 16)

    def test_integration_keeps_mutation_blocked(self):
        classification = run_navigation_feasibility_integration(ROOT)[
            "classification"
        ]
        self.assertFalse(classification["safe_mutation_ready"])
        self.assertFalse(classification["installable_artifact_ready"])
        self.assertFalse(classification["vehicle_validation_performed"])

    def test_integration_is_publication_safe(self):
        safety = run_navigation_feasibility_integration(ROOT)[
            "publication_safety"
        ]
        for key, value in safety.items():
            if key.endswith("_included"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

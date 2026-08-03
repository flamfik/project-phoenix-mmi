import json
from pathlib import Path
import unittest

from phoenix_mmi.hardware_validation_integration import (
    run_hardware_validation_preparation_integration,
)


ROOT = Path(__file__).resolve().parents[1]
M7_ROOT = ROOT / "research/milestones/m7"
CLOSURE_PATH = (
    M7_ROOT / "session119" / "m7-preparation-readiness.json"
)


class M7ReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(CLOSURE_PATH.read_text(encoding="utf-8"))

    def test_preparation_is_complete_but_m7_is_not(self):
        self.assertEqual(
            self.report["classification"]["m7_status"],
            "AWAITING_BENCH_EVIDENCE",
        )
        self.assertEqual(
            self.report["classification"]["preparation_criteria_passed"], 8
        )
        self.assertEqual(
            self.report["classification"]["physical_criteria_passed"], 0
        )
        self.assertEqual(self.report["exit_criteria_passed"], 8)
        self.assertEqual(self.report["exit_criteria_total"], 9)

    def test_session120_is_the_honest_stop(self):
        transition = self.report["milestone_transition"]
        self.assertEqual(transition["m7"], "AWAITING_BENCH_EVIDENCE")
        self.assertEqual(transition["m8"], "NOT_READY")
        self.assertEqual(transition["next_session"], "120")
        self.assertEqual(
            transition["required_external_evidence"],
            "PRIVATE_SIGNED_ISOLATED_BENCH_BUNDLE",
        )

    def test_integration_is_deterministic(self):
        first = run_hardware_validation_preparation_integration()
        second = run_hardware_validation_preparation_integration()
        self.assertEqual(first, second)
        self.assertTrue(first["preparation_passed"])
        self.assertTrue(first["repeat_run_equal"])
        self.assertEqual(first["stages_passed"], 8)
        self.assertEqual(first["stages_total"], 8)

    def test_physical_and_vehicle_claims_are_false(self):
        classification = self.report["classification"]
        self.assertFalse(
            classification["physical_bench_validation_performed"]
        )
        self.assertFalse(classification["vehicle_operations_authorized"])
        self.assertFalse(classification["safe_mutation_ready"])
        self.assertFalse(classification["installable_artifact_ready"])

    def test_every_preparation_session_report_exists(self):
        for session in range(111, 120):
            path = M7_ROOT / f"session{session:03d}"
            self.assertEqual(len(list(path.glob("*.json"))), 1)

    def test_publication_flags_remain_safe(self):
        safety = self.report["publication_safety"]
        for key, value in safety.items():
            if (
                key.endswith("_included")
                or key.endswith("_performed")
                or key == "hardware_powered"
            ):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

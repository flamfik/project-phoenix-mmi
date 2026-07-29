import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
M6_ROOT = ROOT / "research" / "milestones" / "m6"
CLOSURE_PATH = M6_ROOT / "session110" / "milestone-m6-closure.json"


class M6ClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(CLOSURE_PATH.read_text(encoding="utf-8"))

    def test_m6_is_complete_and_m7_is_ready(self):
        self.assertEqual(self.report["classification"]["m6_status"], "COMPLETE")
        self.assertEqual(self.report["milestone_transition"]["m6"], "COMPLETE")
        self.assertEqual(self.report["milestone_transition"]["m7"], "READY")

    def test_all_exit_criteria_pass(self):
        self.assertEqual(self.report["exit_criteria_passed"], 8)
        self.assertEqual(self.report["exit_criteria_total"], 8)
        self.assertEqual(
            {row["passed"] for row in self.report["exit_criteria"]}, {True}
        )

    def test_dual_track_verdict_is_preserved(self):
        transition = self.report["milestone_transition"]
        self.assertEqual(
            transition["direct_mmi_media_replacement"], "BLOCKED"
        )
        self.assertEqual(
            transition["independent_osm_host_pipeline"],
            "PROTOTYPE_FEASIBLE",
        )

    def test_integration_reproduces(self):
        integration = self.report["integration"]
        self.assertTrue(integration["passed"])
        self.assertTrue(integration["repeat_run_equal"])
        self.assertEqual(integration["stages_passed"], 8)
        self.assertEqual(integration["stages_total"], 8)

    def test_mutation_and_installation_remain_blocked(self):
        self.assertFalse(self.report["classification"]["safe_mutation_ready"])
        self.assertFalse(
            self.report["classification"]["installable_artifact_ready"]
        )
        self.assertFalse(
            self.report["milestone_transition"]["safe_mutation_ready"]
        )

    def test_every_m6_session_report_exists(self):
        for session in range(102, 111):
            path = M6_ROOT / f"session{session:03d}"
            self.assertEqual(len(list(path.glob("*.json"))), 1)

    def test_closure_contains_no_unsafe_publication_flags(self):
        safety = self.report["publication_safety"]
        for key, value in safety.items():
            if key.endswith("_included") or key.endswith("_performed"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

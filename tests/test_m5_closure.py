import json
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLOSURE_PATH = (
    ROOT
    / "research"
    / "milestones"
    / "m5"
    / "session101"
    / "milestone-m5-closure.json"
)
PREVIEW_PATH = ROOT / "ui" / "previews" / "m5" / "session098"


class M5ClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(CLOSURE_PATH.read_text(encoding="utf-8"))

    def test_m5_is_complete_and_m6_is_ready(self):
        self.assertEqual(self.report["classification"]["m5_status"], "COMPLETE")
        self.assertEqual(self.report["milestone_transition"]["m5"], "COMPLETE")
        self.assertEqual(self.report["milestone_transition"]["m6"], "READY")

    def test_all_exit_criteria_pass(self):
        self.assertEqual(self.report["exit_criteria_passed"], 8)
        self.assertEqual(self.report["exit_criteria_total"], 8)
        self.assertEqual(
            {criterion["passed"] for criterion in self.report["exit_criteria"]},
            {True},
        )

    def test_integration_gate_reproduces(self):
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

    def test_every_closure_session_report_exists(self):
        for session in range(95, 102):
            session_path = (
                ROOT
                / "research"
                / "milestones"
                / "m5"
                / f"session{session:03d}"
            )
            self.assertEqual(len(list(session_path.glob("*.json"))), 1)

    def test_five_public_svg_previews_exist(self):
        self.assertEqual(len(list(PREVIEW_PATH.glob("*.svg"))), 5)

    def test_preview_manifest_hashes_match_public_files(self):
        report_path = (
            ROOT
            / "research"
            / "milestones"
            / "m5"
            / "session098"
            / "offline-preview-renderer.json"
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for entry in report["preview_catalog"]["manifest"]:
            payload = (PREVIEW_PATH / f"{entry['screen_id']}.svg").read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["sha256"])


if __name__ == "__main__":
    unittest.main()

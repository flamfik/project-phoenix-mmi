import unittest

from phoenix_mmi.ui_playback import (
    DEFAULT_PLAYBACK_ACTIONS,
    run_ui_playback,
)


class UIPlaybackTests(unittest.TestCase):
    def test_default_playback_is_deterministic(self):
        self.assertEqual(run_ui_playback(), run_ui_playback())

    def test_default_playback_visits_every_screen(self):
        report = run_ui_playback()
        self.assertTrue(report["metrics"]["all_model_screens_visited"])
        self.assertEqual(report["metrics"]["visited_screen_count"], 5)
        self.assertEqual(
            {step["after"]["screen_id"] for step in report["steps"]},
            {"communication", "home", "media", "navigation", "settings"},
        )

    def test_steps_and_snapshots_match_actions(self):
        report = run_ui_playback()
        self.assertEqual(
            report["metrics"]["action_count"],
            len(DEFAULT_PLAYBACK_ACTIONS),
        )
        self.assertEqual(
            report["metrics"]["snapshot_count"],
            len(DEFAULT_PLAYBACK_ACTIONS),
        )
        self.assertEqual(
            [step["sequence"] for step in report["steps"]],
            list(range(1, len(DEFAULT_PLAYBACK_ACTIONS) + 1)),
        )
        self.assertTrue(report["metrics"]["sequence_monotonic"])

    def test_every_snapshot_has_stable_sha256(self):
        report = run_ui_playback()
        for step in report["steps"]:
            self.assertEqual(len(step["preview_sha256"]), 64)
            int(step["preview_sha256"], 16)
            self.assertGreater(step["preview_draw_commands"], 0)

    def test_final_home_state_is_known(self):
        report = run_ui_playback()
        self.assertEqual(report["final_state"]["screen_id"], "home")
        self.assertEqual(
            report["final_state"]["focused_entry_id"],
            "home.communication",
        )

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(ValueError):
            run_ui_playback(("ACTIVATE", "CAN_WRITE"))

    def test_empty_playback_is_valid_and_bounded(self):
        report = run_ui_playback(())
        self.assertEqual(report["metrics"]["action_count"], 0)
        self.assertEqual(report["metrics"]["snapshot_count"], 0)
        self.assertEqual(report["metrics"]["visited_screen_count"], 1)
        self.assertFalse(report["metrics"]["all_model_screens_visited"])

    def test_playback_requires_no_external_system(self):
        classification = run_ui_playback()["classification"]
        self.assertFalse(classification["service_dispatch"])
        self.assertFalse(classification["filesystem_required"])
        self.assertFalse(classification["network_required"])
        self.assertFalse(classification["vehicle_required"])
        self.assertFalse(classification["hardware_timing_claim"])

    def test_playback_is_publication_safe(self):
        safety = run_ui_playback()["publication_safety"]
        self.assertTrue(safety["original_or_synthetic_content_only"])
        for key, value in safety.items():
            if key.endswith("_included"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

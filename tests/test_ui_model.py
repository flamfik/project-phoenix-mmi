from dataclasses import replace
from pathlib import Path
import json
import unittest

from phoenix_mmi.ui_model import (
    DATA_SOURCES,
    UI_SCREEN_SCHEMA,
    build_phoenix_information_architecture,
    build_public_information_architecture,
    validate_information_architecture,
)
from phoenix_mmi.ui_prototype_audit import advance_m5_progress


ROOT = Path(__file__).resolve().parents[1]
M5_BASELINE = (
    ROOT
    / "research"
    / "milestones"
    / "m5"
    / "session093"
    / "m5-ui-prototype-baseline.json"
)


class UIModelTests(unittest.TestCase):
    def test_model_is_deterministic_and_valid(self):
        first = build_phoenix_information_architecture()
        second = build_phoenix_information_architecture()
        self.assertEqual(first, second)
        self.assertEqual(first.schema, UI_SCREEN_SCHEMA)
        validate_information_architecture(first)

    def test_model_has_one_root_and_four_sections(self):
        model = build_phoenix_information_architecture()
        self.assertEqual(model.root_screen_id, "home")
        self.assertEqual(len(model.screens), 5)
        self.assertEqual(model.screens[0].role, "ROOT")
        self.assertEqual(
            [screen.screen_id for screen in model.screens[1:]],
            ["communication", "media", "navigation", "settings"],
        )

    def test_public_topology_counts_are_stable(self):
        report = build_public_information_architecture()
        self.assertEqual(report["topology"]["screen_count"], 5)
        self.assertEqual(report["topology"]["entry_count"], 16)
        self.assertEqual(report["topology"]["focusable_entry_count"], 16)
        self.assertEqual(report["topology"]["navigation_edge_count"], 4)
        self.assertTrue(report["topology"]["all_screens_reachable"])
        self.assertTrue(report["topology"]["hierarchy_acyclic"])

    def test_tokens_are_original_namespaced_identifiers(self):
        model = build_phoenix_information_architecture()
        for screen in model.screens:
            self.assertTrue(screen.title_token.startswith("phoenix.screen."))
            for entry in screen.entries:
                self.assertTrue(entry.label_token.startswith("phoenix.entry."))

    def test_entries_have_no_service_binding(self):
        model = build_phoenix_information_architecture()
        for screen in model.screens:
            for entry in screen.entries:
                self.assertEqual(entry.service_binding, "NONE")
                self.assertIn(entry.data_source, DATA_SOURCES)

    def test_model_does_not_assign_layout_or_reducer(self):
        report = build_public_information_architecture()
        classification = report["classification"]
        self.assertFalse(classification["layout_geometry_assigned"])
        self.assertFalse(classification["interaction_reducer_implemented"])
        self.assertFalse(classification["firmware_menu_reconstruction"])
        for screen in report["screens"]:
            for entry in screen["entries"]:
                self.assertNotIn("x", entry)
                self.assertNotIn("y", entry)
                self.assertNotIn("width", entry)
                self.assertNotIn("height", entry)

    def test_validator_rejects_duplicate_screen(self):
        model = build_phoenix_information_architecture()
        invalid = replace(model, screens=model.screens + (model.screens[-1],))
        with self.assertRaises(ValueError):
            validate_information_architecture(invalid)

    def test_validator_rejects_unknown_navigation_target(self):
        model = build_phoenix_information_architecture()
        home = model.screens[0]
        bad_entry = replace(home.entries[0], target_screen_id="missing")
        invalid_home = replace(home, entries=(bad_entry,) + home.entries[1:])
        invalid = replace(model, screens=(invalid_home,) + model.screens[1:])
        with self.assertRaises(ValueError):
            validate_information_architecture(invalid)

    def test_validator_rejects_service_binding(self):
        model = build_phoenix_information_architecture()
        section = model.screens[1]
        bad_entry = replace(section.entries[0], service_binding="VEHICLE")
        invalid_section = replace(
            section, entries=(bad_entry,) + section.entries[1:]
        )
        invalid = replace(
            model, screens=(model.screens[0], invalid_section) + model.screens[2:]
        )
        with self.assertRaises(ValueError):
            validate_information_architecture(invalid)

    def test_validator_rejects_external_data_source(self):
        model = build_phoenix_information_architecture()
        section = model.screens[1]
        bad_entry = replace(section.entries[0], data_source="FIRMWARE")
        invalid_section = replace(
            section, entries=(bad_entry,) + section.entries[1:]
        )
        invalid = replace(
            model, screens=(model.screens[0], invalid_section) + model.screens[2:]
        )
        with self.assertRaises(ValueError):
            validate_information_architecture(invalid)

    def test_publication_safety_is_explicit(self):
        safety = build_public_information_architecture()["publication_safety"]
        self.assertTrue(safety["original_or_synthetic_content_only"])
        for key, value in safety.items():
            if key.endswith("_included"):
                self.assertFalse(value, key)


class Session094ProgressTests(unittest.TestCase):
    def test_information_architecture_advances_only_m5_x1(self):
        baseline = json.loads(M5_BASELINE.read_text(encoding="utf-8"))
        report = advance_m5_progress(
            ROOT,
            baseline,
            session="094",
            transitions=[
                {
                    "capability_id": "M5-CAP-010",
                    "from_status": "MISSING",
                    "to_status": "IMPLEMENTED",
                    "probe_kind": "python-symbol",
                    "probe_target": (
                        "phoenix_mmi.ui_model:"
                        "build_phoenix_information_architecture"
                    ),
                    "evidence": "Session 094 and SPEC-103",
                    "limitation": (
                        "original prototype model is not the firmware menu"
                    ),
                }
            ],
            graph_version="v86",
            graph_node_id="m5-information-architecture",
        )
        self.assertEqual(report["exit_criteria_passed"], 1)
        self.assertEqual(report["exit_criteria_total"], 8)
        self.assertEqual(report["operational_graph_version"], "v86")
        self.assertEqual(report["classification"]["m5_status"], "IN_PROGRESS")
        self.assertFalse(report["classification"]["safe_mutation_ready"])
        self.assertEqual(baseline["exit_criteria_passed"], 0)


if __name__ == "__main__":
    unittest.main()

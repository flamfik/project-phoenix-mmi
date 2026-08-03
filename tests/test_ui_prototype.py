from copy import deepcopy
from pathlib import Path
import json
import unittest

from phoenix_mmi.ui_constraints import (
    ABSTRACT_INPUT_ACTIONS,
    UI_CONSTRAINT_SCHEMA,
    build_ui_constraint_contract,
    validate_ui_constraint_contract,
)
from phoenix_mmi.ui_prototype_audit import (
    M5_CAPABILITIES,
    M5_EXIT_CRITERIA,
    advance_m5_progress,
    build_m5_baseline,
)


ROOT = Path(__file__).resolve().parents[1]
M4_CLOSURE = (
    ROOT
    / "research"
    / "milestones"
    / "m4"
    / "session092"
    / "milestone-m4-closure.json"
)


class UIConstraintTests(unittest.TestCase):
    def test_contract_is_deterministic_and_valid(self):
        first = build_ui_constraint_contract()
        second = build_ui_constraint_contract()
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], UI_CONSTRAINT_SCHEMA)
        validate_ui_constraint_contract(first)

    def test_viewport_is_fixed_without_hardware_overclaim(self):
        contract = build_ui_constraint_contract()
        self.assertEqual(
            (contract["viewport"]["width"], contract["viewport"]["height"]),
            (480, 240),
        )
        self.assertIn("does not establish", contract["viewport"]["limitation"])
        self.assertEqual(
            contract["classification"]["renderer_compatibility"],
            "NOT_ESTABLISHED",
        )

    def test_input_layer_is_abstract_focus_only(self):
        contract = build_ui_constraint_contract()
        self.assertEqual(
            tuple(contract["input"]["actions"]), ABSTRACT_INPUT_ACTIONS
        )
        self.assertTrue(contract["input"]["focus_required"])
        self.assertFalse(contract["input"]["pointer_required"])
        self.assertFalse(contract["input"]["touch_required"])
        self.assertEqual(
            contract["input"]["hardware_mapping_status"], "NOT_ESTABLISHED"
        )

    def test_asset_policy_accepts_only_original_or_synthetic(self):
        policy = build_ui_constraint_contract()["asset_policy"]
        self.assertEqual(policy["allowed_sources"], ["ORIGINAL", "SYNTHETIC"])
        self.assertFalse(policy["firmware_extracted_assets_allowed"])
        self.assertFalse(policy["navigation_media_assets_allowed"])

    def test_forbidden_authorizations_remain_false(self):
        authorization = build_ui_constraint_contract()["authorization"]
        self.assertFalse(authorization["firmware_execution"])
        self.assertFalse(authorization["firmware_resource_replacement"])
        self.assertFalse(authorization["firmware_repacking"])
        self.assertFalse(authorization["installable_artifact_generation"])
        self.assertFalse(authorization["vehicle_communication"])
        self.assertFalse(authorization["protected_service_emulation"])

    def test_validator_rejects_weakened_constraint(self):
        contract = build_ui_constraint_contract()
        contract["authorization"]["firmware_repacking"] = True
        with self.assertRaises(ValueError):
            validate_ui_constraint_contract(contract)

    def test_validator_rejects_missing_action_set(self):
        contract = build_ui_constraint_contract()
        contract["input"]["actions"] = None
        with self.assertRaises(ValueError):
            validate_ui_constraint_contract(contract)

    def test_hardware_budgets_remain_unknown(self):
        budget = build_ui_constraint_contract()["budget_policy"]
        self.assertEqual(budget["numeric_cpu_budget_status"], "NOT_ESTABLISHED")
        self.assertEqual(
            budget["numeric_memory_budget_status"], "NOT_ESTABLISHED"
        )
        self.assertIn("STATE_COUNT", budget["prototype_must_report"])


class UIPrototypeAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m4_closure = json.loads(M4_CLOSURE.read_text(encoding="utf-8"))

    def test_capability_and_criterion_ids_are_unique(self):
        capability_ids = [row.capability_id for row in M5_CAPABILITIES]
        criterion_ids = [row["criterion_id"] for row in M5_EXIT_CRITERIA]
        self.assertEqual(len(capability_ids), len(set(capability_ids)))
        self.assertEqual(len(criterion_ids), len(set(criterion_ids)))

    def test_baseline_passes_entry_but_not_exit(self):
        report = build_m5_baseline(ROOT, self.m4_closure)
        self.assertEqual(report["classification"]["m5_entry"], "PASS")
        self.assertEqual(report["classification"]["m5_status"], "IN_PROGRESS")
        self.assertEqual(report["exit_criteria_passed"], 0)
        self.assertEqual(report["exit_criteria_total"], 8)
        self.assertFalse(report["classification"]["safe_mutation_ready"])
        self.assertFalse(report["classification"]["installable_artifact_ready"])

    def test_baseline_capability_counts_and_probes_match(self):
        report = build_m5_baseline(ROOT, self.m4_closure)
        self.assertEqual(report["capability_audit"]["capability_count"], 17)
        self.assertEqual(
            report["capability_audit"]["status_counts"],
            {"BLOCKED": 4, "IMPLEMENTED": 2, "MISSING": 8, "PARTIAL": 3},
        )
        self.assertTrue(report["capability_audit"]["probe_integrity"])

    def test_backlog_is_sessions_094_through_101(self):
        report = build_m5_baseline(ROOT, self.m4_closure)
        self.assertEqual(
            [row["session"] for row in report["ordered_session_backlog"]],
            [f"{value:03d}" for value in range(94, 102)],
        )

    def test_entry_rejects_incomplete_m4(self):
        closure = deepcopy(self.m4_closure)
        closure["classification"]["m4_status"] = "IN_PROGRESS"
        with self.assertRaises(ValueError):
            build_m5_baseline(ROOT, closure)

    def test_entry_rejects_scope_expansion(self):
        closure = deepcopy(self.m4_closure)
        closure["milestone_transition"]["m5_authorized_scope"] = (
            "firmware integration"
        )
        with self.assertRaises(ValueError):
            build_m5_baseline(ROOT, closure)

    def test_progress_advances_only_explicit_capability(self):
        baseline = build_m5_baseline(ROOT, self.m4_closure)
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
                        "phoenix_mmi.ui_constraints:"
                        "validate_ui_constraint_contract"
                    ),
                    "evidence": "synthetic test transition",
                    "limitation": "not a production screen schema",
                }
            ],
            graph_version="v86",
            graph_node_id="m5-test-transition",
        )
        self.assertEqual(report["exit_criteria_passed"], 1)
        self.assertEqual(report["classification"]["m5_status"], "IN_PROGRESS")
        baseline_row = next(
            row
            for row in baseline["capability_audit"]["capabilities"]
            if row["capability_id"] == "M5-CAP-010"
        )
        self.assertEqual(baseline_row["status"], "MISSING")

    def test_progress_rejects_stale_transition(self):
        baseline = build_m5_baseline(ROOT, self.m4_closure)
        transition = {
            "capability_id": "M5-CAP-010",
            "from_status": "IMPLEMENTED",
            "to_status": "IMPLEMENTED",
            "probe_kind": "python-symbol",
            "probe_target": (
                "phoenix_mmi.ui_constraints:validate_ui_constraint_contract"
            ),
            "evidence": "invalid stale transition",
            "limitation": "none",
        }
        with self.assertRaises(ValueError):
            advance_m5_progress(
                ROOT,
                baseline,
                session="094",
                transitions=[transition],
                graph_version="v86",
                graph_node_id="invalid",
            )

    def test_publication_safety_is_explicit(self):
        report = build_m5_baseline(ROOT, self.m4_closure)
        safety = report["publication_safety"]
        self.assertTrue(safety["original_or_synthetic_assets_only"])
        self.assertTrue(safety["offline_only"])
        for key, value in safety.items():
            if key.endswith("_included") or key.endswith("_performed"):
                self.assertFalse(value, key)


if __name__ == "__main__":
    unittest.main()

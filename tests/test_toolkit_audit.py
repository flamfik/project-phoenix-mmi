from pathlib import Path
import unittest

from phoenix_mmi.toolkit_audit import (
    CAPABILITIES,
    EXIT_CRITERIA,
    audit_toolkit_capabilities,
    advance_m2_progress,
    build_m2_foundation_report,
)


ROOT = Path(__file__).resolve().parents[1]


def m1_closure():
    return {
        "schema": "phoenix-mmi.milestone-m1-closure/v1",
        "classification": {
            "milestone_m1": "COMPLETE",
            "safe_mutation_ready": False,
        },
    }


class ToolkitAuditTests(unittest.TestCase):
    def test_capability_and_criterion_ids_are_unique(self):
        capability_ids = [
            capability.capability_id for capability in CAPABILITIES
        ]
        criterion_ids = [
            criterion["criterion_id"] for criterion in EXIT_CRITERIA
        ]
        self.assertEqual(len(capability_ids), len(set(capability_ids)))
        self.assertEqual(len(criterion_ids), len(set(criterion_ids)))

    def test_every_exit_capability_and_target_session_is_declared(self):
        capability_ids = {
            capability.capability_id for capability in CAPABILITIES
        }
        sessions = []
        for criterion in EXIT_CRITERIA:
            self.assertTrue(
                set(criterion["required_capabilities"])
                <= capability_ids
            )
            sessions.append(criterion["target_session"])
        self.assertEqual(
            sessions,
            ["067", "068", "069", "070", "071", "072", "073", "074"],
        )

    def test_repository_capability_probes_match_declarations(self):
        report = audit_toolkit_capabilities(ROOT)
        self.assertEqual(report["capability_count"], 27)
        self.assertTrue(report["probe_integrity"])
        self.assertEqual(
            report["status_counts"],
            {
                "BLOCKED": 2,
                "IMPLEMENTED": 8,
                "MISSING": 9,
                "PARTIAL": 8,
            },
        )

    def test_m2_foundation_passes_entry_but_not_exit(self):
        report = build_m2_foundation_report(ROOT, m1_closure())
        self.assertEqual(report["classification"]["m2_entry"], "PASS")
        self.assertEqual(
            report["classification"]["m2_status"], "IN_PROGRESS"
        )
        self.assertEqual(report["exit_criteria_passed"], 0)
        self.assertEqual(report["exit_criteria_total"], 8)
        self.assertFalse(
            report["classification"]["safe_mutation_ready"]
        )
        self.assertEqual(report["operational_graph_version"], "v58")

    def test_m2_entry_rejects_open_m1_or_enabled_mutation(self):
        open_m1 = m1_closure()
        open_m1["classification"]["milestone_m1"] = "BLOCKED"
        with self.assertRaises(ValueError):
            build_m2_foundation_report(ROOT, open_m1)

        unsafe = m1_closure()
        unsafe["classification"]["safe_mutation_ready"] = True
        with self.assertRaises(ValueError):
            build_m2_foundation_report(ROOT, unsafe)

    def test_report_is_publication_safe(self):
        report = build_m2_foundation_report(ROOT, m1_closure())
        safety = report["publication_safety"]
        self.assertTrue(all(value is False for value in safety.values()))
        self.assertNotIn(str(ROOT), str(report))

    def test_session_progress_advances_without_mutating_baseline(self):
        baseline = build_m2_foundation_report(ROOT, m1_closure())
        progress = advance_m2_progress(
            ROOT,
            baseline,
            session="067",
            transitions=[
                {
                    "capability_id": "M2-CAP-023",
                    "from_status": "MISSING",
                    "to_status": "IMPLEMENTED",
                    "probe_kind": "python-symbol",
                    "probe_target": (
                        "phoenix_mmi.manifest:ArtifactManifest"
                    ),
                    "evidence": "fixture",
                    "limitation": "read-only fixture",
                }
            ],
            graph_version="v59",
            graph_node_id="fixture-manifest",
        )
        self.assertEqual(progress["exit_criteria_passed"], 1)
        self.assertTrue(progress["exit_criteria"][0]["passed"])
        self.assertTrue(
            all(
                not row["passed"]
                for row in progress["exit_criteria"][1:]
            )
        )
        self.assertEqual(
            baseline["capability_audit"]["status_counts"]["MISSING"],
            9,
        )
        self.assertEqual(
            progress["capability_audit"]["status_counts"],
            {
                "BLOCKED": 2,
                "IMPLEMENTED": 9,
                "MISSING": 8,
                "PARTIAL": 8,
            },
        )

    def test_progress_rejects_stale_or_duplicate_transition(self):
        baseline = build_m2_foundation_report(ROOT, m1_closure())
        transition = {
            "capability_id": "M2-CAP-023",
            "from_status": "IMPLEMENTED",
            "to_status": "IMPLEMENTED",
            "probe_kind": "python-symbol",
            "probe_target": "phoenix_mmi.manifest:ArtifactManifest",
            "evidence": "fixture",
            "limitation": "fixture",
        }
        with self.assertRaises(ValueError):
            advance_m2_progress(
                ROOT,
                baseline,
                session="067",
                transitions=[transition],
                graph_version="v59",
                graph_node_id="fixture",
            )


if __name__ == "__main__":
    unittest.main()

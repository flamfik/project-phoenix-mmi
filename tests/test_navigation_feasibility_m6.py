from copy import deepcopy
import json
from pathlib import Path
import unittest

from phoenix_mmi.navigation_boundaries import (
    build_navigation_boundary_graph,
    validate_navigation_boundary_graph,
)
from phoenix_mmi.navigation_evidence import (
    build_navigation_evidence_ledger,
    validate_navigation_evidence_ledger,
)
from phoenix_mmi.navigation_feasibility_audit import (
    M6_CAPABILITIES,
    M6_EXIT_CRITERIA,
    advance_m6_progress,
    build_m6_baseline,
)
from phoenix_mmi.navigation_feasibility_contract import (
    build_navigation_feasibility_contract,
    validate_navigation_feasibility_contract,
)
from phoenix_mmi.navigation_knowledge import (
    build_navigation_knowledge_matrix,
    validate_navigation_knowledge_matrix,
)
from phoenix_mmi.navigation_provenance import (
    NavigationSource,
    build_navigation_provenance_policy,
    validate_navigation_provenance_policy,
    validate_navigation_source,
)


ROOT = Path(__file__).resolve().parents[1]
M5_CLOSURE = (
    ROOT
    / "research"
    / "milestones"
    / "m5"
    / "session101"
    / "milestone-m5-closure.json"
)


class NavigationFeasibilityContractTests(unittest.TestCase):
    def test_contract_is_deterministic_and_valid(self):
        first = build_navigation_feasibility_contract()
        second = build_navigation_feasibility_contract()
        self.assertEqual(first, second)
        validate_navigation_feasibility_contract(first)

    def test_contract_keeps_target_generation_blocked(self):
        contract = build_navigation_feasibility_contract()
        operations = contract["authorized_operations"]
        self.assertFalse(operations["generate_proprietary_map_payloads"])
        self.assertFalse(operations["synthesize_unknown_integrity_fields"])
        self.assertFalse(operations["repack_navigation_media"])
        self.assertFalse(operations["generate_installable_media"])
        self.assertFalse(operations["communicate_with_vehicle"])

    def test_osm_policy_requires_attribution_and_snapshot_identity(self):
        policy = build_navigation_feasibility_contract()["osm_policy"]
        self.assertEqual(policy["data_license"], "ODbL-1.0")
        self.assertTrue(policy["attribution_required"])
        self.assertTrue(policy["source_snapshot_required"])
        self.assertTrue(policy["source_hash_required"])
        self.assertFalse(policy["legal_advice_provided"])

    def test_validator_rejects_enabled_target_generation(self):
        contract = build_navigation_feasibility_contract()
        contract["authorized_operations"][
            "generate_proprietary_map_payloads"
        ] = True
        with self.assertRaises(ValueError):
            validate_navigation_feasibility_contract(contract)


class NavigationFeasibilityAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m5_closure = json.loads(M5_CLOSURE.read_text(encoding="utf-8"))

    def test_capability_and_criterion_ids_are_unique(self):
        capabilities = [row.capability_id for row in M6_CAPABILITIES]
        criteria = [row["criterion_id"] for row in M6_EXIT_CRITERIA]
        self.assertEqual(len(capabilities), len(set(capabilities)))
        self.assertEqual(len(criteria), len(set(criteria)))

    def test_baseline_passes_entry_but_not_exit(self):
        report = build_m6_baseline(ROOT, self.m5_closure)
        self.assertEqual(report["classification"]["m6_entry"], "PASS")
        self.assertEqual(report["classification"]["m6_status"], "IN_PROGRESS")
        self.assertEqual(report["exit_criteria_passed"], 0)
        self.assertEqual(report["exit_criteria_total"], 8)
        self.assertFalse(report["classification"]["safe_mutation_ready"])

    def test_baseline_capabilities_and_probes_match(self):
        report = build_m6_baseline(ROOT, self.m5_closure)
        self.assertEqual(report["capability_audit"]["capability_count"], 17)
        self.assertEqual(
            report["capability_audit"]["status_counts"],
            {"BLOCKED": 4, "IMPLEMENTED": 2, "MISSING": 8, "PARTIAL": 3},
        )
        self.assertTrue(report["capability_audit"]["probe_integrity"])

    def test_backlog_is_sessions_103_through_110(self):
        report = build_m6_baseline(ROOT, self.m5_closure)
        self.assertEqual(
            [row["session"] for row in report["ordered_session_backlog"]],
            [f"{value:03d}" for value in range(103, 111)],
        )

    def test_entry_rejects_scope_expansion(self):
        closure = deepcopy(self.m5_closure)
        closure["milestone_transition"]["m6_authorized_scope"] = (
            "install navigation media"
        )
        with self.assertRaises(ValueError):
            build_m6_baseline(ROOT, closure)

    def test_progress_advances_only_explicit_capability(self):
        baseline = build_m6_baseline(ROOT, self.m5_closure)
        report = advance_m6_progress(
            ROOT,
            baseline,
            session="103",
            transitions=[
                {
                    "capability_id": "M6-CAP-010",
                    "from_status": "MISSING",
                    "to_status": "IMPLEMENTED",
                    "probe_kind": "python-symbol",
                    "probe_target": (
                        "phoenix_mmi.navigation_evidence:"
                        "build_navigation_evidence_ledger"
                    ),
                    "evidence": "synthetic transition",
                    "limitation": "test only",
                }
            ],
            graph_version="v95",
            graph_node_id="m6-test",
        )
        self.assertEqual(report["exit_criteria_passed"], 1)
        self.assertEqual(report["classification"]["m6_status"], "IN_PROGRESS")
        self.assertEqual(baseline["exit_criteria_passed"], 0)


class NavigationEvidenceAndBoundaryTests(unittest.TestCase):
    def test_evidence_ledger_reproduces_registered_structure(self):
        ledger = build_navigation_evidence_ledger(ROOT)
        validate_navigation_evidence_ledger(ledger)
        self.assertEqual(ledger["structural_summary"]["root_file_count"], 7)
        self.assertEqual(
            ledger["structural_summary"]["internal_record_count"], 3599
        )
        self.assertEqual(ledger["structural_summary"]["partition_count"], 16)

    def test_evidence_ledger_is_deterministic(self):
        self.assertEqual(
            build_navigation_evidence_ledger(ROOT),
            build_navigation_evidence_ledger(ROOT),
        )

    def test_evidence_ledger_does_not_claim_local_rehash(self):
        ledger = build_navigation_evidence_ledger(ROOT)
        self.assertFalse(ledger["classification"]["local_media_rehash_claimed"])
        self.assertFalse(
            ledger["publication_safety"]["navigation_media_content_included"]
        )

    def test_knowledge_matrix_keeps_writer_and_integrity_open(self):
        matrix = build_navigation_knowledge_matrix(
            build_navigation_evidence_ledger(ROOT)
        )
        validate_navigation_knowledge_matrix(matrix)
        by_id = {row["knowledge_id"]: row for row in matrix["rows"]}
        self.assertEqual(by_id["proprietary-write-model"]["status"], "OPEN")
        self.assertEqual(
            by_id["proprietary-integrity-model"]["status"], "OPEN"
        )
        self.assertFalse(matrix["direct_replacement_gate"]["passed"])

    def test_boundary_graph_has_no_confirmed_runtime_path(self):
        matrix = build_navigation_knowledge_matrix(
            build_navigation_evidence_ledger(ROOT)
        )
        graph = build_navigation_boundary_graph(matrix)
        validate_navigation_boundary_graph(graph)
        self.assertFalse(
            graph["metrics"]["confirmed_media_to_runtime_path"]
        )
        self.assertEqual(
            graph["classification"]["direct_runtime_bridge"], "NOT_CONFIRMED"
        )


class NavigationProvenanceTests(unittest.TestCase):
    def test_policy_is_deterministic_and_not_legal_advice(self):
        first = build_navigation_provenance_policy()
        second = build_navigation_provenance_policy()
        self.assertEqual(first, second)
        validate_navigation_provenance_policy(first)
        self.assertFalse(first["classification"]["policy_is_legal_advice"])

    def test_osm_source_requires_odbl_attribution(self):
        valid = NavigationSource(
            "osm-test",
            "OPENSTREETMAP",
            "ODbL-1.0",
            "OpenStreetMap contributors",
            "https://example.invalid/extract.osm",
            "0" * 64,
        )
        validate_navigation_source(valid)
        invalid = NavigationSource(
            "osm-test",
            "OPENSTREETMAP",
            "UNKNOWN",
            "",
            "https://example.invalid/extract.osm",
            "0" * 64,
        )
        with self.assertRaises(ValueError):
            validate_navigation_source(invalid)

    def test_policy_contains_official_reference_urls(self):
        urls = {
            row["url"]
            for row in build_navigation_provenance_policy()[
                "authoritative_references"
            ]
        }
        self.assertIn("https://www.openstreetmap.org/copyright", urls)
        self.assertIn("https://wiki.openstreetmap.org/wiki/OSM_XML", urls)


if __name__ == "__main__":
    unittest.main()

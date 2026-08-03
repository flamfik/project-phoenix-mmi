import json
from pathlib import Path
import unittest

from phoenix_mmi.bench_evidence import (
    build_bench_evidence_template,
    evaluate_bench_evidence_bundle,
)


class BenchEvidenceTests(unittest.TestCase):
    def test_committed_template_matches_sdk_builder(self):
        root = Path(__file__).resolve().parents[1]
        path = (
            root
            / "docs/templates/SESSION-120-private-bench-evidence.template.json"
        )
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8")),
            build_bench_evidence_template(),
        )

    def test_empty_template_fails_closed(self):
        summary = evaluate_bench_evidence_bundle(
            build_bench_evidence_template()
        )
        self.assertEqual(
            summary["classification"]["m7_physical_gate"], "BLOCKED"
        )
        self.assertFalse(summary["summary"]["physical_claim_ready"])
        self.assertGreater(len(summary["summary"]["blockers"]), 0)

    def test_invalid_capture_hash_is_rejected(self):
        bundle = build_bench_evidence_template()
        bundle["private_capture_sha256"] = ["not-a-hash"]
        with self.assertRaises(ValueError):
            evaluate_bench_evidence_bundle(bundle)

    def test_unknown_evidence_kind_is_rejected(self):
        bundle = build_bench_evidence_template()
        bundle["evidence_kind"] = "UNVERIFIED"
        with self.assertRaises(ValueError):
            evaluate_bench_evidence_bundle(bundle)

    def test_unknown_field_is_rejected(self):
        bundle = build_bench_evidence_template()
        bundle["unreviewed_extension"] = True
        with self.assertRaises(ValueError):
            evaluate_bench_evidence_bundle(bundle)

    def test_complete_private_metadata_can_pass_validator(self):
        bundle = build_bench_evidence_template()
        bundle["prerequisites"] = {
            key: True for key in bundle["prerequisites"]
        }
        bundle["observation"].update(
            {
                "physical_observation_performed": True,
                "safe_shutdown_confirmed": True,
            }
        )
        bundle["private_capture_sha256"] = ["a" * 64]
        bundle["approval_record_sha256"] = "b" * 64
        summary = evaluate_bench_evidence_bundle(bundle)
        self.assertEqual(
            summary["classification"]["m7_physical_gate"], "PASS"
        )
        self.assertTrue(summary["summary"]["physical_claim_ready"])
        self.assertNotIn("a" * 64, repr(summary))

    def test_incomplete_stop_response_blocks_claim(self):
        bundle = build_bench_evidence_template()
        bundle["prerequisites"] = {
            key: True for key in bundle["prerequisites"]
        }
        bundle["observation"].update(
            {
                "physical_observation_performed": True,
                "safe_shutdown_confirmed": True,
                "stop_condition_triggered": True,
                "stop_response_completed": False,
            }
        )
        bundle["private_capture_sha256"] = ["a" * 64]
        bundle["approval_record_sha256"] = "b" * 64
        summary = evaluate_bench_evidence_bundle(bundle)
        self.assertEqual(
            summary["classification"]["m7_physical_gate"], "BLOCKED"
        )
        self.assertIn(
            "stop_response_incomplete", summary["summary"]["blockers"]
        )
        self.assertIn(
            "incident_record_hash_absent", summary["summary"]["blockers"]
        )

    def test_triggered_stop_requires_incident_record_hash(self):
        bundle = build_bench_evidence_template()
        bundle["prerequisites"] = {
            key: True for key in bundle["prerequisites"]
        }
        bundle["observation"] = {
            "physical_observation_performed": True,
            "safe_shutdown_confirmed": True,
            "stop_condition_triggered": True,
            "stop_response_completed": True,
        }
        bundle["private_capture_sha256"] = ["a" * 64]
        bundle["approval_record_sha256"] = "b" * 64
        blocked = evaluate_bench_evidence_bundle(bundle)
        self.assertIn(
            "incident_record_hash_absent", blocked["summary"]["blockers"]
        )
        bundle["incident_record_sha256"] = "d" * 64
        accepted = evaluate_bench_evidence_bundle(bundle)
        self.assertEqual(
            accepted["classification"]["m7_physical_gate"], "PASS"
        )

    def test_public_summary_contains_no_private_hash_values(self):
        bundle = build_bench_evidence_template()
        bundle["private_capture_sha256"] = ["c" * 64]
        summary = evaluate_bench_evidence_bundle(bundle)
        self.assertNotIn("c" * 64, repr(summary))
        self.assertFalse(
            summary["publication_safety"]["private_hash_values_included"]
        )


if __name__ == "__main__":
    unittest.main()

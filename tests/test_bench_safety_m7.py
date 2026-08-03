import unittest

from phoenix_mmi.bench_manifest import (
    build_bench_manifest_template,
    build_public_bench_manifest_summary,
    validate_bench_manifest,
)
from phoenix_mmi.bench_observation import (
    build_bench_observation_contract,
    validate_bench_observation_contract,
)
from phoenix_mmi.bench_power import (
    build_bench_power_plan,
    validate_bench_power_plan,
)
from phoenix_mmi.bench_recovery import (
    build_bench_recovery_plan,
    validate_bench_recovery_plan,
)
from phoenix_mmi.bench_risk import (
    bench_risk_fingerprint,
    build_bench_risk_register,
    validate_bench_risk_register,
)


class BenchSafetyModelTests(unittest.TestCase):
    def test_empty_manifest_summary_contains_no_values(self):
        manifest = build_bench_manifest_template()
        summary = build_public_bench_manifest_summary(manifest)
        self.assertFalse(summary["complete"])
        self.assertFalse(
            summary["publication_safety"]["raw_identity_values_included"]
        )
        serialized = repr(summary)
        for value in manifest["identity"].values():
            if value is not None:
                self.assertNotIn(value, serialized)

    def test_complete_private_manifest_publishes_only_aggregate(self):
        manifest = build_bench_manifest_template()
        manifest["identity"] = {
            key: f"private-{index}"
            for index, key in enumerate(manifest["identity"], start=1)
        }
        for section in (
            "isolation_assertions",
            "source_documents",
            "operator_review",
        ):
            manifest[section] = {
                key: True for key in manifest[section]
            }
        validate_bench_manifest(manifest, require_complete=True)
        summary = build_public_bench_manifest_summary(manifest)
        self.assertTrue(summary["complete"])
        for value in manifest["identity"].values():
            self.assertNotIn(value, repr(summary))

    def test_manifest_rejects_unknown_identity_field(self):
        manifest = build_bench_manifest_template()
        manifest["identity"]["unexpected"] = "value"
        with self.assertRaises(ValueError):
            validate_bench_manifest(manifest, require_complete=False)

    def test_power_plan_refuses_guessed_values(self):
        plan = build_bench_power_plan()
        plan["device_specific_values"]["nominal_voltage"] = "12"
        with self.assertRaises(ValueError):
            validate_bench_power_plan(plan)

    def test_power_plan_requires_independent_cutoff(self):
        plan = build_bench_power_plan()
        plan["required_controls"].remove("INDEPENDENT_OPERATOR_POWER_CUTOFF")
        with self.assertRaises(ValueError):
            validate_bench_power_plan(plan)

    def test_recovery_plan_contains_no_write_recovery(self):
        plan = build_bench_recovery_plan()
        self.assertIn("NO_FIRMWARE_REFLASH", plan["explicit_non_recovery"])
        self.assertFalse(
            plan["classification"]["target_write_recovery_available"]
        )

    def test_recovery_plan_rejects_incomplete_rehearsal(self):
        plan = build_bench_recovery_plan()
        plan["rehearsal_requirements"]["dummy_load_only"] = False
        with self.assertRaises(ValueError):
            validate_bench_recovery_plan(plan)

    def test_observation_contract_denies_active_probe(self):
        contract = build_bench_observation_contract()
        self.assertIn(
            "ACTIVE_DIAGNOSTIC_PROBING", contract["never_allowed"]
        )
        contract["never_allowed"].remove("ACTIVE_DIAGNOSTIC_PROBING")
        with self.assertRaises(ValueError):
            validate_bench_observation_contract(contract)

    def test_risk_register_is_fixed_and_unsigned(self):
        register = build_bench_risk_register()
        self.assertEqual(register["summary"]["risk_count"], 8)
        self.assertFalse(register["summary"]["signed_review_complete"])
        self.assertFalse(
            register["classification"]["bench_observation_authorized"]
        )

    def test_risk_fingerprint_is_deterministic(self):
        first = build_bench_risk_register()
        second = build_bench_risk_register()
        self.assertEqual(
            bench_risk_fingerprint(first),
            bench_risk_fingerprint(second),
        )

    def test_risk_register_rejects_false_score(self):
        register = build_bench_risk_register()
        register["risks"][0]["residual_score"] += 1
        with self.assertRaises(ValueError):
            validate_bench_risk_register(register)


if __name__ == "__main__":
    unittest.main()

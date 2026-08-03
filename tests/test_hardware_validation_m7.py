import json
from pathlib import Path
import unittest

from phoenix_mmi.hardware_validation_audit import (
    M7_CAPABILITIES,
    M7_EXIT_CRITERIA,
    build_m7_baseline,
)
from phoenix_mmi.hardware_validation_contract import (
    build_hardware_validation_contract,
    validate_hardware_validation_contract,
)


ROOT = Path(__file__).resolve().parents[1]
M6_CLOSURE = (
    ROOT
    / "research/milestones/m6/session110/milestone-m6-closure.json"
)


class HardwareValidationContractTests(unittest.TestCase):
    def test_contract_is_fail_closed(self):
        contract = build_hardware_validation_contract()
        self.assertFalse(
            contract["classification"][
                "physical_bench_observation_authorized_now"
            ]
        )
        self.assertFalse(
            contract["classification"]["vehicle_operations_authorized"]
        )
        self.assertFalse(
            contract["sdk_authorized_operations"]["power_hardware"]
        )
        self.assertFalse(
            contract["sdk_authorized_operations"]["write_target_storage"]
        )

    def test_contract_has_ten_external_prerequisites(self):
        contract = build_hardware_validation_contract()
        self.assertEqual(
            len(contract["external_bench_candidate"]["prerequisites"]),
            10,
        )

    def test_contract_rejects_hardware_power_authorization(self):
        contract = build_hardware_validation_contract()
        contract["sdk_authorized_operations"]["power_hardware"] = True
        with self.assertRaises(ValueError):
            validate_hardware_validation_contract(contract)

    def test_contract_rejects_physical_claim_without_evidence(self):
        contract = build_hardware_validation_contract()
        contract["evidence_policy"][
            "physical_claim_without_evidence_allowed"
        ] = True
        with self.assertRaises(ValueError):
            validate_hardware_validation_contract(contract)

    def test_baseline_requires_complete_m6(self):
        closure = json.loads(M6_CLOSURE.read_text(encoding="utf-8"))
        closure["classification"]["m6_status"] = "IN_PROGRESS"
        with self.assertRaises(ValueError):
            build_m7_baseline(ROOT, closure)

    def test_baseline_is_deterministic_and_blocked_physically(self):
        closure = json.loads(M6_CLOSURE.read_text(encoding="utf-8"))
        first = build_m7_baseline(ROOT, closure)
        second = build_m7_baseline(ROOT, closure)
        self.assertEqual(first, second)
        self.assertEqual(first["session"], "111")
        self.assertEqual(first["operational_graph_version"], "v103")
        self.assertEqual(first["exit_criteria_passed"], 0)
        self.assertEqual(first["exit_criteria_total"], 9)
        self.assertFalse(
            first["classification"]["physical_bench_validation_performed"]
        )

    def test_registry_has_eight_preparation_and_one_physical_criterion(self):
        self.assertEqual(len(M7_CAPABILITIES), 10)
        self.assertEqual(len(M7_EXIT_CRITERIA), 9)
        self.assertEqual(
            [row["target_session"] for row in M7_EXIT_CRITERIA],
            [str(value) for value in range(112, 121)],
        )


if __name__ == "__main__":
    unittest.main()

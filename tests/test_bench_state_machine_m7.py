import unittest

from phoenix_mmi.bench_state_machine import (
    BenchState,
    run_synthetic_bench_rehearsal,
    transition_bench_state,
    validate_bench_state,
)


class BenchStateMachineTests(unittest.TestCase):
    def test_rehearsal_is_deterministic(self):
        self.assertEqual(
            run_synthetic_bench_rehearsal(),
            run_synthetic_bench_rehearsal(),
        )

    def test_normal_and_abort_paths_pass(self):
        report = run_synthetic_bench_rehearsal()
        self.assertTrue(report["passed"])
        self.assertEqual(
            report["normal_path"]["terminal_state"], "EVIDENCE_SEALED"
        )
        self.assertEqual(
            report["abort_path"]["terminal_state"], "ABORT_LOCKED"
        )
        self.assertFalse(
            report["abort_path"]["power_candidate_after_abort"]
        )

    def test_invalid_transition_fails(self):
        with self.assertRaises(ValueError):
            transition_bench_state(BenchState(), "AUTHORIZE_POWER")

    def test_abort_cannot_start_from_draft(self):
        with self.assertRaises(ValueError):
            transition_bench_state(BenchState(), "ABORT")

    def test_terminal_state_cannot_transition(self):
        state = BenchState(
            state="ABORT_LOCKED",
            sequence=1,
            evidence_sealed=True,
            aborted=True,
        )
        with self.assertRaises(ValueError):
            transition_bench_state(state, "VERIFY_IDENTITY")

    def test_state_invariant_rejects_false_power_candidate(self):
        with self.assertRaises(ValueError):
            validate_bench_state(
                BenchState(
                    state="OBSERVING",
                    sequence=7,
                    power_candidate=False,
                )
            )

    def test_rehearsal_never_claims_hardware(self):
        report = run_synthetic_bench_rehearsal()
        self.assertFalse(report["classification"]["hardware_controller"])
        self.assertFalse(report["classification"]["hardware_powered"])
        self.assertFalse(
            report["classification"]["physical_validation_performed"]
        )


if __name__ == "__main__":
    unittest.main()

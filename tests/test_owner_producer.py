from __future__ import annotations

import unittest

from phoenix_mmi.owner_producer import (
    _argument_definition_profile,
    _correlate_candidate_families,
    _roots_available,
    _verify_session021_registry,
    build_public_owner_producer_report,
    update_operational_graph_v18,
)
from phoenix_mmi.superh import SHInstruction


def _contract(target: str, r4: str, r6: str) -> dict[str, object]:
    return {
        "target_expression": {
            "canonical": target,
            "load_path": [{"width_bits": 32, "displacement": 28}],
        },
        "arguments": {
            "r4": {
                "canonical": r4,
                "load_path": [],
                "root_classes": ["ENTRY:r4"],
            },
            "r6": {
                "canonical": r6,
                "load_path": [],
                "root_classes": ["CONSTANT"],
            },
        },
        "gates": {"available_r4_r6_provenance": True},
    }


class OwnerProducerTests(unittest.TestCase):
    def test_delay_slot_definition_is_after_last_prior_call(self):
        instructions = [
            SHInstruction(
                0x100,
                "jsr",
                "@r1",
                flow="indirect-call",
                delayed=True,
            ),
            SHInstruction(0x102, "nop", ""),
            SHInstruction(0x104, "mov", "#0,r6"),
            SHInstruction(
                0x106,
                "jsr",
                "@r2",
                flow="indirect-call",
                delayed=True,
            ),
            SHInstruction(0x108, "mov", "r8,r4"),
        ]

        r4 = _argument_definition_profile(instructions, 3, 4)
        r6 = _argument_definition_profile(instructions, 3, 6)

        self.assertTrue(r4["definition_after_last_preceding_call"])
        self.assertTrue(r4["definition_in_current_call_delay_slot"])
        self.assertTrue(r6["definition_after_last_preceding_call"])
        self.assertEqual(r6["definition_file_offset"], 0x104)

    def test_argument_roots_reject_undefined_and_clobbered(self):
        self.assertFalse(_roots_available(["NO_DEFINITION", "CONSTANT"]))
        self.assertFalse(_roots_available(["CALLER_SAVED_CLOBBER"]))
        self.assertTrue(_roots_available(["ENTRY:r7"]))
        self.assertTrue(_roots_available(["CONSTANT"]))

    def test_registry_verification_requires_all_counts(self):
        current = {
            "active_pointer_zero_target_count": 3,
            "active_pointer_zero_call_count": 4,
            "prologue_code_gated_owner_count": 2,
            "exact_prologue_owner_shape_count": 1,
        }
        check = _verify_session021_registry(current, dict(current))
        self.assertTrue(check["all_registered_counts_equal"])

        changed = dict(current)
        changed["active_pointer_zero_call_count"] = 5
        check = _verify_session021_registry(current, changed)
        self.assertFalse(check["all_registered_counts_equal"])

    def test_equal_available_paths_promote_candidate(self):
        key = ("shape", 21)
        contract = _contract("LOAD32[28](ENTRY:r4)", "ENTRY:r4", "CONST:0")
        rows = _correlate_candidate_families(
            {key: [contract]},
            {key: [contract]},
            {key: [contract]},
            {key: [contract]},
        )

        self.assertTrue(rows[0]["argument_compatible_candidate_promoted"])
        self.assertEqual(
            rows[0]["classification"],
            "CONFIRMED_BILATERAL_ARGUMENT_COMPATIBLE_CANDIDATE",
        )

    def test_mismatched_or_unavailable_paths_do_not_promote(self):
        key = ("shape", 21)
        left = _contract("LOAD32[28](ENTRY:r4)", "ENTRY:r4", "CONST:0")
        right = _contract("LOAD32[28](ENTRY:r4)", "ENTRY:r4", "CONST:1")
        mismatch = _correlate_candidate_families(
            {key: [left]}, {key: [right]}, {key: [left]}, {key: [right]}
        )
        self.assertFalse(
            mismatch[0]["argument_compatible_candidate_promoted"]
        )

        unavailable = _correlate_candidate_families(
            {key: [left]}, {key: [left]}, {}, {}
        )
        self.assertEqual(
            unavailable[0]["classification"],
            "REJECTED_UNAVAILABLE_ARGUMENT_PROVENANCE",
        )

    def test_graph_and_public_copy_keep_target_link_open(self):
        comparison = {
            "classification": {
                "bilateral_argument_compatible_candidate_family_count": 4,
                "selected_owner_target_link": "NOT_ESTABLISHED",
                "owner_entry_argument_producer": (
                    "PARTIAL_ARGUMENT_COMPATIBLE_CANDIDATES_ONLY"
                ),
            },
            "interpretation": "four candidates, target open",
        }
        graph = update_operational_graph_v18(
            {
                "schema": "phoenix-mmi.operational-graph/v17",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )

        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v18")
        self.assertEqual(graph["edges"][0]["status"], "OPEN_TARGET_LINK")
        public = build_public_owner_producer_report(graph)
        public["nodes"][0]["status"] = "changed"
        self.assertEqual(
            graph["nodes"][0]["status"],
            "CONFIRMED_STRUCTURAL_CANDIDATES",
        )


if __name__ == "__main__":
    unittest.main()

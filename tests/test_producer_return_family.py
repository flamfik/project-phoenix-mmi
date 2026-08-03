from __future__ import annotations

import unittest

from phoenix_mmi.producer_return_family import (
    _entry_register_profile,
    _flow_signature,
    _next_linear_call_index,
    _pair_flow_contracts,
    _register_access,
    build_public_producer_return_report,
    update_operational_graph_v20,
)
from phoenix_mmi.superh import SHInstruction


def _expression(canonical: str) -> dict[str, object]:
    return {
        "canonical": canonical,
        "root_classes": ["CONSTANT"],
    }


def _flow(offset: int) -> dict[str, object]:
    return {
        "literal_file_offset": offset,
        "referrer_file_offset": offset + 4,
        "producer_call_site_file_offset": offset + 6,
        "context_start_file_offset": offset - 10,
        "producer_arguments": {
            f"r{register}": _expression(f"ENTRY:r{register}")
            for register in range(4, 8)
        },
        "next_linear_call": {
            "target": _expression("LOAD32[28](CALL_RETURN)"),
            "arguments": {
                f"r{register}": _expression(
                    "CALL_RETURN" if register == 4 else f"ENTRY:r{register}"
                )
                for register in range(4, 8)
            },
        },
        "returned_object_geometry": {
            "target_field_displacement": 28,
            "receiver_adjustment_field_displacement": 24,
            "target_after_adjustment_stride": 4,
            "shared_call_return_vtable_grammar": True,
        },
        "classification": "RETURN_OBJECT_DYNAMIC_DISPATCH",
        "owner_summary": {
            "normalized_shape_sha256": "shape",
            "bounded_code_gate_passed": True,
        },
    }


class ProducerReturnFamilyTests(unittest.TestCase):
    def test_register_access_separates_source_and_destination(self):
        read, write = _register_access(
            SHInstruction(0x100, "mov", "r5,r8"), 5
        )
        self.assertTrue(read)
        self.assertFalse(write)

        read, write = _register_access(
            SHInstruction(0x102, "mov", "r8,r5"), 5
        )
        self.assertFalse(read)
        self.assertTrue(write)

    def test_register_access_marks_read_modify_write(self):
        read, write = _register_access(
            SHInstruction(0x100, "add", "#4,r5"), 5
        )
        self.assertTrue(read)
        self.assertTrue(write)

    def test_entry_profile_confirms_read_before_call(self):
        profile = _entry_register_profile(
            [
                SHInstruction(0x100, "mov", "r5,r8"),
                SHInstruction(
                    0x102, "jsr", "@r0", flow="indirect-call", delayed=True
                ),
                SHInstruction(0x104, "nop", ""),
            ],
            5,
        )
        self.assertTrue(profile["direct_entry_value_use_confirmed"])
        self.assertEqual(profile["terminal"], "CALLER_SAVED_CLOBBER")

    def test_entry_profile_accounts_for_delay_slot_overwrite(self):
        profile = _entry_register_profile(
            [
                SHInstruction(
                    0x100, "jsr", "@r0", flow="indirect-call", delayed=True
                ),
                SHInstruction(0x102, "mov", "#3,r5"),
            ],
            5,
        )
        self.assertFalse(profile["direct_entry_value_use_confirmed"])
        self.assertEqual(
            profile["terminal"], "DELAY_SLOT_OVERWRITE_BEFORE_CALL"
        )

    def test_next_linear_call_selects_first_call(self):
        instructions = [
            SHInstruction(0x100, "nop", ""),
            SHInstruction(0x102, "bsr", "0x200", flow="call"),
            SHInstruction(0x104, "nop", ""),
            SHInstruction(0x106, "jsr", "@r0", flow="indirect-call"),
        ]
        self.assertEqual(_next_linear_call_index(instructions, 0), 1)

    def test_flow_signature_includes_target_and_all_arguments(self):
        flow = _flow(100)
        signature = _flow_signature(flow)
        self.assertEqual(signature[0], "RETURN_OBJECT_DYNAMIC_DISPATCH")
        self.assertEqual(len(signature), 6)

    def test_bilateral_flow_pair_requires_relocation_and_owner_gates(self):
        left = _flow(100)
        right = _flow(120)
        rows = _pair_flow_contracts(
            [left],
            [right],
            target_delta=20,
            session026_candidates={
                "left": {106: 3},
                "right": {126: 3},
            },
        )
        self.assertTrue(
            rows[0]["bilateral_gates"]["bilateral_flow_gate_passed"]
        )
        self.assertEqual(rows[0]["session025_candidate_family_ordinal"], 3)

    def test_graph_and_public_copy_keep_registration_bounded(self):
        comparison = {
            "classification": {
                "bilateral_return_flow_pair_count": 18,
                "return_flow_classification_counts": {
                    "RETURN_OBJECT_DYNAMIC_DISPATCH": 15
                },
                "owner_argument_compatible_dynamic_dispatch_count": 5,
            },
            "interpretation": "call-only target references",
        }
        graph = update_operational_graph_v20(
            {
                "schema": "phoenix-mmi.operational-graph/v19",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )
        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v20")
        self.assertEqual(
            graph["edges"][1]["status"],
            "BOUNDED_NEGATIVE_STATIC_POINTER_MODEL",
        )
        public = build_public_producer_return_report(graph)
        public["nodes"][0]["status"] = "changed"
        self.assertEqual(
            graph["nodes"][0]["status"],
            "CONFIRMED_BILATERAL_STRUCTURAL_FAMILY",
        )


if __name__ == "__main__":
    unittest.main()

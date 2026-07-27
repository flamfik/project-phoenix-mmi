from __future__ import annotations

import unittest

from phoenix_mmi.call_return_producer import (
    _compare_candidates,
    _last_preceding_call_index,
    _pair_target_calls,
    _returned_object_geometry,
    build_public_call_return_producer_report,
    update_operational_graph_v19,
)
from phoenix_mmi.superh import SHInstruction


def _return_vtable() -> dict[str, object]:
    return {
        "kind": "LOAD",
        "width_bits": 32,
        "displacement": 0,
        "base": {"kind": "CALL_RETURN"},
    }


def _geometry(field: int) -> tuple[dict[str, object], dict[str, object]]:
    target = {
        "kind": "LOAD",
        "width_bits": 32,
        "displacement": field,
        "base": _return_vtable(),
    }
    receiver = {
        "kind": "ADD",
        "left": {"kind": "CALL_RETURN"},
        "right": {
            "kind": "LOAD",
            "width_bits": 16,
            "displacement": 0,
            "base": {
                "kind": "ADD",
                "left": _return_vtable(),
                "right": {"kind": "CONSTANT", "value": field - 4},
            },
        },
    }
    return target, receiver


def _candidate() -> dict[str, object]:
    return {
        "producer_call_relative_instruction_index": 9,
        "producer_call_relative_byte_offset": 18,
        "producer_target": {
            "canonical": "IN_IMAGE_POINTER",
            "resolution_status": "RESOLVED_IN_IMAGE_POINTER",
        },
        "producer_target_owner_relative_offset": 100,
        "producer_arguments": {
            name: {"canonical": value}
            for name, value in {
                "r4": "ENTRY:r4",
                "r5": "ENTRY:r5",
                "r6": "CONST:0",
                "r7": "ENTRY:r7",
            }.items()
        },
        "returned_object_geometry": {
            "target_field_displacement": 28,
            "receiver_adjustment_field_displacement": 24,
            "target_after_adjustment_stride": 4,
            "shared_call_return_vtable_grammar": True,
        },
        "gates": {
            "producer_target_resolved_in_image": True,
            "returned_object_geometry_passed": True,
            "same_immediately_preceding_producer_call": True,
        },
    }


class CallReturnProducerTests(unittest.TestCase):
    def test_last_preceding_call_selects_nearest_call(self):
        instructions = [
            SHInstruction(0x100, "bsr", "0x200", flow="call"),
            SHInstruction(0x102, "nop", ""),
            SHInstruction(0x104, "jsr", "@r0", flow="indirect-call"),
            SHInstruction(0x106, "nop", ""),
        ]
        self.assertEqual(_last_preceding_call_index(instructions, 4), 2)

    def test_returned_object_geometry_accepts_stride_four(self):
        target, receiver = _geometry(36)
        result = _returned_object_geometry(target, receiver)
        self.assertEqual(result["target_field_displacement"], 36)
        self.assertEqual(
            result["receiver_adjustment_field_displacement"], 32
        )
        self.assertTrue(result["shared_call_return_vtable_grammar"])

    def test_returned_object_geometry_rejects_wrong_stride(self):
        target, receiver = _geometry(44)
        receiver["right"]["base"]["right"]["value"] = 32
        result = _returned_object_geometry(target, receiver)
        self.assertEqual(result["target_after_adjustment_stride"], 12)
        self.assertFalse(result["shared_call_return_vtable_grammar"])

    def test_candidate_pair_requires_every_bilateral_gate(self):
        left = _candidate()
        right = _candidate()
        gates = _compare_candidates(left, right)
        self.assertTrue(gates["bilateral_producer_reference_gate_passed"])

        right["producer_arguments"]["r6"]["canonical"] = "ENTRY:r6"
        gates = _compare_candidates(left, right)
        self.assertFalse(gates["bilateral_producer_reference_gate_passed"])

    def test_target_call_pairing_keeps_syntactic_scope_explicit(self):
        left = [
            {
                "call_site_file_offset": 100,
                "normalized_context_sha256": "a",
            }
        ]
        right = [
            {
                "call_site_file_offset": 120,
                "normalized_context_sha256": "a",
            }
        ]
        result = _pair_target_calls(
            left,
            right,
            target_delta=20,
            candidate_offsets={"left": {100: 3}, "right": {120: 3}},
        )
        self.assertTrue(result["all_offsets_co_relocated"])
        self.assertTrue(result["all_normalized_contexts_equal"])
        self.assertEqual(result["session025_candidate_reference_pair_count"], 1)
        self.assertTrue(
            result["global_census_is_target_specific_and_syntactic"]
        )

    def test_graph_and_public_copy_preserve_unvalidated_target(self):
        comparison = {
            "classification": {
                "session025_candidate_reference_pair_count": 4,
                "target_specific_literal_jsr_reference_pairs": 7,
                "producer_target_code_entry": "NOT_VALIDATED",
            },
            "interpretation": "resolved reference, code gate open",
        }
        graph = update_operational_graph_v19(
            {
                "schema": "phoenix-mmi.operational-graph/v18",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )
        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v19")
        self.assertEqual(
            graph["nodes"][0]["producer_target_code_entry"],
            "NOT_VALIDATED",
        )
        public = build_public_call_return_producer_report(graph)
        public["nodes"][0]["status"] = "changed"
        self.assertEqual(
            graph["nodes"][0]["status"],
            "CONFIRMED_STATIC_REFERENCE_FAMILY",
        )


if __name__ == "__main__":
    unittest.main()

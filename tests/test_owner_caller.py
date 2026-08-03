from __future__ import annotations

import unittest

from phoenix_mmi.owner_caller import (
    _argument_is_available,
    _evaluate_candidate,
    _indirect_call_signature_matches,
    _normalized_call_signature,
    _owner_required_arguments,
    build_public_owner_caller_report,
    update_operational_graph_v17,
)


def _put_word(image: bytearray, offset: int, word: int) -> None:
    image[offset : offset + 2] = word.to_bytes(2, "big")


def _expression(canonical: str, roots: list[str]) -> dict[str, object]:
    return {
        "canonical": canonical,
        "root_classes": roots,
        "resolution_status": "UNRESOLVED",
    }


class OwnerCallerTests(unittest.TestCase):
    def test_normalized_call_signature_matches_relocated_context(self):
        image = bytearray(0x100)
        first = [0xD001] + [0x0009] * 7 + [0x410B] + [0xA002] * 7
        second = [0xD00A] + [0x0009] * 7 + [0x410B] + [0xA00F] * 7
        for index, word in enumerate(first):
            _put_word(image, 0x20 + index * 2, word)
        for index, word in enumerate(second):
            _put_word(image, 0x60 + index * 2, word)

        signature = _normalized_call_signature(bytes(image), 0x30)
        matches = _indirect_call_signature_matches(
            bytes(image), signature
        )

        self.assertEqual(matches, [0x30, 0x70])

    def test_owner_contract_requires_bilateral_entry_roots(self):
        prior = {
            "state_base_profiles": {
                "left": [
                    {
                        "owner_start_file_offset": 10,
                        "root_class_counts": {
                            "ENTRY:r4": 7,
                            "ENTRY:r6": 1,
                            "NO_DEFINITION": 2,
                        },
                    }
                ],
                "right": [
                    {
                        "owner_start_file_offset": 20,
                        "root_class_counts": {
                            "ENTRY:r4": 7,
                            "ENTRY:r6": 1,
                            "ENTRY:r7": 0,
                        },
                    }
                ],
            }
        }

        rows = _owner_required_arguments(prior)

        self.assertEqual(rows[0]["required_entry_arguments"], ["r4", "r6"])
        self.assertFalse(rows[0]["state_object_identity_asserted"])

    def test_clobbered_argument_is_not_available(self):
        self.assertFalse(
            _argument_is_available(
                _expression(
                    "CALLER_SAVED_CLOBBER", ["CALLER_SAVED_CLOBBER"]
                )
            )
        )
        self.assertTrue(
            _argument_is_available(
                _expression("LOAD32[0](ENTRY:r4)", ["LOAD", "ENTRY:r4"])
            )
        )

    def test_candidate_fails_when_required_r6_is_clobbered(self):
        call = {
            "target_expression": _expression(
                "LOAD32[12](CALL_RETURN)", ["LOAD", "CALL_RETURN"]
            ),
            "arguments": {
                "r4": _expression("LOAD32[0](CALL_RETURN)", ["LOAD"]),
                "r6": _expression(
                    "CALLER_SAVED_CLOBBER", ["CALLER_SAVED_CLOBBER"]
                ),
            },
        }
        compatibility = _evaluate_candidate(
            call,
            call,
            [
                {
                    "owner_pair_ordinal": 1,
                    "required_entry_arguments": ["r4", "r6"],
                }
            ],
        )

        owner = compatibility["owner_pair_compatibility"][0]
        self.assertFalse(owner["candidate_owner_caller_compatible"])
        self.assertEqual(compatibility["compatible_owner_pair_count"], 0)

    def test_graph_and_public_copy_preserve_bounded_negative(self):
        comparison = {
            "classification": {
                "bilateral_owner_entry_argument_contract": (
                    "CONFIRMED_R4_R6_FOR_BOTH_SELECTED_OWNER_PAIRS"
                ),
                "session016_call_return_field_load_family_as_owner_caller": (
                    "BOUNDED_NEGATIVE_INCOMPATIBLE_ENTRY_ARGUMENT_CONTRACT"
                ),
                "owner_entry_argument_producer": "OPEN",
            },
            "interpretation": "candidate excluded",
        }
        graph = update_operational_graph_v17(
            {
                "schema": "phoenix-mmi.operational-graph/v16",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )

        self.assertEqual(graph["schema"], "phoenix-mmi.operational-graph/v17")
        self.assertEqual(graph["bounded_negative_edge_count"], 1)
        public = build_public_owner_caller_report(graph)
        public["nodes"][0]["status"] = "changed"
        self.assertEqual(
            graph["nodes"][0]["status"], "CONFIRMED_BOUNDED_NEGATIVE"
        )


if __name__ == "__main__":
    unittest.main()

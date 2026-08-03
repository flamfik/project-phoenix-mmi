from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.handoff_field60 import (
    _entry_register_profile,
    _field60_contract,
    _selected_owner_pointer_profile,
    _strict_target_profile,
    analyze_handoff_field60,
    build_public_handoff_field60_report,
    update_operational_graph_v21,
)
from phoenix_mmi.superh import SHInstruction


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _field_flow() -> dict[str, object]:
    expression = {
        "canonical": "ENTRY:r4",
        "root_classes": ["ENTRY:r4"],
    }
    return {
        "context_start_file_offset": 0,
        "producer_call_site_file_offset": 0x0C,
        "next_linear_call": {
            "call_site_file_offset": 0x14,
            "target": {
                "canonical": "LOAD32[60](LOAD32[0](CALL_RETURN))",
                "root_classes": ["LOAD", "CALL_RETURN"],
            },
            "arguments": {
                f"r{register}": {
                    **expression,
                    "canonical": f"ENTRY:r{register}",
                }
                for register in range(4, 8)
            },
        },
        "returned_object_geometry": {
            "target_field_displacement": 60,
            "receiver_adjustment_field_displacement": 56,
        },
    }


def _image() -> bytes:
    data = bytearray(0x140)
    owner_words = [
        "4f22",  # save PR
        "6a53",  # preserve entry r5
        "6963",  # preserve entry r6
        "e800",  # zero
        "2a82",  # store zero through saved r5
        "2982",  # store zero through saved r6
        "400b",  # producer call
        "e507",  # delay slot
        "6303",
        "502f",
        "400b",  # field-60 dispatch
        "6433",  # delay slot
        "680c",  # unsigned-byte normalization
        "6083",  # return normalized value
        "000b",
        "0009",
    ]
    data[: len(owner_words) * 2] = b"".join(
        bytes.fromhex(word) for word in owner_words
    )
    invalid_entry = [
        "ffff",
        "b000",
        "0009",
        "4f22",
        "000b",
        "0009",
    ]
    data[0x40 : 0x40 + len(invalid_entry) * 2] = b"".join(
        bytes.fromhex(word) for word in invalid_entry
    )
    return bytes(data)


class HandoffField60Tests(unittest.TestCase):
    def test_control_aware_profile_stops_at_direct_branch(self):
        profile = _entry_register_profile(
            [
                SHInstruction(0, "mov", "r5,r8"),
                SHInstruction(
                    2,
                    "bra",
                    "0x20",
                    target=0x20,
                    flow="branch",
                    delayed=True,
                ),
                SHInstruction(4, "nop"),
                SHInstruction(6, "mov", "r5,r9"),
            ],
            5,
        )
        self.assertEqual(profile["modeled_read_count_before_terminal"], 1)
        self.assertEqual(profile["terminal"], "DIRECT_BRANCH_EXIT")

    def test_strict_gate_rejects_unknown_and_call_before_save_pr(self):
        with TemporaryDirectory() as temporary:
            reader = _reader(_image(), temporary, "image.bin")
            profile = _strict_target_profile(reader, 0x40)
            self.assertFalse(profile["strict_exact_entry_gate_passed"])
            self.assertEqual(profile["call_count_before_save_pr"], 1)
            self.assertGreater(
                profile["unknown_instruction_count_before_save_pr"], 0
            )

    def test_strict_gate_accepts_compact_documented_prologue(self):
        with TemporaryDirectory() as temporary:
            data = bytes.fromhex("2fe64f226ef3000b0009")
            reader = _reader(data, temporary, "entry.bin")
            profile = _strict_target_profile(reader, 0)
            self.assertTrue(profile["strict_exact_entry_gate_passed"])

    def test_field60_contract_confirms_zero_stores_and_byte_return(self):
        with TemporaryDirectory() as temporary:
            reader = _reader(_image(), temporary, "image.bin")
            contract = _field60_contract(reader, _field_flow())
            self.assertTrue(contract["fully_decoded_bounded_owner_window"])
            self.assertTrue(contract["entry_r5_zero_store_confirmed"])
            self.assertTrue(contract["entry_r6_zero_store_confirmed"])
            self.assertEqual(
                contract["post_dispatch_return_extension"], "extu.b"
            )
            self.assertTrue(contract["extended_value_returned_in_r0"])

    def test_selected_owner_probe_is_exact_and_bounded(self):
        with TemporaryDirectory() as temporary:
            data = bytearray(0x100)
            owner = 0x44
            data[0x20:0x24] = (0x0C000000 + owner).to_bytes(4, "big")
            reader = _reader(bytes(data), temporary, "pointer.bin")
            profile = _selected_owner_pointer_profile(
                reader, 0, [owner, 0x88]
            )
            self.assertEqual(
                profile["exact_aligned_selected_owner_word_count"], 1
            )
            self.assertFalse(
                profile["computed_or_encoded_pointer_models_tested"]
            )

    def test_bilateral_analysis_keeps_registration_open(self):
        with TemporaryDirectory() as temporary:
            left = _reader(_image(), temporary, "left.bin")
            right = _reader(_image(), temporary, "right.bin")
            field = _field_flow()
            session027 = {
                "return_flow_pairs": [
                    {
                        "flow_ordinal": 3,
                        "classification": "RETURN_OBJECT_DYNAMIC_DISPATCH",
                        "left": field,
                        "right": field,
                        "bilateral_gates": {
                            "owner_normalized_shape_equal": True,
                            "owner_code_gate_passed_both": True,
                        },
                    }
                ],
                "static_handoff_pairs": [
                    {
                        "flow_ordinal": 12,
                        "left_target_file_offset": 0x40,
                        "right_target_file_offset": 0x40,
                        "code_gate_passed_both": True,
                    }
                ],
            }
            session021 = {
                "residual_lineage": {
                    "selected_owner_pairs": [
                        {
                            "left_owner_start_file_offset": 0x100,
                            "right_owner_start_file_offset": 0x100,
                        }
                    ]
                }
            }
            result = analyze_handoff_field60(
                left, right, session021, session027
            )
            self.assertTrue(
                result["classification"][
                    "field60_owner_fully_decoded_pair"
                ]
            )
            self.assertEqual(
                result["classification"][
                    "strict_static_handoff_exact_entry_pair_count"
                ],
                0,
            )
            self.assertEqual(
                result["classification"][
                    "static_handoff_registration_path"
                ],
                "NOT_ESTABLISHED",
            )

    def test_graph_and_public_copy_are_detached(self):
        comparison = {
            "interpretation": "bounded field-60 contract",
            "publication_safety": {"firmware_bytes_included": False},
        }
        graph = update_operational_graph_v21(
            {
                "schema": "phoenix-mmi.operational-graph/v20",
                "nodes": [],
                "edges": [],
            },
            comparison,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v21"
        )
        self.assertEqual(
            graph["edges"][1]["status"],
            "BOUNDED_NEGATIVE_TARGET_LINK_MODEL",
        )
        public = build_public_handoff_field60_report(graph)
        public["nodes"][0]["status"] = "changed"
        self.assertEqual(
            graph["nodes"][0]["status"],
            "CONFIRMED_BILATERAL_STRUCTURAL_CONTRACT",
        )


if __name__ == "__main__":
    unittest.main()

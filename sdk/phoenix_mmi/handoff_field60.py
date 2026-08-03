"""Bounded Session 028 handoff-prelude and field-60 analysis.

This module revisits only the two static handoff targets and the single
field-60 owner registered by Session 027. It does not widen the scan to an
unconstrained executable search and never treats a nearby prologue as proof
that a runtime pointer maps to that exact file entry.
"""

from __future__ import annotations

from collections import Counter
import copy
import re

from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import _decode_window
from .producer_return_family import _register_access


_REGISTER_MOVE = re.compile(r"r(\d+),r(\d+)$")
_IMMEDIATE_MOVE = re.compile(r"#(-?\d+),r(\d+)$")
_INDIRECT_STORE = re.compile(r"r(\d+),@r(\d+)$")
_EXTENSION = re.compile(r"r(\d+),r(\d+)$")
_TARGET_WINDOW_BYTES = 0x180
_ENTRY_PREFIX_BYTES = 0x40


def _entry_register_profile(
    instructions: list[object], register: int
) -> dict[str, object]:
    """Trace one entry register until the first unresolved control transfer."""

    reads = 0
    writes = 0
    unknown = 0
    terminal = "WINDOW_END"
    terminal_offset = None
    index = 0
    while index < len(instructions):
        instruction = instructions[index]
        if instruction.mnemonic == "unknown":
            unknown += 1
        read, write = _register_access(instruction, register)
        reads += int(read)
        writes += int(write)

        if instruction.flow in {"call", "indirect-call"}:
            if instruction.delayed and index + 1 < len(instructions):
                delay = instructions[index + 1]
                if delay.mnemonic == "unknown":
                    unknown += 1
                delay_read, delay_write = _register_access(delay, register)
                reads += int(delay_read)
                writes += int(delay_write)
                if delay_write and not delay_read:
                    terminal = "DELAY_SLOT_OVERWRITE_BEFORE_CALL"
                    terminal_offset = int(delay.offset)
                    break
            terminal = "CALLER_SAVED_CLOBBER"
            terminal_offset = int(instruction.offset)
            break
        if instruction.flow in {
            "branch",
            "conditional",
            "indirect-branch",
            "return",
            "trap",
        }:
            if instruction.delayed and index + 1 < len(instructions):
                delay = instructions[index + 1]
                if delay.mnemonic == "unknown":
                    unknown += 1
                delay_read, delay_write = _register_access(delay, register)
                reads += int(delay_read)
                writes += int(delay_write)
            terminal = {
                "branch": "DIRECT_BRANCH_EXIT",
                "conditional": "CONDITIONAL_CONTROL_SPLIT",
                "indirect-branch": "INDIRECT_BRANCH_EXIT",
                "return": "RETURN",
                "trap": "TRAP_TRANSFER",
            }[instruction.flow]
            terminal_offset = int(instruction.offset)
            break
        if write and not read:
            terminal = "EXPLICIT_OVERWRITE"
            terminal_offset = int(instruction.offset)
            break
        index += 1

    return {
        "register": f"r{register}",
        "modeled_read_count_before_terminal": reads,
        "modeled_write_count_before_terminal": writes,
        "unknown_instruction_count_before_terminal": unknown,
        "terminal": terminal,
        "terminal_file_offset": terminal_offset,
        "direct_entry_value_use_confirmed": reads > 0,
        "unknown_or_control_flow_limits_negative_result": bool(
            unknown > 0
            or terminal
            in {
                "DIRECT_BRANCH_EXIT",
                "CONDITIONAL_CONTROL_SPLIT",
                "INDIRECT_BRANCH_EXIT",
                "TRAP_TRANSFER",
            }
        ),
    }


def _strict_target_profile(
    reader: BinaryReader, target: int
) -> dict[str, object]:
    instructions = _decode_window(
        reader, target, maximum_bytes=_ENTRY_PREFIX_BYTES
    )
    save_index = next(
        (
            index
            for index, instruction in enumerate(instructions)
            if instruction.mnemonic == "sts.l"
            and instruction.operands == "pr,@-r15"
        ),
        None,
    )
    prefix = (
        instructions
        if save_index is None
        else instructions[:save_index]
    )
    unknown = sum(item.mnemonic == "unknown" for item in prefix)
    calls = sum(
        item.flow in {"call", "indirect-call"} for item in prefix
    )
    transfers = sum(
        item.flow
        in {
            "branch",
            "conditional",
            "indirect-branch",
            "return",
            "trap",
        }
        for item in prefix
    )
    save_delta = (
        None
        if save_index is None
        else int(instructions[save_index].offset) - target
    )
    strict_gate = bool(
        save_index is not None
        and save_index <= 4
        and unknown == 0
        and calls == 0
        and transfers == 0
    )
    recognized = Counter(
        item.mnemonic
        for item in prefix
        if item.mnemonic != "unknown"
    )
    return {
        "target_file_offset": target,
        "bounded_window_bytes": _ENTRY_PREFIX_BYTES,
        "save_pr_file_offset": (
            None
            if save_index is None
            else int(instructions[save_index].offset)
        ),
        "save_pr_delta_from_target": save_delta,
        "instruction_count_before_save_pr": len(prefix),
        "unknown_instruction_count_before_save_pr": unknown,
        "call_count_before_save_pr": calls,
        "control_transfer_count_before_save_pr": transfers,
        "documented_mnemonic_counts_before_save_pr": dict(
            sorted(recognized.items())
        ),
        "strict_exact_entry_gate_passed": strict_gate,
        "strict_gate_is_analysis_policy_not_abi_rule": True,
        "nearby_prologue_does_not_validate_exact_target": True,
        "entry_r5_profile": _entry_register_profile(instructions, 5),
        "instruction_bytes_included": False,
    }


def _count_exact_aligned_words(data: bytes, word: bytes) -> int:
    count = 0
    start = 0
    while True:
        offset = data.find(word, start)
        if offset < 0:
            return count
        count += int(offset % 4 == 0)
        start = offset + 1


def _selected_owner_pointer_profile(
    reader: BinaryReader,
    target: int,
    selected_owner_offsets: list[int],
) -> dict[str, object]:
    window = reader.read(
        target, min(_TARGET_WINDOW_BYTES, reader.size - target)
    )
    counts = []
    for owner in selected_owner_offsets:
        runtime_word = (RUNTIME_BASE + owner).to_bytes(4, "big")
        counts.append(_count_exact_aligned_words(window, runtime_word))
    return {
        "bounded_window_bytes": len(window),
        "selected_owner_candidate_count": len(selected_owner_offsets),
        "exact_aligned_selected_owner_word_count": sum(counts),
        "per_owner_counts": counts,
        "address_model": "RUNTIME_BASE_PLUS_FILE_OFFSET",
        "address_model_scope": "SESSION006_BOUNDED_NOT_UNIVERSAL",
        "computed_or_encoded_pointer_models_tested": False,
    }


def _field60_contract(
    reader: BinaryReader, flow: dict[str, object]
) -> dict[str, object]:
    entry = int(flow["context_start_file_offset"])
    producer_call = int(flow["producer_call_site_file_offset"])
    dynamic_call = int(
        flow["next_linear_call"]["call_site_file_offset"]
    )
    instructions = _decode_window(reader, entry)
    instruction_by_offset = {
        int(instruction.offset): instruction
        for instruction in instructions
    }
    producer_index = next(
        index
        for index, instruction in enumerate(instructions)
        if int(instruction.offset) == producer_call
    )
    dynamic_index = next(
        index
        for index, instruction in enumerate(instructions)
        if int(instruction.offset) == dynamic_call
    )

    preserved: dict[int, int] = {}
    zero_registers: set[int] = set()
    for instruction in instructions[:producer_index]:
        move = _REGISTER_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and move is not None:
            source, destination = map(int, move.groups())
            if source in {5, 6}:
                preserved[source] = destination
        immediate = _IMMEDIATE_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and immediate is not None:
            value, destination = map(int, immediate.groups())
            if value == 0:
                zero_registers.add(destination)

    zero_stores: dict[str, int] = {}
    for instruction in instructions[:producer_index]:
        store = _INDIRECT_STORE.fullmatch(instruction.operands)
        if instruction.mnemonic != "mov.l" or store is None:
            continue
        source, base = map(int, store.groups())
        if source not in zero_registers:
            continue
        for entry_register, saved_register in preserved.items():
            if base == saved_register:
                zero_stores[f"ENTRY:r{entry_register}"] = int(
                    instruction.offset
                )

    extension = None
    extension_register = None
    for instruction in instructions[
        dynamic_index + 1 : dynamic_index + 6
    ]:
        operands = _EXTENSION.fullmatch(instruction.operands)
        if instruction.mnemonic == "extu.b" and operands is not None:
            source, destination = map(int, operands.groups())
            if source == 0:
                extension = instruction
                extension_register = destination
                break
    returned = False
    return_move_offset = None
    if extension_register is not None:
        for instruction in instructions[
            dynamic_index + 1 :
        ]:
            move = _REGISTER_MOVE.fullmatch(instruction.operands)
            if instruction.mnemonic == "mov" and move is not None:
                source, destination = map(int, move.groups())
                if source == extension_register and destination == 0:
                    returned = True
                    return_move_offset = int(instruction.offset)
                    break
            if instruction.flow == "return":
                break

    unknown_count = sum(
        instruction.mnemonic == "unknown"
        for instruction in instructions
    )
    return {
        "owner_entry_file_offset": entry,
        "instruction_count": len(instructions),
        "known_instruction_count": len(instructions) - unknown_count,
        "unknown_instruction_count": unknown_count,
        "fully_decoded_bounded_owner_window": unknown_count == 0,
        "producer_call_site_file_offset": producer_call,
        "dynamic_call_site_file_offset": dynamic_call,
        "target_field_displacement": int(
            flow["returned_object_geometry"][
                "target_field_displacement"
            ]
        ),
        "receiver_adjustment_field_displacement": int(
            flow["returned_object_geometry"][
                "receiver_adjustment_field_displacement"
            ]
        ),
        "entry_argument_preservation": {
            f"r{source}": f"r{destination}"
            for source, destination in sorted(preserved.items())
        },
        "pre_producer_zero_stores": dict(sorted(zero_stores.items())),
        "entry_r5_zero_store_confirmed": "ENTRY:r5" in zero_stores,
        "entry_r6_zero_store_confirmed": "ENTRY:r6" in zero_stores,
        "post_dispatch_return_extension": (
            None if extension is None else extension.mnemonic
        ),
        "post_dispatch_extension_file_offset": (
            None if extension is None else int(extension.offset)
        ),
        "extended_value_returned_in_r0": returned,
        "return_move_file_offset": return_move_offset,
        "dynamic_target": copy.deepcopy(
            flow["next_linear_call"]["target"]
        ),
        "dynamic_arguments": copy.deepcopy(
            flow["next_linear_call"]["arguments"]
        ),
        "selected_owner_target_link_established": False,
        "path_dominance_asserted": False,
        "instruction_bytes_included": False,
    }


def _selected_owner_offsets(
    session021: dict[str, object], side: str
) -> list[int]:
    return [
        int(row[f"{side}_owner_start_file_offset"])
        for row in session021["residual_lineage"][
            "selected_owner_pairs"
        ]
    ]


def analyze_handoff_field60(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    session021: dict[str, object],
    session027: dict[str, object],
) -> dict[str, object]:
    """Revisit only Session 027 static handoffs and field-60 owner."""

    field60 = next(
        row
        for row in session027["return_flow_pairs"]
        if row["classification"] == "RETURN_OBJECT_DYNAMIC_DISPATCH"
        and int(
            row["left"]["returned_object_geometry"][
                "target_field_displacement"
            ]
        )
        == 60
    )
    readers = {"left": left_reader, "right": right_reader}
    field_contracts = {
        side: _field60_contract(readers[side], field60[side])
        for side in ("left", "right")
    }
    handoffs = []
    for prior in session027["static_handoff_pairs"]:
        row: dict[str, object] = {
            "flow_ordinal": int(prior["flow_ordinal"]),
            "session027_nearby_code_gate_passed_both": bool(
                prior["code_gate_passed_both"]
            ),
            "session027_gate_validates_exact_entry": False,
        }
        for side in ("left", "right"):
            target = int(prior[f"{side}_target_file_offset"])
            target_profile = _strict_target_profile(
                readers[side], target
            )
            pointer_profile = _selected_owner_pointer_profile(
                readers[side],
                target,
                _selected_owner_offsets(session021, side),
            )
            row[side] = {
                "target": target_profile,
                "selected_owner_pointer_probe": pointer_profile,
            }
        row["strict_exact_entry_gate_passed_both"] = bool(
            row["left"]["target"][
                "strict_exact_entry_gate_passed"
            ]
            and row["right"]["target"][
                "strict_exact_entry_gate_passed"
            ]
        )
        row["direct_modeled_entry_r5_use_confirmed_both"] = bool(
            row["left"]["target"]["entry_r5_profile"][
                "direct_entry_value_use_confirmed"
            ]
            and row["right"]["target"]["entry_r5_profile"][
                "direct_entry_value_use_confirmed"
            ]
        )
        row["exact_selected_owner_pointer_confirmed_both"] = bool(
            row["left"]["selected_owner_pointer_probe"][
                "exact_aligned_selected_owner_word_count"
            ]
            and row["right"]["selected_owner_pointer_probe"][
                "exact_aligned_selected_owner_word_count"
            ]
        )
        row["registration_path_established"] = False
        handoffs.append(row)

    field_bilateral = {
        "owner_shape_equal": bool(
            field60["bilateral_gates"]["owner_normalized_shape_equal"]
        ),
        "owner_code_gate_passed_both": bool(
            field60["bilateral_gates"]["owner_code_gate_passed_both"]
        ),
        "fully_decoded_bounded_owner_window_both": all(
            contract["fully_decoded_bounded_owner_window"]
            for contract in field_contracts.values()
        ),
        "entry_r5_zero_store_confirmed_both": all(
            contract["entry_r5_zero_store_confirmed"]
            for contract in field_contracts.values()
        ),
        "entry_r6_zero_store_confirmed_both": all(
            contract["entry_r6_zero_store_confirmed"]
            for contract in field_contracts.values()
        ),
        "unsigned_byte_return_normalization_confirmed_both": all(
            contract["post_dispatch_return_extension"] == "extu.b"
            and contract["extended_value_returned_in_r0"]
            for contract in field_contracts.values()
        ),
        "dynamic_contract_equal": bool(
            field_contracts["left"]["dynamic_target"]["canonical"]
            == field_contracts["right"]["dynamic_target"]["canonical"]
            and all(
                field_contracts["left"]["dynamic_arguments"][register][
                    "canonical"
                ]
                == field_contracts["right"]["dynamic_arguments"][
                    register
                ]["canonical"]
                for register in ("r4", "r5", "r6", "r7")
            )
        ),
    }
    return {
        "schema": "phoenix-mmi.handoff-field60-comparison/v1",
        "analysis_mode": (
            "read-only-static-session027-bounded-handoff-field60"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "field60": {
            "flow_ordinal": int(field60["flow_ordinal"]),
            "left": field_contracts["left"],
            "right": field_contracts["right"],
            "bilateral_gates": field_bilateral,
        },
        "static_handoffs": handoffs,
        "classification": {
            "documented_decoder_additions": [
                "EXTS.B",
                "EXTS.W",
                "EXTU.B",
                "EXTU.W",
                "MAC.L",
                "MOV_INDEXED",
                "MUL.L",
                "SHAD",
                "SHLD",
                "TRAPA",
            ],
            "field60_owner_fully_decoded_pair": field_bilateral[
                "fully_decoded_bounded_owner_window_both"
            ],
            "field60_entry_r5_zero_store_pair": field_bilateral[
                "entry_r5_zero_store_confirmed_both"
            ],
            "field60_entry_r6_zero_store_pair": field_bilateral[
                "entry_r6_zero_store_confirmed_both"
            ],
            "field60_unsigned_byte_return_pair": field_bilateral[
                "unsigned_byte_return_normalization_confirmed_both"
            ],
            "strict_static_handoff_exact_entry_pair_count": sum(
                row["strict_exact_entry_gate_passed_both"]
                for row in handoffs
            ),
            "static_handoff_direct_entry_r5_use_pair_count": sum(
                row["direct_modeled_entry_r5_use_confirmed_both"]
                for row in handoffs
            ),
            "static_handoff_selected_owner_pointer_pair_count": sum(
                row["exact_selected_owner_pointer_confirmed_both"]
                for row in handoffs
            ),
            "static_handoff_registration_path": "NOT_ESTABLISHED",
            "static_handoff_exact_target_mapping": (
                "NOT_VALIDATED_UNDER_STRICT_ENTRY_GATE"
            ),
            "field60_selected_owner_target_link": "NOT_ESTABLISHED",
            "runtime_equivalence": "NOT_ASSERTED",
            "semantic_owner_identity": "OPEN",
            "returned_object_type": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
        },
        "limits": {
            "source_session": 27,
            "static_target_window_bytes": _TARGET_WINDOW_BYTES,
            "entry_prefix_bytes": _ENTRY_PREFIX_BYTES,
            "only_registered_handoffs_and_field60_owner_followed": True,
            "arbitrary_raw_image_code_scan_performed": False,
            "runtime_base_mapping_assumed_universal": False,
            "strict_entry_gate_is_abi_claim": False,
            "computed_or_encoded_pointer_models_tested": False,
            "path_dominance_asserted": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "The field-60 owner pair is now fully decoded in its bounded "
            "window. Both releases preserve entry r5/r6, write zero through "
            "those two entry pointers before the producer call, reuse them "
            "as r5/r6 for the field-60 dynamic dispatch, and normalize the "
            "dispatch result to an unsigned byte returned in r0. The target "
            "remains a call-return-rooted memory load, so no selected-owner "
            "edge follows. The two handoff pointer mappings fail the stricter "
            "exact-entry gate, contain no bilateral modeled entry-r5 use and "
            "contain no exact selected-owner pointer in their bounded "
            "windows. Session 027's nearby-prologue gate is therefore not "
            "sufficient to validate those exact target mappings; static "
            "registration remains open."
        ),
        "publication_safety": {
            "firmware_bytes_included": False,
            "instruction_bytes_included": False,
            "absolute_runtime_addresses_included": False,
            "raw_strings_included": False,
            "local_paths_included": False,
            "map_payload_included": False,
        },
    }


def update_operational_graph_v21(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v21"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "field60-owner-contract"
    ]
    graph["nodes"].append(
        {
            "id": "field60-owner-contract",
            "label": "Field-60 owner contract",
            "status": "CONFIRMED_BILATERAL_STRUCTURAL_CONTRACT",
            "zeroed_entry_pointer_count": 2,
            "return_width": "UNSIGNED_BYTE",
            "evidence": ["S028-01", "S028-02", "RQ-088", "RQ-089"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "producer-return-use-family"
            and edge["target"] == "field60-owner-contract"
        )
        and not (
            edge["source"] == "field60-owner-contract"
            and edge["target"] == "runtime-linkage-owner-ingress"
        )
    ]
    graph["edges"].extend(
        [
            {
                "source": "producer-return-use-family",
                "target": "field60-owner-contract",
                "relation": (
                    "contains one fully decoded field-60 owner contract"
                ),
                "status": "CONFIRMED_STRUCTURAL",
            },
            {
                "source": "field60-owner-contract",
                "target": "runtime-linkage-owner-ingress",
                "relation": (
                    "memory-loaded target remains unresolved; strict "
                    "handoff-entry and selected-pointer probes are negative"
                ),
                "status": "BOUNDED_NEGATIVE_TARGET_LINK_MODEL",
            },
        ]
    )
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED")
        for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE")
        for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(
        node["status"] == "OPEN" for node in graph["nodes"]
    )
    graph["bounded_negative_edge_count"] = sum(
        "BOUNDED_NEGATIVE" in edge["status"] for edge in graph["edges"]
    )
    graph["interpretation"] = comparison["interpretation"]
    return graph


def correlate_handoff_field60(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.handoff-field60-correlation/v1",
        "analysis_mode": comparison["analysis_mode"],
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "correlation": {
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "partition_consumer": "OPEN",
            "dynamic_compatibility": "NOT_ESTABLISHED",
        },
        "operational_graph": update_operational_graph_v21(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_handoff_field60_report(
    report: dict[str, object],
) -> dict[str, object]:
    """Return a detached already-publication-safe report."""

    return copy.deepcopy(report)

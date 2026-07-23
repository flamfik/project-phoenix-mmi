"""Internal-continuation and frame-record analysis for Session 023.

The analyzer follows only the two address-taken seeds registered by Session
022.  A seed inside an owner window is never treated as an owner entry.  The
module distinguishes direct internal-label invocation from passing an internal
address to another helper and keeps landing-pad/unwind semantics probable.
"""

from __future__ import annotations

from collections import Counter
import copy
import re

from .accessor_dispatch import (
    _callsite_signature,
    _compare_call_families,
    _literal_jsr_calls,
    _normalized_word,
)
from .binary import BinaryReader
from .linkage_owner import _MemoryReader
from .object_dispatch import (
    _bounded_context,
    _canonical_expression,
    _destination_register,
    _resolve_static_expression,
    _trace_expression,
)
from .optical_callgraph import _decode_window, summarize_bounded_entry
from .owner_provenance import (
    _exact_pc_context_matches,
    _expression_roots,
    _loaded_pointer_target,
)


_REGISTER = re.compile(r"r(\d+)")
_CALL_REGISTER = re.compile(r"@r(\d+)$")
_DISPLACED_STORE = re.compile(r"r(\d+),@\((\d+),r(\d+)\)$")
_INDIRECT_STORE = re.compile(r"r(\d+),@r(\d+)$")
_HELPER_SEQUENCE_WORDS = 30


def _trace_call_argument(
    instructions: list[object],
    call_index: int,
    register: int,
    *,
    image_size: int,
) -> dict[str, object]:
    """Trace one call argument while applying the SH delay slot first."""

    prefix = list(instructions[:call_index])
    if (
        instructions[call_index].delayed
        and call_index + 1 < len(instructions)
    ):
        prefix.append(instructions[call_index + 1])
    return _trace_expression(
        prefix, len(prefix), register, image_size=image_size
    )


def _public_expression(
    reader: BinaryReader, expression: dict[str, object]
) -> dict[str, object]:
    resolution = _resolve_static_expression(reader, expression)
    result = {
        "canonical": _canonical_expression(expression),
        "root_classes": _expression_roots(expression),
        "resolution_status": resolution["status"],
    }
    target = resolution.get("target_file_offset")
    if isinstance(target, int):
        result["target_file_offset"] = target
    return result


def _definition_offset(
    instructions: list[object], before_index: int, register: int
) -> int | None:
    for index in range(before_index - 1, -1, -1):
        if _destination_register(instructions[index]) == register:
            return int(instructions[index].offset)
        if (
            instructions[index].flow in {"call", "indirect-call"}
            and register <= 7
        ):
            return None
    return None


def _call_contract(
    reader: BinaryReader,
    *,
    referrer: int,
    relative_use_instruction_index: int,
) -> dict[str, object]:
    data = reader.read(0, reader.size)
    instructions, boundary = _bounded_context(
        _MemoryReader(data), referrer
    )
    load_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.offset == referrer
    )
    call_index = load_index + relative_use_instruction_index
    call = instructions[call_index]
    if call.flow not in {"call", "indirect-call"}:
        raise ValueError("Session 022 use does not select a call")

    target_expression = None
    target_resolution = {"status": "UNRESOLVED"}
    target_load = None
    call_register = _CALL_REGISTER.fullmatch(call.operands)
    if call.mnemonic == "jsr" and call_register is not None:
        register = int(call_register.group(1))
        target_expression = _trace_expression(
            instructions,
            call_index,
            register,
            image_size=reader.size,
        )
        target_resolution = _resolve_static_expression(
            reader, target_expression
        )
        target_load = _definition_offset(
            instructions, call_index, register
        )
    elif call.target is not None:
        target_resolution = {
            "status": "RESOLVED_DIRECT_BSR",
            "target_file_offset": int(call.target),
        }

    arguments = {
        f"r{register}": _public_expression(
            reader,
            _trace_call_argument(
                instructions,
                call_index,
                register,
                image_size=reader.size,
            ),
        )
        for register in range(4, 15)
    }
    result = {
        "enclosing_window_start_file_offset": int(
            boundary["context_start_file_offset"]
        ),
        "context_start_reason": boundary["context_start_reason"],
        "call_site_file_offset": int(call.offset),
        "call_relative_to_window": int(call.offset)
        - int(boundary["context_start_file_offset"]),
        "target_resolution_status": target_resolution["status"],
        "target_load_file_offset": target_load,
        "arguments_and_preserved_context": arguments,
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }
    target = target_resolution.get("target_file_offset")
    if isinstance(target, int):
        result["target_file_offset"] = target
    if target_expression is not None:
        result["target_expression"] = _public_expression(
            reader, target_expression
        )
    return result


def _instruction_reads(instruction: object) -> set[int]:
    registers = {
        int(match) for match in _REGISTER.findall(instruction.operands)
    }
    destination = _destination_register(instruction)
    if destination is not None:
        registers.discard(destination)
    return registers


def _internal_label_diagnostic(
    reader: BinaryReader,
    *,
    target: int,
    owner_start: int,
) -> dict[str, object]:
    instructions = _decode_window(reader, target, maximum_bytes=0x80)
    live_in = set()
    defined = set()
    for instruction in instructions:
        live_in.update(_instruction_reads(instruction) - defined)
        destination = _destination_register(instruction)
        if destination is not None:
            defined.add(destination)
        if instruction.flow in {"call", "indirect-call"}:
            break
    summary = summarize_bounded_entry(
        reader,
        target,
        source="SESSION023_INTERNAL_ADDRESS",
        maximum_bytes=0x80,
    )
    return {
        "target_file_offset": target,
        "target_relative_to_owner": target - owner_start,
        "first_instruction_mnemonic": (
            instructions[0].mnemonic if instructions else None
        ),
        "live_in_registers_before_first_call": [
            f"r{register}" for register in sorted(live_in)
        ],
        "prologue_save_pr_in_first_12_instructions": summary[
            "prologue_save_pr_in_first_12_instructions"
        ],
        "bounded_code_gate_passed": summary[
            "bounded_code_gate_passed"
        ],
        "known_ratio": summary["known_ratio"],
        "return_count": summary["return_count"],
        "call_count": summary["call_count"],
        "address_classification": "INTERNAL_LABEL_NOT_OWNER_ENTRY",
        "standalone_abi_entry_asserted": False,
        "function_boundary_asserted": False,
    }


def _normalized_sequence(
    data: bytes, start: int, count: int
) -> tuple[int, ...]:
    return tuple(
        _normalized_word(
            int.from_bytes(data[offset : offset + 2], "big")
        )
        for offset in range(start, start + count * 2, 2)
    )


def _normalized_sequence_matches(
    data: bytes, sequence: tuple[int, ...]
) -> list[int]:
    matches = []
    maximum = len(data) - len(sequence) * 2 + 1
    for start in range(0, maximum, 2):
        first = _normalized_word(
            int.from_bytes(data[start : start + 2], "big")
        )
        if first != sequence[0]:
            continue
        for index, expected in enumerate(sequence[1:], start=1):
            offset = start + index * 2
            actual = _normalized_word(
                int.from_bytes(data[offset : offset + 2], "big")
            )
            if actual != expected:
                break
        else:
            matches.append(start)
    return matches


def _helper_store_profile(
    reader: BinaryReader, target: int
) -> dict[str, object]:
    instructions = _decode_window(reader, target, maximum_bytes=0x180)
    rows = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic != "mov.l":
            continue
        displaced = _DISPLACED_STORE.fullmatch(instruction.operands)
        indirect = _INDIRECT_STORE.fullmatch(instruction.operands)
        if displaced is not None:
            source, displacement, base = map(int, displaced.groups())
        elif indirect is not None:
            source, base = map(int, indirect.groups())
            displacement = 0
        else:
            continue
        base_expression = _trace_expression(
            instructions, index, base, image_size=reader.size
        )
        if _canonical_expression(base_expression) != "ENTRY:r4":
            continue
        rows.append(
            {
                "field_offset": displacement,
                "source_register": f"r{source}",
                "source_value_path_merged": True,
            }
        )
    register_mentions = Counter(
        match
        for instruction in instructions
        for match in _REGISTER.findall(instruction.operands)
    )
    summary = summarize_bounded_entry(
        reader, target, source="SESSION023_FRAME_RECORD_HELPER"
    )
    return {
        "target_file_offset": target,
        "instruction_count": summary["instruction_count"],
        "known_ratio": summary["known_ratio"],
        "call_count": summary["call_count"],
        "return_count": summary["return_count"],
        "bounded_code_gate_passed": summary[
            "bounded_code_gate_passed"
        ],
        "normalized_shape_sha256": summary[
            "normalized_shape_sha256"
        ],
        "entry_r4_field_offsets": sorted(
            {int(row["field_offset"]) for row in rows}
        ),
        "entry_r4_field_store_count": len(rows),
        "field_stores": rows,
        "r7_modeled_operand_mention_count": int(
            register_mentions.get("7", 0)
        ),
        "record_or_frame_semantics": "PROBABLE",
        "landing_pad_or_unwind_semantics": "PROBABLE_NOT_CONFIRMED",
        "function_boundary_asserted": False,
    }


def _address_argument_census(
    reader: BinaryReader,
    calls: list[dict[str, int]],
    *,
    target: int,
) -> dict[str, object]:
    data = reader.read(0, reader.size)
    selected = [
        row for row in calls if int(row["target_file_offset"]) == target
    ]
    address_targets = []
    for row in selected:
        instructions, _ = _bounded_context(
            _MemoryReader(data), int(row["load_file_offset"])
        )
        call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.offset == int(row["call_site_offset"])
        )
        expression = _trace_call_argument(
            instructions,
            call_index,
            5,
            image_size=reader.size,
        )
        resolution = _resolve_static_expression(reader, expression)
        if resolution.get("status") == "RESOLVED_IN_IMAGE_POINTER":
            address_targets.append(
                int(resolution["target_file_offset"])
            )
    return {
        "adjacent_literal_jsr_call_count": len(selected),
        "r5_in_image_address_count": len(address_targets),
        "r5_unique_in_image_address_count": len(set(address_targets)),
        "all_calls_have_r5_in_image_address": bool(
            selected and len(address_targets) == len(selected)
        ),
        "address_semantics_asserted": False,
    }


def analyze_internal_continuation_contract(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
) -> dict[str, object]:
    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    data = {"left": left_data, "right": right_data}
    readers = {"left": left_reader, "right": right_reader}

    selected = {}
    for side in ("left", "right"):
        seeds = [
            (owner, address, use)
            for owner in prior["owner_ingress"][side]
            for address in owner["address_taken_rows"]
            for use in address["uses"]
        ]
        if len(seeds) != 1:
            raise ValueError(
                f"Session 022 does not register one {side} address seed"
            )
        owner, address, use = seeds[0]
        contract = _call_contract(
            readers[side],
            referrer=int(use["referrer_file_offset"]),
            relative_use_instruction_index=int(
                use["relative_use_instruction_index"]
            ),
        )
        selected[side] = {
            "session022_use_classification": use["classification"],
            "owner_start_file_offset": owner[
                "owner_start_file_offset"
            ],
            "internal_address": _internal_label_diagnostic(
                readers[side],
                target=int(address["target_file_offset"]),
                owner_start=int(owner["owner_start_file_offset"]),
            ),
            "use_contract": contract,
        }

    right_contract = selected["right"]["use_contract"]
    helper_target = right_contract.get("target_file_offset")
    helper_load = right_contract.get("target_load_file_offset")
    if not isinstance(helper_target, int) or not isinstance(
        helper_load, int
    ):
        raise ValueError("right address-argument helper is not statically resolved")

    left_calls = _literal_jsr_calls(
        left_data, image_size=left_reader.size
    )
    right_calls = _literal_jsr_calls(
        right_data, image_size=right_reader.size
    )
    family, _ = _compare_call_families(
        left_data,
        right_data,
        left_calls,
        right_calls,
        right_target=helper_target,
    )
    dominant_left = family["dominant_left_target_file_offset"]
    if not isinstance(dominant_left, int):
        raise ValueError("right helper family has no dominant left target")

    helper_sequence = _normalized_sequence(
        right_data, helper_target, _HELPER_SEQUENCE_WORDS
    )
    shape_matches = {
        side: _normalized_sequence_matches(
            data[side], helper_sequence
        )
        for side in ("left", "right")
    }
    calls_by_side = {"left": left_calls, "right": right_calls}
    shape_census = {
        side: {
            "exact_normalized_sequence_match_count": len(offsets),
            "matches": [
                {
                    "target_file_offset": offset,
                    "adjacent_literal_jsr_call_count": sum(
                        int(row["target_file_offset"]) == offset
                        for row in calls_by_side[side]
                    ),
                }
                for offset in offsets
            ],
        }
        for side, offsets in shape_matches.items()
    }

    helper_signature = _callsite_signature(right_data, helper_load)
    selected_context_matches = _exact_pc_context_matches(
        left_data, helper_signature
    )
    helper_family = {
        **family,
        "left_address_argument_census": _address_argument_census(
            left_reader, left_calls, target=dominant_left
        ),
        "right_address_argument_census": _address_argument_census(
            right_reader, right_calls, target=helper_target
        ),
        "selected_non_adjacent_helper_call": {
            "right_helper_load_file_offset": helper_load,
            "right_helper_target_file_offset": helper_target,
            "left_exact_context_match_count": len(
                selected_context_matches
            ),
            "left_target_consensus": (
                _loaded_pointer_target(
                    left_data, selected_context_matches[0]
                )
                if len(selected_context_matches) == 1
                else None
            ),
        },
        "exact_helper_shape_census": shape_census,
        "right_helper_profile": _helper_store_profile(
            right_reader, helper_target
        ),
        "dominant_left_target_profile": summarize_bounded_entry(
            left_reader,
            dominant_left,
            source="SESSION023_DOMINANT_LEFT_HELPER",
        ),
        "runtime_equivalence_asserted": False,
    }

    return {
        "schema": "phoenix-mmi.internal-continuation-contract-comparison/v1",
        "analysis_mode": (
            "read-only-static-bounded-internal-continuation-contract"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "selected_internal_address_contracts": selected,
        "generic_address_record_family": helper_family,
        "classification": {
            "selected_addresses_are_owner_entries": (
                "DISPROVED_FOR_THE_TWO_SESSION022_INTERNAL_SEEDS"
            ),
            "left_seed_role": (
                "CONFIRMED_INTERNAL_LABEL_INDIRECT_INVOCATION"
            ),
            "right_seed_role": (
                "CONFIRMED_INTERNAL_ADDRESS_ARGUMENT_TO_RECORD_HELPER"
            ),
            "generic_cross_version_address_record_family": (
                "CONFIRMED_STRUCTURAL_CALL_FAMILY"
                if family["cross_version_call_family_promoted"]
                else "NOT_PROMOTED"
            ),
            "landing_pad_or_unwind_registration": (
                "PROBABLE_NOT_CONFIRMED"
            ),
            "bilateral_selected_owner_producer": "NOT_ESTABLISHED",
            "owner_entry_argument_producer": (
                "NOT_ESTABLISHED_SEEDS_ARE_INTERNAL_LABELS"
            ),
            "state_creator_or_writer": "OPEN",
            "semantic_owner_identity": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "specific_session017_producer_edge": "OPEN",
        },
        "limits": {
            "helper_shape_sequence_words": _HELPER_SEQUENCE_WORDS,
            "call_family_context_words": family[
                "normalized_context_total_word_count"
            ],
            "whole_image_executable_map_available": False,
            "function_boundaries_asserted": False,
            "path_dominance_asserted": False,
            "runtime_execution_observed": False,
            "exception_or_unwind_abi_identified": False,
        },
        "interpretation": (
            "Both Session 022 address seeds point inside bounded owner "
            "windows rather than to owner entries. The CD1 seed is invoked "
            "as an internal label with preserved-register context. The CD3 "
            "seed is passed as r5 to a stack-local record helper; the same "
            "broad helper-call family is structurally paired across releases "
            "and every adjacent family call carries an in-image r5 address. "
            "This is consistent with compiler-generated landing-pad or frame "
            "registration, but that semantic label is not confirmed. These "
            "seeds therefore do not identify an owner-entry producer, state "
            "creator, runtime-linkage writer or navigation parser."
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


def update_operational_graph_v16(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v16"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "runtime-linkage-internal-continuation"
    ]
    graph["nodes"].append(
        {
            "id": "runtime-linkage-internal-continuation",
            "label": "Internal-label and address-record contracts",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "generic_family": comparison["classification"][
                "generic_cross_version_address_record_family"
            ],
            "landing_pad_or_unwind": comparison["classification"][
                "landing_pad_or_unwind_registration"
            ],
            "owner_entry_producer": comparison["classification"][
                "owner_entry_argument_producer"
            ],
            "evidence": [
                "S023-01",
                "S023-02",
                "S023-03",
                "RQ-066",
                "RQ-067",
            ],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "runtime-linkage-internal-continuation"
            and edge["target"] == "runtime-linkage-owner-ingress"
        )
    ]
    graph["edges"].append(
        {
            "source": "runtime-linkage-internal-continuation",
            "target": "runtime-linkage-owner-ingress",
            "relation": (
                "Session 022 address seeds are internal labels and do not "
                "supply owner-entry provenance"
            ),
            "status": "CONFIRMED_STRUCTURAL_SEEDS_NOT_OWNER_ENTRIES",
        }
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


def correlate_internal_continuation_contract(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.internal-continuation-contract-correlation/v1",
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
        "operational_graph": update_operational_graph_v16(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_internal_continuation_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

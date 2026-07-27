"""Target-specific producer return-use analysis for Session 027.

The analyzer starts from the single resolved producer-reference pair registered
by Session 026.  It classifies every exact PC-relative use of that target,
models the following linear result use, and compares only co-relocated
bilateral pairs.  Literal pools, decoded owners and helper targets remain
structural evidence rather than runtime or semantic claims.
"""

from __future__ import annotations

from collections import Counter
import copy
import re

from .accessor_dispatch import (
    _find_all,
    _literal_jsr_calls,
    _target_reference_profile,
)
from .binary import BinaryReader
from .call_return_producer import (
    _bounded_target_summary,
    _public_expression,
    _returned_object_geometry,
)
from .continuation_contract import _trace_call_argument
from .linkage_owner import _MemoryReader
from .navigation_storage import RUNTIME_BASE
from .object_dispatch import (
    _bounded_context,
    _destination_register,
    _resolve_static_expression,
    _trace_expression,
)
from .optical_callgraph import (
    _decode_window,
    _result_use,
    summarize_bounded_entry,
)
from .owner_producer import _roots_available
from .owner_provenance import (
    _classify_pointer_use,
    _expression_roots,
    _pc_referrer_index,
    _scan_direct_bsr_calls,
)


_CALL_REGISTER = re.compile(r"@r(\d+)$")
_REGISTER = re.compile(r"r(\d+)")
_POINTER_USE_BYTES = 32


def _compact_entry_summary(
    reader: BinaryReader, entry: int, *, source: str
) -> dict[str, object]:
    summary = summarize_bounded_entry(reader, entry, source=source)
    return {
        key: summary[key]
        for key in (
            "entry_file_offset",
            "window_length",
            "instruction_count",
            "known_instruction_count",
            "known_ratio",
            "normalized_shape_sha256",
            "prologue_save_pr_in_first_12_instructions",
            "return_count",
            "call_count",
            "resolved_static_call_count",
            "unresolved_indirect_call_count",
            "bounded_code_gate_passed",
            "function_boundary_asserted",
            "instruction_bytes_included",
        )
    }


def _target_pointer_use_census(
    reader: BinaryReader, target: int
) -> dict[str, object]:
    data = reader.read(0, reader.size)
    target_word = (RUNTIME_BASE + target).to_bytes(4, "big")
    exact_offsets = _find_all(data, target_word)
    aligned_offsets = [
        offset for offset in exact_offsets if offset % 4 == 0
    ]
    pc_index = _pc_referrer_index(data)
    memory = _MemoryReader(data)
    uses = []
    for literal in aligned_offsets:
        for referrer in pc_index.get(literal, []):
            classification = _classify_pointer_use(memory, referrer)
            call_site = None
            if classification["classification"] == "INDIRECT_CONTROL_TARGET":
                instructions = _decode_window(
                    memory, referrer, maximum_bytes=_POINTER_USE_BYTES
                )
                relative_index = int(
                    classification["relative_use_instruction_index"]
                )
                if relative_index < len(instructions):
                    call_site = int(instructions[relative_index].offset)
            uses.append(
                {
                    "literal_file_offset": literal,
                    "referrer_file_offset": referrer,
                    "classification": classification["classification"],
                    "relative_use_instruction_index": classification.get(
                        "relative_use_instruction_index"
                    ),
                    "loaded_register": classification.get("loaded_register"),
                    "call_site_file_offset": call_site,
                }
            )
    uses.sort(key=lambda row: int(row["referrer_file_offset"]))
    literal_calls = _literal_jsr_calls(data, image_size=len(data))
    profile = _target_reference_profile(
        data,
        literal_calls,
        target=target,
        image_size=len(data),
    )
    direct_bsr = sum(
        int(row["target_file_offset"]) == target
        for row in _scan_direct_bsr_calls(data)
    )
    return {
        "target_file_offset": target,
        "exact_word_occurrence_count": profile[
            "exact_word_occurrence_count"
        ],
        "aligned_word_occurrence_count": profile[
            "aligned_word_occurrence_count"
        ],
        "pc_relative_load_reference_count": profile[
            "pc_relative_load_reference_count"
        ],
        "adjacent_literal_jsr_count": profile[
            "adjacent_literal_jsr_count"
        ],
        "literal_pool_occurrence_used_by_adjacent_jsr_count": profile[
            "literal_pool_occurrence_used_by_adjacent_jsr_count"
        ],
        "data_only_aligned_occurrence_count": profile[
            "data_only_aligned_occurrence_count"
        ],
        "all_aligned_occurrences_are_pc_relative_literals": profile[
            "all_aligned_occurrences_are_pc_relative_literals"
        ],
        "direct_bsr_target_count": direct_bsr,
        "pointer_use_classification_counts": dict(
            sorted(Counter(row["classification"] for row in uses).items())
        ),
        "uses": uses,
        "whole_image_pointer_census_is_syntactic": True,
        "direct_callback_record_semantics_asserted": False,
    }


def _call_target_expression(
    reader: BinaryReader,
    instructions: list[object],
    call_index: int,
) -> dict[str, object]:
    call = instructions[call_index]
    if call.flow == "call" and isinstance(call.target, int):
        target = int(call.target)
        return {
            "kind": "IN_IMAGE_POINTER",
            "target_file_offset": target,
        }
    match = _CALL_REGISTER.fullmatch(call.operands)
    if call.mnemonic != "jsr" or match is None:
        return {"kind": "UNSUPPORTED_CALL_FORM"}
    return _trace_expression(
        instructions,
        call_index,
        int(match.group(1)),
        image_size=reader.size,
    )


def _call_arguments(
    reader: BinaryReader,
    instructions: list[object],
    call_index: int,
) -> dict[str, dict[str, object]]:
    return {
        f"r{register}": _public_expression(
            reader,
            _trace_call_argument(
                instructions,
                call_index,
                register,
                image_size=reader.size,
            ),
        )
        for register in range(4, 8)
    }


def _next_linear_call_index(
    instructions: list[object], call_index: int
) -> int | None:
    return next(
        (
            index
            for index in range(call_index + 1, len(instructions))
            if instructions[index].flow in {"call", "indirect-call"}
        ),
        None,
    )


def _register_access(
    instruction: object, register: int
) -> tuple[bool, bool]:
    token = f"r{register}"
    occurrences = [
        int(value) for value in _REGISTER.findall(instruction.operands)
    ]
    if register not in occurrences:
        return False, False
    destination = _destination_register(instruction)
    write = destination == register
    read = bool(destination != register)
    if write:
        source = instruction.operands.rsplit(",", 1)[0]
        read = bool(
            token in source
            or instruction.mnemonic
            in {
                "add",
                "sub",
                "and",
                "or",
                "xor",
                "shlr2",
                "swap.b",
                "swap.w",
                "xtrct",
                "shad",
                "shld",
            }
        )
    return read, write


def _entry_register_profile(
    instructions: list[object], register: int
) -> dict[str, object]:
    reads = 0
    writes = 0
    unknown = 0
    terminal = "WINDOW_END"
    for index, instruction in enumerate(instructions):
        if instruction.flow in {"call", "indirect-call"}:
            delay = (
                instructions[index + 1]
                if instruction.delayed and index + 1 < len(instructions)
                else None
            )
            if delay is not None:
                if delay.mnemonic == "unknown":
                    unknown += 1
                read, write = _register_access(delay, register)
                reads += int(read)
                writes += int(write)
                if write and not read:
                    terminal = "DELAY_SLOT_OVERWRITE_BEFORE_CALL"
                    break
            terminal = "CALLER_SAVED_CLOBBER"
            break
        if instruction.mnemonic == "unknown":
            unknown += 1
        read, write = _register_access(instruction, register)
        reads += int(read)
        writes += int(write)
        if write and not read:
            terminal = "EXPLICIT_OVERWRITE"
            break
    return {
        "register": f"r{register}",
        "modeled_read_count_before_terminal": reads,
        "modeled_write_count_before_terminal": writes,
        "unknown_instruction_count_before_terminal": unknown,
        "terminal": terminal,
        "direct_entry_value_use_confirmed": reads > 0,
        "unknown_instructions_limit_negative_result": unknown > 0,
    }


def _static_handoff_target(
    reader: BinaryReader,
    target: int,
) -> dict[str, object]:
    instructions = _decode_window(reader, target)
    return {
        "summary": _compact_entry_summary(
            reader, target, source="SESSION027_STATIC_HANDOFF_TARGET"
        ),
        "entry_r5_profile": _entry_register_profile(instructions, 5),
        "registration_store_established": False,
    }


def _flow_contract(
    reader: BinaryReader,
    pointer_use: dict[str, object],
    producer_target: int,
) -> dict[str, object]:
    call_offset = pointer_use.get("call_site_file_offset")
    if not isinstance(call_offset, int):
        raise ValueError("producer pointer use does not resolve to a call")
    data = reader.read(0, reader.size)
    instructions, boundary = _bounded_context(
        _MemoryReader(data), call_offset
    )
    call_index = next(
        index
        for index, instruction in enumerate(instructions)
        if int(instruction.offset) == call_offset
    )
    target_expression = _call_target_expression(
        reader, instructions, call_index
    )
    target_resolution = _resolve_static_expression(
        reader, target_expression
    )
    if target_resolution.get("target_file_offset") != producer_target:
        raise ValueError("pointer use does not call the registered producer")
    producer_arguments = _call_arguments(
        reader, instructions, call_index
    )
    result_use = _result_use(instructions, call_index)
    next_index = _next_linear_call_index(instructions, call_index)
    next_call = None
    geometry = None
    classification = "OTHER_LINEAR_RESULT_USE"
    owner_argument_compatible = False
    if next_index is None:
        if result_use["tested_immediately_or_locally"]:
            classification = "RETURN_NULL_TEST_WITHOUT_LINEAR_CALL"
    else:
        next_target_expression = _call_target_expression(
            reader, instructions, next_index
        )
        next_target_public = _public_expression(
            reader, next_target_expression
        )
        next_arguments = _call_arguments(
            reader, instructions, next_index
        )
        geometry = _returned_object_geometry(
            next_target_expression,
            _trace_call_argument(
                instructions,
                next_index,
                4,
                image_size=reader.size,
            ),
        )
        return_arguments = [
            register
            for register, expression in next_arguments.items()
            if "CALL_RETURN" in expression["root_classes"]
        ]
        target_return_rooted = (
            "CALL_RETURN"
            in _expression_roots(next_target_expression)
        )
        next_call = {
            "call_site_file_offset": int(
                instructions[next_index].offset
            ),
            "target": next_target_public,
            "arguments": next_arguments,
            "call_return_argument_registers": return_arguments,
            "target_crosses_call_return": target_return_rooted,
        }
        if (
            target_return_rooted
            and geometry["shared_call_return_vtable_grammar"]
            and "CALL_RETURN"
            in next_arguments["r4"]["root_classes"]
        ):
            classification = "RETURN_OBJECT_DYNAMIC_DISPATCH"
            owner_argument_compatible = bool(
                _roots_available(next_arguments["r4"]["root_classes"])
                and _roots_available(next_arguments["r6"]["root_classes"])
            )
        elif (
            next_target_public["resolution_status"]
            == "RESOLVED_IN_IMAGE_POINTER"
            and return_arguments
        ):
            classification = "RETURN_FORWARDED_TO_STATIC_HELPER"
            target = next_target_public.get("target_file_offset")
            if isinstance(target, int):
                next_call["static_target"] = _static_handoff_target(
                    reader, target
                )

    context_start = int(boundary["context_start_file_offset"])
    return {
        "literal_file_offset": pointer_use["literal_file_offset"],
        "referrer_file_offset": pointer_use["referrer_file_offset"],
        "producer_call_site_file_offset": call_offset,
        "producer_relative_use_instruction_index": pointer_use[
            "relative_use_instruction_index"
        ],
        "context_start_file_offset": context_start,
        "context_start_reason": boundary["context_start_reason"],
        "producer_arguments": producer_arguments,
        "result_use": result_use,
        "next_linear_call": next_call,
        "returned_object_geometry": geometry,
        "classification": classification,
        "owner_argument_compatible_dynamic_dispatch": (
            owner_argument_compatible
        ),
        "owner_summary": _compact_entry_summary(
            reader, context_start, source="SESSION027_PRODUCER_CALL_OWNER"
        ),
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }


def _flow_signature(flow: dict[str, object]) -> tuple[object, ...]:
    next_call = flow["next_linear_call"]
    if next_call is None:
        return (flow["classification"], None)
    return (
        flow["classification"],
        next_call["target"]["canonical"],
        *(
            next_call["arguments"][f"r{register}"]["canonical"]
            for register in range(4, 8)
        ),
    )


def _pair_flow_contracts(
    left: list[dict[str, object]],
    right: list[dict[str, object]],
    *,
    target_delta: int,
    session026_candidates: dict[str, dict[int, int]],
) -> list[dict[str, object]]:
    rows = []
    for ordinal, (left_flow, right_flow) in enumerate(
        zip(left, right, strict=False), start=1
    ):
        offsets_equal = all(
            int(right_flow[key]) - int(left_flow[key]) == target_delta
            for key in (
                "literal_file_offset",
                "referrer_file_offset",
                "producer_call_site_file_offset",
                "context_start_file_offset",
            )
        )
        owner_equal = (
            left_flow["owner_summary"]["normalized_shape_sha256"]
            == right_flow["owner_summary"]["normalized_shape_sha256"]
        )
        owner_code_gated = bool(
            left_flow["owner_summary"]["bounded_code_gate_passed"]
            and right_flow["owner_summary"]["bounded_code_gate_passed"]
        )
        producer_arguments_equal = all(
            left_flow["producer_arguments"][f"r{register}"]["canonical"]
            == right_flow["producer_arguments"][f"r{register}"]["canonical"]
            for register in range(4, 8)
        )
        flow_equal = _flow_signature(left_flow) == _flow_signature(
            right_flow
        )
        geometry_equal = (
            left_flow["returned_object_geometry"]
            == right_flow["returned_object_geometry"]
        )
        left_candidate = session026_candidates["left"].get(
            int(left_flow["producer_call_site_file_offset"])
        )
        right_candidate = session026_candidates["right"].get(
            int(right_flow["producer_call_site_file_offset"])
        )
        gates = {
            "all_file_offsets_co_relocated": offsets_equal,
            "owner_normalized_shape_equal": owner_equal,
            "owner_code_gate_passed_both": owner_code_gated,
            "producer_arguments_equal": producer_arguments_equal,
            "return_flow_signature_equal": flow_equal,
            "returned_object_geometry_equal": geometry_equal,
        }
        gates["bilateral_flow_gate_passed"] = all(gates.values())
        rows.append(
            {
                "flow_ordinal": ordinal,
                "left": left_flow,
                "right": right_flow,
                "session025_candidate_family_ordinal": (
                    left_candidate
                    if left_candidate == right_candidate
                    else None
                ),
                "bilateral_gates": gates,
                "classification": left_flow["classification"],
                "runtime_equivalence_asserted": False,
                "selected_owner_target_link_established": False,
            }
        )
    return rows


def _session026_candidate_offsets(
    session026: dict[str, object],
) -> dict[str, dict[int, int]]:
    result = {"left": {}, "right": {}}
    for row in session026["producer_call_family_census"]["pairs"]:
        ordinal = row["session025_candidate_family_ordinal"]
        if ordinal is None:
            continue
        result["left"][
            int(row["left_call_site_file_offset"])
        ] = int(ordinal)
        result["right"][
            int(row["right_call_site_file_offset"])
        ] = int(ordinal)
    return result


def _static_handoff_pairs(
    flow_pairs: list[dict[str, object]],
    *,
    target_delta: int,
) -> list[dict[str, object]]:
    rows = []
    for flow in flow_pairs:
        if flow["classification"] != "RETURN_FORWARDED_TO_STATIC_HELPER":
            continue
        left = flow["left"]["next_linear_call"]
        right = flow["right"]["next_linear_call"]
        left_target = int(left["target"]["target_file_offset"])
        right_target = int(right["target"]["target_file_offset"])
        left_static = left["static_target"]
        right_static = right["static_target"]
        rows.append(
            {
                "flow_ordinal": flow["flow_ordinal"],
                "left_target_file_offset": left_target,
                "right_target_file_offset": right_target,
                "target_file_offset_delta": right_target - left_target,
                "target_delta_matches_producer_family": (
                    right_target - left_target == target_delta
                ),
                "code_gate_passed_both": bool(
                    left_static["summary"]["bounded_code_gate_passed"]
                    and right_static["summary"]["bounded_code_gate_passed"]
                ),
                "normalized_target_shape_equal": (
                    left_static["summary"]["normalized_shape_sha256"]
                    == right_static["summary"]["normalized_shape_sha256"]
                ),
                "left": left_static,
                "right": right_static,
                "direct_modeled_entry_r5_use_confirmed_both": bool(
                    left_static["entry_r5_profile"][
                        "direct_entry_value_use_confirmed"
                    ]
                    and right_static["entry_r5_profile"][
                        "direct_entry_value_use_confirmed"
                    ]
                ),
                "registration_path_established": False,
                "runtime_equivalence_asserted": False,
            }
        )
    return rows


def analyze_producer_return_family(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    session026: dict[str, object],
) -> dict[str, object]:
    """Classify every exact static use of the Session 026 producer pair."""

    target_pair = session026["producer_target_pair"]
    left_target = int(target_pair["left_target_file_offset"])
    right_target = int(target_pair["right_target_file_offset"])
    target_delta = right_target - left_target
    censuses = {
        "left": _target_pointer_use_census(left_reader, left_target),
        "right": _target_pointer_use_census(right_reader, right_target),
    }
    for side in ("left", "right"):
        classifications = censuses[side][
            "pointer_use_classification_counts"
        ]
        if classifications != {"INDIRECT_CONTROL_TARGET": 18}:
            raise ValueError(
                "producer pointer topology is not the expected call-only set"
            )
    flows = {
        "left": [
            _flow_contract(left_reader, row, left_target)
            for row in censuses["left"]["uses"]
        ],
        "right": [
            _flow_contract(right_reader, row, right_target)
            for row in censuses["right"]["uses"]
        ],
    }
    pairs = _pair_flow_contracts(
        flows["left"],
        flows["right"],
        target_delta=target_delta,
        session026_candidates=_session026_candidate_offsets(session026),
    )
    static_handoffs = _static_handoff_pairs(
        pairs, target_delta=target_delta
    )
    classifications = Counter(row["classification"] for row in pairs)
    dynamic = [
        row
        for row in pairs
        if row["classification"] == "RETURN_OBJECT_DYNAMIC_DISPATCH"
    ]
    field_counts = Counter(
        int(
            row["left"]["returned_object_geometry"][
                "target_field_displacement"
            ]
        )
        for row in dynamic
    )
    r6_counts = Counter(
        str(
            row["left"]["next_linear_call"]["arguments"]["r6"][
                "canonical"
            ]
        )
        for row in dynamic
    )
    compatible = [
        row
        for row in dynamic
        if row["left"]["owner_argument_compatible_dynamic_dispatch"]
        and row["right"]["owner_argument_compatible_dynamic_dispatch"]
    ]
    new_compatible = [
        row
        for row in compatible
        if row["session025_candidate_family_ordinal"] is None
    ]
    unique_owner_pairs = {
        (
            int(row["left"]["context_start_file_offset"]),
            int(row["right"]["context_start_file_offset"]),
        )
        for row in pairs
    }
    all_flow_gates = all(
        row["bilateral_gates"]["bilateral_flow_gate_passed"]
        for row in pairs
    )
    pointer_topology_equal = bool(
        censuses["left"]["exact_word_occurrence_count"]
        == censuses["right"]["exact_word_occurrence_count"]
        == 17
        and censuses["left"]["pc_relative_load_reference_count"]
        == censuses["right"]["pc_relative_load_reference_count"]
        == 18
        and censuses["left"]["data_only_aligned_occurrence_count"]
        == censuses["right"]["data_only_aligned_occurrence_count"]
        == 0
        and censuses["left"]["direct_bsr_target_count"]
        == censuses["right"]["direct_bsr_target_count"]
        == 0
    )
    return {
        "schema": "phoenix-mmi.producer-return-family-comparison/v1",
        "analysis_mode": (
            "read-only-static-session026-target-specific-return-use-census"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "producer_target_pair": copy.deepcopy(target_pair),
        "pointer_use_census": censuses,
        "return_flow_pairs": pairs,
        "static_handoff_pairs": static_handoffs,
        "classification": {
            "exact_target_word_occurrences_per_release": 17,
            "pc_relative_target_reference_pairs": 18,
            "adjacent_literal_jsr_reference_pairs": 7,
            "all_pointer_uses_are_indirect_control_targets": (
                "CONFIRMED"
            ),
            "data_only_target_pointer_occurrences": 0,
            "direct_bsr_target_references": 0,
            "pointer_topology_equal": pointer_topology_equal,
            "bilateral_return_flow_pair_count": len(pairs),
            "bilateral_flow_gates_all_passed": all_flow_gates,
            "unique_exact_code_gated_owner_pair_count": len(
                unique_owner_pairs
            ),
            "return_flow_classification_counts": dict(
                sorted(classifications.items())
            ),
            "dynamic_dispatch_target_field_counts": {
                str(key): value
                for key, value in sorted(field_counts.items())
            },
            "dynamic_dispatch_r6_contract_counts": dict(
                sorted(r6_counts.items())
            ),
            "owner_argument_compatible_dynamic_dispatch_count": len(
                compatible
            ),
            "new_owner_argument_compatible_dispatch_count": len(
                new_compatible
            ),
            "new_compatible_dispatch_target_fields": sorted(
                {
                    int(
                        row["left"]["returned_object_geometry"][
                            "target_field_displacement"
                        ]
                    )
                    for row in new_compatible
                }
            ),
            "static_handoff_pair_count": len(static_handoffs),
            "static_handoff_code_gated_pair_count": sum(
                row["code_gate_passed_both"] for row in static_handoffs
            ),
            "static_handoff_equal_target_shape_count": sum(
                row["normalized_target_shape_equal"]
                for row in static_handoffs
            ),
            "static_handoff_direct_modeled_r5_use_pair_count": sum(
                row["direct_modeled_entry_r5_use_confirmed_both"]
                for row in static_handoffs
            ),
            "producer_target_code_entry": session026["classification"][
                "producer_target_code_entry"
            ],
            "producer_implementation": "NOT_ESTABLISHED",
            "static_target_registration_evidence": (
                "BOUNDED_NEGATIVE_CALL_LITERAL_MODEL"
            ),
            "static_handoff_registration_path": "NOT_ESTABLISHED",
            "returned_object_type": "OPEN",
            "returned_object_creator_or_writer": "OPEN",
            "selected_owner_target_link": "NOT_ESTABLISHED",
            "unique_bilateral_owner_entry_caller": "NOT_ESTABLISHED",
            "semantic_owner_identity": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
        },
        "limits": {
            "producer_source_session": 26,
            "pointer_use_lookahead_bytes": _POINTER_USE_BYTES,
            "whole_image_pointer_census_is_syntactic": True,
            "only_exact_registered_target_words_followed": True,
            "arbitrary_raw_image_code_scan_performed": False,
            "whole_image_executable_map_available": False,
            "function_boundaries_asserted": False,
            "path_dominance_asserted": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "The Session 026 producer target appears in seventeen aligned "
            "literal-pool words per release with eighteen PC-relative "
            "referrers. Every referrer is used as an indirect control target; "
            "there are no data-only target words or direct BSR references. "
            "All eighteen bilateral flows pass co-relocation, exact owner "
            "shape and code gates. Fifteen results feed a stable returned-"
            "object dispatch grammar covering fields 28 through 92 in steps "
            "of eight, two are forwarded as r5 to co-relocated code-gated "
            "static helpers, and one is null-tested without a following "
            "linear call. Five dynamic dispatches preserve available r4/r6, "
            "including one field-60 context outside Session 025. The two "
            "static helper targets have unequal shapes and no confirmed "
            "modeled entry-r5 use; target registration, producer "
            "implementation, object type/writer and selected-owner linkage "
            "remain open."
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


def update_operational_graph_v20(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v20"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "producer-return-use-family"
    ]
    graph["nodes"].append(
        {
            "id": "producer-return-use-family",
            "label": "Producer return-use family",
            "status": "CONFIRMED_BILATERAL_STRUCTURAL_FAMILY",
            "flow_pair_count": comparison["classification"][
                "bilateral_return_flow_pair_count"
            ],
            "dynamic_dispatch_count": comparison["classification"][
                "return_flow_classification_counts"
            ]["RETURN_OBJECT_DYNAMIC_DISPATCH"],
            "owner_argument_compatible_dispatch_count": comparison[
                "classification"
            ]["owner_argument_compatible_dynamic_dispatch_count"],
            "evidence": ["S027-01", "S027-02", "RQ-083", "RQ-084"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "call-return-producer-family"
            and edge["target"] == "producer-return-use-family"
        )
        and not (
            edge["source"] == "producer-return-use-family"
            and edge["target"] == "runtime-linkage-owner-ingress"
        )
    ]
    graph["edges"].extend(
        [
            {
                "source": "call-return-producer-family",
                "target": "producer-return-use-family",
                "relation": (
                    "supplies eighteen bilateral return-use contexts"
                ),
                "status": "CONFIRMED_STRUCTURAL",
            },
            {
                "source": "producer-return-use-family",
                "target": "runtime-linkage-owner-ingress",
                "relation": (
                    "exact producer pointers are call literals only; no "
                    "selected-owner registration edge is established"
                ),
                "status": "BOUNDED_NEGATIVE_STATIC_POINTER_MODEL",
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


def correlate_producer_return_family(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.producer-return-family-correlation/v1",
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
        "operational_graph": update_operational_graph_v20(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_producer_return_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

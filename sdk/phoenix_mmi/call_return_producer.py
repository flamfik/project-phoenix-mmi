"""Bilateral CALL_RETURN producer analysis for Session 026.

The analyzer follows only the four Session 025 promoted dispatches.  It
identifies the immediately preceding call crossed by both the target and
receiver slices, resolves that call conservatively, and compares its context,
arguments and returned-object field geometry across the two principal images.
Resolved targets remain reference anchors until their bounded code gates pass.
"""

from __future__ import annotations

import copy
import hashlib
import re

from .accessor_dispatch import _callsite_signature, _literal_jsr_calls
from .binary import BinaryReader
from .continuation_contract import _trace_call_argument
from .object_dispatch import (
    _canonical_expression,
    _collect_load_offsets,
    _resolve_static_expression,
    _trace_expression,
)
from .optical_callgraph import _decode_window, summarize_bounded_entry
from .owner_provenance import _expression_roots


_CALL_REGISTER = re.compile(r"@r(\d+)$")
_OWNER_FORWARD_BYTES = 0x180


def _public_expression(
    reader: BinaryReader, expression: dict[str, object]
) -> dict[str, object]:
    resolution = _resolve_static_expression(reader, expression)
    result = {
        "canonical": _canonical_expression(expression),
        "root_classes": _expression_roots(expression),
        "load_path": _collect_load_offsets(expression),
        "resolution_status": resolution["status"],
    }
    target = resolution.get("target_file_offset")
    if isinstance(target, int):
        result["target_file_offset"] = target
    return result


def _last_preceding_call_index(
    instructions: list[object], before_index: int
) -> int | None:
    return next(
        (
            index
            for index in range(before_index - 1, -1, -1)
            if instructions[index].flow in {"call", "indirect-call"}
        ),
        None,
    )


def _constant_and_other(
    expression: dict[str, object],
) -> tuple[int, dict[str, object]] | None:
    if expression.get("kind") != "ADD":
        return None
    left = expression["left"]
    right = expression["right"]
    if left.get("kind") == "CONSTANT":
        return int(left["value"]), right
    if right.get("kind") == "CONSTANT":
        return int(right["value"]), left
    return None


def _is_return_vtable(expression: dict[str, object]) -> bool:
    return bool(
        expression.get("kind") == "LOAD"
        and int(expression.get("width_bits", 0)) == 32
        and int(expression.get("displacement", -1)) == 0
        and expression["base"].get("kind") == "CALL_RETURN"
    )


def _effective_vtable_field(
    expression: dict[str, object],
) -> int | None:
    if (
        expression.get("kind") != "LOAD"
        or int(expression.get("width_bits", 0)) != 32
    ):
        return None
    displacement = int(expression["displacement"])
    base = expression["base"]
    if _is_return_vtable(base):
        return displacement
    added = _constant_and_other(base)
    if added is None:
        return None
    constant, other = added
    if not _is_return_vtable(other):
        return None
    return constant + displacement


def _receiver_adjustment_field(
    expression: dict[str, object],
) -> int | None:
    if expression.get("kind") != "ADD":
        return None
    sides = (expression["left"], expression["right"])
    return_side = next(
        (side for side in sides if side.get("kind") == "CALL_RETURN"),
        None,
    )
    load_side = next(
        (
            side
            for side in sides
            if side.get("kind") == "LOAD"
            and int(side.get("width_bits", 0)) == 16
        ),
        None,
    )
    if return_side is None or load_side is None:
        return None
    added = _constant_and_other(load_side["base"])
    if added is None:
        return None
    constant, other = added
    if not _is_return_vtable(other):
        return None
    return constant + int(load_side["displacement"])


def _returned_object_geometry(
    target_expression: dict[str, object],
    receiver_expression: dict[str, object],
) -> dict[str, object]:
    target_field = _effective_vtable_field(target_expression)
    adjustment_field = _receiver_adjustment_field(receiver_expression)
    stride = (
        target_field - adjustment_field
        if target_field is not None and adjustment_field is not None
        else None
    )
    return {
        "target_field_displacement": target_field,
        "receiver_adjustment_field_displacement": adjustment_field,
        "target_after_adjustment_stride": stride,
        "shared_call_return_vtable_grammar": bool(
            target_field is not None
            and adjustment_field is not None
            and stride == 4
        ),
    }


def _producer_target(
    reader: BinaryReader,
    instructions: list[object],
    producer_index: int,
) -> dict[str, object]:
    call = instructions[producer_index]
    if call.flow == "call" and isinstance(call.target, int):
        target = int(call.target)
        return {
            "canonical": "DIRECT_BSR",
            "root_classes": ["IN_IMAGE_POINTER"],
            "load_path": [],
            "resolution_status": (
                "RESOLVED_IN_IMAGE_POINTER"
                if 0 <= target < reader.size
                else "OUT_OF_IMAGE"
            ),
            **(
                {"target_file_offset": target}
                if 0 <= target < reader.size
                else {}
            ),
        }
    match = _CALL_REGISTER.fullmatch(call.operands)
    if call.mnemonic != "jsr" or match is None:
        return {
            "canonical": "UNSUPPORTED_CALL_FORM",
            "root_classes": ["UNKNOWN"],
            "load_path": [],
            "resolution_status": "DYNAMIC_OR_UNSUPPORTED",
        }
    expression = _trace_expression(
        instructions,
        producer_index,
        int(match.group(1)),
        image_size=reader.size,
    )
    return _public_expression(reader, expression)


def _bounded_target_summary(
    reader: BinaryReader, target: int
) -> dict[str, object]:
    summary = summarize_bounded_entry(
        reader, target, source="SESSION026_RESOLVED_PRODUCER_TARGET"
    )
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


def _candidate_contract(
    reader: BinaryReader,
    prior_contract: dict[str, object],
) -> dict[str, object]:
    owner_start = int(prior_contract["owner_start_file_offset"])
    consumer_index = int(
        prior_contract["call_relative_instruction_index"]
    )
    instructions = _decode_window(
        reader, owner_start, maximum_bytes=_OWNER_FORWARD_BYTES
    )
    if consumer_index >= len(instructions):
        raise ValueError("Session 025 consumer falls outside owner window")
    consumer = instructions[consumer_index]
    if int(consumer.offset) != int(
        prior_contract["call_site_file_offset"]
    ):
        raise ValueError("Session 025 consumer offset did not reproduce")
    consumer_register = _CALL_REGISTER.fullmatch(consumer.operands)
    if consumer.mnemonic != "jsr" or consumer_register is None:
        raise ValueError("Session 025 consumer is not an indirect JSR")

    target_expression = _trace_expression(
        instructions,
        consumer_index,
        int(consumer_register.group(1)),
        image_size=reader.size,
    )
    receiver_expression = _trace_call_argument(
        instructions,
        consumer_index,
        4,
        image_size=reader.size,
    )
    consumer_r6 = _trace_call_argument(
        instructions,
        consumer_index,
        6,
        image_size=reader.size,
    )
    producer_index = _last_preceding_call_index(
        instructions, consumer_index
    )
    if producer_index is None:
        raise ValueError("no preceding producer call for Session 025 consumer")
    producer = instructions[producer_index]
    producer_target = _producer_target(
        reader, instructions, producer_index
    )
    producer_arguments = {
        f"r{register}": _public_expression(
            reader,
            _trace_call_argument(
                instructions,
                producer_index,
                register,
                image_size=reader.size,
            ),
        )
        for register in range(4, 8)
    }
    geometry = _returned_object_geometry(
        target_expression, receiver_expression
    )
    target_roots = _expression_roots(target_expression)
    receiver_roots = _expression_roots(receiver_expression)
    target = producer_target.get("target_file_offset")
    return {
        "owner_start_file_offset": owner_start,
        "consumer_call_site_file_offset": int(consumer.offset),
        "consumer_call_relative_instruction_index": consumer_index,
        "producer_call_site_file_offset": int(producer.offset),
        "producer_call_relative_instruction_index": producer_index,
        "producer_call_relative_byte_offset": (
            int(producer.offset) - owner_start
        ),
        "producer_call_form": (
            "DIRECT_BSR" if producer.flow == "call" else "INDIRECT_JSR"
        ),
        "producer_target": producer_target,
        "producer_arguments": producer_arguments,
        "returned_object_geometry": geometry,
        "consumer_contract": {
            "target": _public_expression(reader, target_expression),
            "r4": _public_expression(reader, receiver_expression),
            "r6": _public_expression(reader, consumer_r6),
        },
        "producer_target_owner_relative_offset": (
            int(target) - owner_start if isinstance(target, int) else None
        ),
        "gates": {
            "target_slice_crosses_call_return": (
                "CALL_RETURN" in target_roots
            ),
            "receiver_slice_crosses_call_return": (
                "CALL_RETURN" in receiver_roots
            ),
            "same_immediately_preceding_producer_call": bool(
                "CALL_RETURN" in target_roots
                and "CALL_RETURN" in receiver_roots
            ),
            "producer_target_resolved_in_image": (
                producer_target["resolution_status"]
                == "RESOLVED_IN_IMAGE_POINTER"
            ),
            "returned_object_geometry_passed": geometry[
                "shared_call_return_vtable_grammar"
            ],
        },
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }


def _signature_sha256(signature: tuple[int, ...] | None) -> str | None:
    if signature is None:
        return None
    payload = b"".join(int(word).to_bytes(2, "big") for word in signature)
    return hashlib.sha256(payload).hexdigest()


def _target_call_census(
    reader: BinaryReader, target: int
) -> list[dict[str, object]]:
    data = reader.read(0, reader.size)
    rows = [
        row
        for row in _literal_jsr_calls(data, image_size=len(data))
        if int(row["target_file_offset"]) == target
    ]
    return [
        {
            "load_file_offset": int(row["load_file_offset"]),
            "call_site_file_offset": int(row["call_site_offset"]),
            "normalized_context_sha256": _signature_sha256(
                _callsite_signature(data, int(row["load_file_offset"]))
            ),
        }
        for row in rows
    ]


def _pair_target_calls(
    left: list[dict[str, object]],
    right: list[dict[str, object]],
    *,
    target_delta: int,
    candidate_offsets: dict[str, dict[int, int]],
) -> dict[str, object]:
    rows = []
    for ordinal, (left_row, right_row) in enumerate(
        zip(left, right, strict=False), start=1
    ):
        left_offset = int(left_row["call_site_file_offset"])
        right_offset = int(right_row["call_site_file_offset"])
        left_family = candidate_offsets["left"].get(left_offset)
        right_family = candidate_offsets["right"].get(right_offset)
        rows.append(
            {
                "ordinal": ordinal,
                "left_call_site_file_offset": left_offset,
                "right_call_site_file_offset": right_offset,
                "file_offset_delta": right_offset - left_offset,
                "delta_matches_producer_target": (
                    right_offset - left_offset == target_delta
                ),
                "normalized_context_sha256": left_row[
                    "normalized_context_sha256"
                ],
                "normalized_context_equal": (
                    left_row["normalized_context_sha256"]
                    == right_row["normalized_context_sha256"]
                    and left_row["normalized_context_sha256"] is not None
                ),
                "session025_candidate_family_ordinal": (
                    left_family
                    if left_family == right_family
                    else None
                ),
            }
        )
    return {
        "left_literal_jsr_reference_count": len(left),
        "right_literal_jsr_reference_count": len(right),
        "paired_reference_count": len(rows),
        "count_equal": len(left) == len(right),
        "all_offsets_co_relocated": bool(
            rows
            and len(left) == len(right)
            and all(row["delta_matches_producer_target"] for row in rows)
        ),
        "all_normalized_contexts_equal": bool(
            rows
            and len(left) == len(right)
            and all(row["normalized_context_equal"] for row in rows)
        ),
        "session025_candidate_reference_pair_count": sum(
            row["session025_candidate_family_ordinal"] is not None
            for row in rows
        ),
        "pairs": rows,
        "global_census_is_target_specific_and_syntactic": True,
    }


def _compare_candidates(
    left: dict[str, object],
    right: dict[str, object],
) -> dict[str, object]:
    argument_names = ("r4", "r5", "r6", "r7")
    arguments_equal = all(
        left["producer_arguments"][name]["canonical"]
        == right["producer_arguments"][name]["canonical"]
        for name in argument_names
    )
    geometry_equal = (
        left["returned_object_geometry"]
        == right["returned_object_geometry"]
    )
    gates = {
        "producer_relative_instruction_index_equal": (
            left["producer_call_relative_instruction_index"]
            == right["producer_call_relative_instruction_index"]
        ),
        "producer_relative_byte_offset_equal": (
            left["producer_call_relative_byte_offset"]
            == right["producer_call_relative_byte_offset"]
        ),
        "producer_target_expression_equal": (
            left["producer_target"]["canonical"]
            == right["producer_target"]["canonical"]
        ),
        "producer_target_resolved_both": bool(
            left["gates"]["producer_target_resolved_in_image"]
            and right["gates"]["producer_target_resolved_in_image"]
        ),
        "producer_target_owner_relative_offset_equal": (
            left["producer_target_owner_relative_offset"]
            == right["producer_target_owner_relative_offset"]
        ),
        "producer_arguments_r4_r7_equal": arguments_equal,
        "returned_object_geometry_equal": geometry_equal,
        "returned_object_geometry_passed_both": bool(
            left["gates"]["returned_object_geometry_passed"]
            and right["gates"]["returned_object_geometry_passed"]
        ),
        "same_preceding_call_confirmed_both": bool(
            left["gates"]["same_immediately_preceding_producer_call"]
            and right["gates"]["same_immediately_preceding_producer_call"]
        ),
    }
    gates["bilateral_producer_reference_gate_passed"] = all(gates.values())
    return gates


def analyze_call_return_producer(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    session025: dict[str, object],
) -> dict[str, object]:
    """Correlate the immediate producers of the four Session 025 returns."""

    promoted = [
        row
        for row in session025["candidate_families"]
        if row["argument_compatible_candidate_promoted"]
    ]
    if len(promoted) != 4:
        raise ValueError("Session 025 does not expose four promoted families")

    candidates = []
    candidate_offsets = {"left": {}, "right": {}}
    for family in promoted:
        ordinal = int(family["candidate_family_ordinal"])
        side_contracts = {}
        for side, reader in (
            ("left", left_reader),
            ("right", right_reader),
        ):
            contracts = family[side]["contracts"]
            if len(contracts) != 1:
                raise ValueError("promoted family is not one-to-one")
            contract = _candidate_contract(reader, contracts[0])
            side_contracts[side] = contract
            candidate_offsets[side][
                int(contract["producer_call_site_file_offset"])
            ] = ordinal
        gates = _compare_candidates(
            side_contracts["left"], side_contracts["right"]
        )
        candidates.append(
            {
                "candidate_family_ordinal": ordinal,
                "owner_shape_sha256": family["owner_shape_sha256"],
                "left": side_contracts["left"],
                "right": side_contracts["right"],
                "bilateral_gates": gates,
                "classification": (
                    "CONFIRMED_BILATERAL_CALL_RETURN_PRODUCER_REFERENCE"
                    if gates["bilateral_producer_reference_gate_passed"]
                    else "REJECTED_BILATERAL_PRODUCER_GATE"
                ),
                "selected_owner_target_link_established": False,
                "runtime_equivalence_asserted": False,
            }
        )

    left_targets = {
        row["left"]["producer_target"].get("target_file_offset")
        for row in candidates
    }
    right_targets = {
        row["right"]["producer_target"].get("target_file_offset")
        for row in candidates
    }
    unique_resolved_pair = bool(
        len(left_targets) == 1
        and len(right_targets) == 1
        and all(isinstance(value, int) for value in left_targets | right_targets)
    )
    if not unique_resolved_pair:
        raise ValueError("candidate producers do not converge on one target pair")
    left_target = int(next(iter(left_targets)))
    right_target = int(next(iter(right_targets)))
    target_delta = right_target - left_target
    target_summaries = {
        "left": _bounded_target_summary(left_reader, left_target),
        "right": _bounded_target_summary(right_reader, right_target),
    }
    call_family = _pair_target_calls(
        _target_call_census(left_reader, left_target),
        _target_call_census(right_reader, right_target),
        target_delta=target_delta,
        candidate_offsets=candidate_offsets,
    )
    passed = sum(
        row["bilateral_gates"][
            "bilateral_producer_reference_gate_passed"
        ]
        for row in candidates
    )
    fields = sorted(
        {
            int(
                row["left"]["returned_object_geometry"][
                    "target_field_displacement"
                ]
            )
            for row in candidates
        }
    )
    target_code_gate = bool(
        target_summaries["left"]["bounded_code_gate_passed"]
        and target_summaries["right"]["bounded_code_gate_passed"]
    )
    normalized_target_shape_equal = (
        target_summaries["left"]["normalized_shape_sha256"]
        == target_summaries["right"]["normalized_shape_sha256"]
    )
    return {
        "schema": "phoenix-mmi.call-return-producer-comparison/v1",
        "analysis_mode": (
            "read-only-static-session025-call-return-producer-correlation"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "candidate_producer_contracts": candidates,
        "producer_target_pair": {
            "left_target_file_offset": left_target,
            "right_target_file_offset": right_target,
            "file_offset_delta": target_delta,
            "one_target_per_release_for_all_candidates": (
                unique_resolved_pair
            ),
            "bounded_summaries": target_summaries,
            "bounded_code_gate_passed_both": target_code_gate,
            "normalized_target_shape_equal": normalized_target_shape_equal,
            "function_boundary_asserted": False,
            "runtime_equivalence_asserted": False,
        },
        "producer_call_family_census": call_family,
        "classification": {
            "session025_promoted_candidate_count": len(promoted),
            "bilateral_producer_reference_pass_count": passed,
            "single_resolved_producer_target_pair": "CONFIRMED",
            "target_specific_literal_jsr_reference_pairs": call_family[
                "paired_reference_count"
            ],
            "target_specific_contexts_all_bilateral": (
                "CONFIRMED"
                if call_family["all_offsets_co_relocated"]
                and call_family["all_normalized_contexts_equal"]
                else "PARTIAL"
            ),
            "session025_candidate_reference_pair_count": call_family[
                "session025_candidate_reference_pair_count"
            ],
            "returned_object_target_fields": fields,
            "returned_object_field_geometry": (
                "CONFIRMED_STABLE_STRUCTURAL_GRAMMAR"
            ),
            "producer_target_code_entry": (
                "CONFIRMED_BOUNDED_CODE"
                if target_code_gate
                else "NOT_VALIDATED"
            ),
            "producer_target_cross_version_shape": (
                "EQUAL"
                if normalized_target_shape_equal
                else "NOT_EQUAL"
            ),
            "producer_target_runtime_equivalence": "NOT_ESTABLISHED",
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
            "candidate_source_session": 25,
            "candidate_count": len(promoted),
            "owner_forward_bytes": _OWNER_FORWARD_BYTES,
            "target_call_census_is_syntactic": True,
            "arbitrary_raw_image_code_scan_performed": False,
            "whole_image_executable_map_available": False,
            "function_boundaries_asserted": False,
            "path_dominance_asserted": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "All four Session 025 dispatches cross the same immediately "
            "preceding producer-call family. In each release the four calls "
            "resolve to one in-image target, and the target-specific census "
            "contains seven co-relocated call pairs with equal normalized "
            "contexts. Producer arguments r4-r7 and returned-object field "
            "geometry agree bilaterally. The resolved target pair does not "
            "pass the bounded code gate and its normalized target windows "
            "differ, so function identity, runtime equivalence, object type, "
            "writer and selected-owner target registration remain open."
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


def update_operational_graph_v19(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v19"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "call-return-producer-family"
    ]
    graph["nodes"].append(
        {
            "id": "call-return-producer-family",
            "label": "Resolved CALL_RETURN producer-reference family",
            "status": "CONFIRMED_STATIC_REFERENCE_FAMILY",
            "candidate_reference_pair_count": comparison["classification"][
                "session025_candidate_reference_pair_count"
            ],
            "target_specific_reference_pair_count": comparison[
                "classification"
            ]["target_specific_literal_jsr_reference_pairs"],
            "producer_target_code_entry": comparison["classification"][
                "producer_target_code_entry"
            ],
            "evidence": ["S026-01", "S026-02", "RQ-078", "RQ-079"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "call-return-producer-family"
            and edge["target"] == "owner-entry-producer-first-candidates"
        )
    ]
    graph["edges"].append(
        {
            "source": "call-return-producer-family",
            "target": "owner-entry-producer-first-candidates",
            "relation": (
                "supplies the shared CALL_RETURN root to four bilateral "
                "field-dispatch candidates"
            ),
            "status": "CONFIRMED_STRUCTURAL",
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


def correlate_call_return_producer(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.call-return-producer-correlation/v1",
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
        "operational_graph": update_operational_graph_v19(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_call_return_producer_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

"""Owner-entry indirect-caller compatibility analysis for Session 024.

The analyzer revisits only the two call-return/field-load dispatch contracts
registered by Session 016.  It does not scan arbitrary data as code and does
not promote a matching call shape to a concrete target.  A candidate must
preserve every entry argument used by the selected owner pair in both
releases before it can remain compatible.
"""

from __future__ import annotations

import copy
import re

from .accessor_dispatch import _normalized_word
from .binary import BinaryReader
from .continuation_contract import _trace_call_argument
from .linkage_owner import _MemoryReader
from .object_dispatch import (
    _bounded_context,
    _canonical_expression,
    _resolve_static_expression,
    _trace_expression,
)
from .owner_provenance import _expression_roots


_CALL_REGISTER = re.compile(r"@r(\d+)$")
_DEFAULT_BEFORE_WORDS = 8
_DEFAULT_AFTER_WORDS = 7
_UNAVAILABLE_ARGUMENT_ROOTS = {
    "CALLER_SAVED_CLOBBER",
    "NO_DEFINITION",
    "DEPTH_LIMIT",
    "CYCLE",
}


def _normalized_call_signature(
    data: bytes,
    call_offset: int,
    *,
    before_words: int = _DEFAULT_BEFORE_WORDS,
    after_words: int = _DEFAULT_AFTER_WORDS,
) -> tuple[int, ...] | None:
    """Return a relocation-normalized context centered on one JSR."""

    start = call_offset - before_words * 2
    end = call_offset + (after_words + 1) * 2
    if start < 0 or end > len(data):
        return None
    return tuple(
        _normalized_word(int.from_bytes(data[offset : offset + 2], "big"))
        for offset in range(start, end, 2)
    )


def _indirect_call_signature_matches(
    data: bytes,
    signature: tuple[int, ...] | None,
    *,
    before_words: int = _DEFAULT_BEFORE_WORDS,
    after_words: int = _DEFAULT_AFTER_WORDS,
) -> list[int]:
    """Find exact normalized contexts anchored on modeled SH ``JSR @Rn``."""

    if signature is None:
        return []
    matches = []
    for offset in range(0, len(data) - 1, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF0FF != 0x400B:
            continue
        candidate = _normalized_call_signature(
            data,
            offset,
            before_words=before_words,
            after_words=after_words,
        )
        if candidate == signature:
            matches.append(offset)
    return matches


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


def _trace_indirect_call(
    reader: BinaryReader, call_offset: int
) -> dict[str, object]:
    """Trace target and arguments in one bounded prologue-backed context."""

    data = reader.read(0, reader.size)
    instructions, boundary = _bounded_context(
        _MemoryReader(data), call_offset
    )
    call_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.offset == call_offset
    )
    call = instructions[call_index]
    register_match = _CALL_REGISTER.fullmatch(call.operands)
    if call.mnemonic != "jsr" or register_match is None:
        raise ValueError(f"offset {call_offset} is not an indirect JSR")
    target_register = int(register_match.group(1))
    target_expression = _trace_expression(
        instructions,
        call_index,
        target_register,
        image_size=reader.size,
    )
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
        for register in range(4, 8)
    }
    return {
        "call_site_file_offset": call_offset,
        "context_start_file_offset": int(
            boundary["context_start_file_offset"]
        ),
        "context_start_reason": boundary["context_start_reason"],
        "predecessor_bytes_included": int(
            boundary["predecessor_bytes_included"]
        ),
        "target_register": f"r{target_register}",
        "target_expression": _public_expression(
            reader, target_expression
        ),
        "arguments": arguments,
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }


def _owner_required_arguments(
    owner_ingress: dict[str, object],
) -> list[dict[str, object]]:
    """Derive bilateral owner inputs from Session 022 memory-base roots."""

    left = owner_ingress["state_base_profiles"]["left"]
    right = owner_ingress["state_base_profiles"]["right"]
    if len(left) != len(right):
        raise ValueError("Session 022 owner-pair cardinality differs")
    rows = []
    for ordinal, (left_profile, right_profile) in enumerate(
        zip(left, right, strict=True), start=1
    ):
        left_counts = left_profile["root_class_counts"]
        right_counts = right_profile["root_class_counts"]
        required = sorted(
            key.split(":", 1)[1]
            for key in set(left_counts) | set(right_counts)
            if key.startswith("ENTRY:")
            and int(left_counts.get(key, 0)) > 0
            and int(right_counts.get(key, 0)) > 0
        )
        rows.append(
            {
                "owner_pair_ordinal": ordinal,
                "left_owner_start_file_offset": int(
                    left_profile["owner_start_file_offset"]
                ),
                "right_owner_start_file_offset": int(
                    right_profile["owner_start_file_offset"]
                ),
                "required_entry_arguments": required,
                "bilateral_entry_argument_contract": bool(required),
                "state_object_identity_asserted": False,
            }
        )
    return rows


def _argument_is_available(expression: dict[str, object]) -> bool:
    roots = set(expression["root_classes"])
    return bool(roots) and not bool(roots & _UNAVAILABLE_ARGUMENT_ROOTS)


def _evaluate_candidate(
    left: dict[str, object],
    right: dict[str, object],
    owner_contracts: list[dict[str, object]],
) -> dict[str, object]:
    target_equal = (
        left["target_expression"]["canonical"]
        == right["target_expression"]["canonical"]
    )
    owner_rows = []
    for owner in owner_contracts:
        argument_rows = []
        for register in owner["required_entry_arguments"]:
            left_argument = left["arguments"][register]
            right_argument = right["arguments"][register]
            path_equal = (
                left_argument["canonical"] == right_argument["canonical"]
            )
            left_available = _argument_is_available(left_argument)
            right_available = _argument_is_available(right_argument)
            argument_rows.append(
                {
                    "register": register,
                    "left_canonical": left_argument["canonical"],
                    "right_canonical": right_argument["canonical"],
                    "canonical_path_equal": path_equal,
                    "left_available_at_call": left_available,
                    "right_available_at_call": right_available,
                    "bilateral_argument_gate_passed": (
                        path_equal and left_available and right_available
                    ),
                }
            )
        all_arguments = bool(argument_rows) and all(
            row["bilateral_argument_gate_passed"]
            for row in argument_rows
        )
        owner_rows.append(
            {
                "owner_pair_ordinal": owner["owner_pair_ordinal"],
                "required_entry_arguments": owner[
                    "required_entry_arguments"
                ],
                "argument_compatibility": argument_rows,
                "all_required_arguments_available_and_equal": all_arguments,
                "candidate_owner_caller_compatible": (
                    target_equal and all_arguments
                ),
            }
        )
    return {
        "bilateral_target_expression_equal": target_equal,
        "owner_pair_compatibility": owner_rows,
        "compatible_owner_pair_count": sum(
            row["candidate_owner_caller_compatible"]
            for row in owner_rows
        ),
        "concrete_target_resolved_in_both_releases": (
            left["target_expression"]["resolution_status"]
            == "RESOLVED_IN_IMAGE_POINTER"
            and right["target_expression"]["resolution_status"]
            == "RESOLVED_IN_IMAGE_POINTER"
        ),
        "unique_target_family_established": False,
    }


def analyze_owner_caller_compatibility(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    dispatch: dict[str, object],
    owner_ingress: dict[str, object],
) -> dict[str, object]:
    """Test registered dynamic dispatches against owner entry contracts."""

    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    owner_contracts = _owner_required_arguments(owner_ingress)
    seed_pairs = [
        row
        for row in dispatch["dispatch_pairs"]
        if row["classification"]
        == "CONFIRMED_CROSS_VERSION_DYNAMIC_DESCRIPTOR_STRUCTURE"
    ]
    candidates = []
    for ordinal, pair in enumerate(seed_pairs, start=1):
        left_call = int(pair["left_call_site_offset"])
        right_call = int(pair["right_call_site_offset"])
        signatures = {
            "left": _normalized_call_signature(left_data, left_call),
            "right": _normalized_call_signature(right_data, right_call),
        }
        traced = {
            "left": _trace_indirect_call(left_reader, left_call),
            "right": _trace_indirect_call(right_reader, right_call),
        }
        matches = {
            "left": _indirect_call_signature_matches(
                left_data, signatures["left"]
            ),
            "right": _indirect_call_signature_matches(
                right_data, signatures["right"]
            ),
        }
        candidates.append(
            {
                "candidate_ordinal": ordinal,
                "source": "SESSION016_CALL_RETURN_FIELD_LOAD_DISPATCH",
                "left_seed_call_site_file_offset": left_call,
                "right_seed_call_site_file_offset": right_call,
                "normalized_signature_word_count": (
                    len(signatures["left"])
                    if signatures["left"] is not None
                    else 0
                ),
                "cross_version_normalized_signature_equal": (
                    signatures["left"] == signatures["right"]
                ),
                "exact_signature_census": {
                    "left_count": len(matches["left"]),
                    "right_count": len(matches["right"]),
                    "left_call_sites": matches["left"],
                    "right_call_sites": matches["right"],
                },
                "traced_seed_contract": traced,
                "compatibility": _evaluate_candidate(
                    traced["left"], traced["right"], owner_contracts
                ),
            }
        )

    compatible_count = sum(
        candidate["compatibility"]["compatible_owner_pair_count"]
        for candidate in candidates
    )
    r6_rows = [
        argument
        for candidate in candidates
        for owner in candidate["compatibility"][
            "owner_pair_compatibility"
        ]
        for argument in owner["argument_compatibility"]
        if argument["register"] == "r6"
    ]
    all_r6_unavailable = bool(r6_rows) and all(
        not row["left_available_at_call"]
        and not row["right_available_at_call"]
        for row in r6_rows
    )
    return {
        "schema": "phoenix-mmi.owner-caller-compatibility-comparison/v1",
        "analysis_mode": (
            "read-only-static-registered-indirect-caller-compatibility"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "owner_entry_contracts": owner_contracts,
        "registered_candidate_contracts": candidates,
        "classification": {
            "bilateral_owner_entry_argument_contract": (
                "CONFIRMED_R4_R6_FOR_BOTH_SELECTED_OWNER_PAIRS"
                if all(
                    row["required_entry_arguments"] == ["r4", "r6"]
                    for row in owner_contracts
                )
                else "PARTIAL_OR_DIFFERENT"
            ),
            "registered_memory_loaded_candidate_count": len(candidates),
            "compatible_candidate_owner_pair_count": compatible_count,
            "session016_call_return_field_load_family_as_owner_caller": (
                "BOUNDED_NEGATIVE_INCOMPATIBLE_ENTRY_ARGUMENT_CONTRACT"
                if candidates and compatible_count == 0
                else "NOT_EXCLUDED"
            ),
            "candidate_r6_provenance": (
                "CALLER_SAVED_CLOBBER_IN_ALL_TESTED_BILATERAL_CONTRACTS"
                if all_r6_unavailable
                else "MIXED_OR_AVAILABLE"
            ),
            "unique_bilateral_owner_entry_caller": "NOT_ESTABLISHED",
            "owner_entry_argument_producer": "OPEN",
            "state_creator_or_writer": "OPEN",
            "semantic_owner_identity": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
        },
        "limits": {
            "candidate_source_sessions": [16, 17, 22, 23],
            "normalized_context_before_words": _DEFAULT_BEFORE_WORDS,
            "normalized_context_after_words": _DEFAULT_AFTER_WORDS,
            "arbitrary_indirect_call_scan_performed": False,
            "whole_image_executable_map_available": False,
            "function_boundaries_asserted": False,
            "path_dominance_asserted": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "Both selected owner pairs consume runtime entry r4 and r6. "
            "The two registered Session 016 call-return/field-load dispatch "
            "contracts preserve an equal r4 receiver expression across "
            "releases, but r6 is caller-saved clobber after a preceding "
            "call in every tested contract. They therefore fail the owner "
            "entry argument gate and are excluded as callers of the "
            "selected owners under this bounded model. No concrete target, "
            "unique bilateral owner caller, producer or state creator is "
            "established."
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


def update_operational_graph_v17(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v17"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "owner-entry-indirect-caller-compatibility"
    ]
    graph["nodes"].append(
        {
            "id": "owner-entry-indirect-caller-compatibility",
            "label": "Owner-entry indirect-caller compatibility gate",
            "status": "CONFIRMED_BOUNDED_NEGATIVE",
            "owner_entry_contract": comparison["classification"][
                "bilateral_owner_entry_argument_contract"
            ],
            "tested_family": comparison["classification"][
                "session016_call_return_field_load_family_as_owner_caller"
            ],
            "owner_entry_producer": comparison["classification"][
                "owner_entry_argument_producer"
            ],
            "evidence": ["S024-01", "S024-02", "RQ-070", "RQ-071"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"]
            == "owner-entry-indirect-caller-compatibility"
            and edge["target"] == "runtime-linkage-owner-ingress"
        )
    ]
    graph["edges"].append(
        {
            "source": "owner-entry-indirect-caller-compatibility",
            "target": "runtime-linkage-owner-ingress",
            "relation": (
                "registered call-return/field-load family cannot supply "
                "bilateral owner entry r6"
            ),
            "status": "BOUNDED_NEGATIVE_INCOMPATIBLE_ENTRY_ARGUMENTS",
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


def correlate_owner_caller_compatibility(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.owner-caller-compatibility-correlation/v1",
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
        "operational_graph": update_operational_graph_v17(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_owner_caller_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

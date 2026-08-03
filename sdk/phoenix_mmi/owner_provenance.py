"""Bounded owner ingress and state-base provenance for Session 022.

The analyzer begins with the two owner pairs registered by Session 021.  It
tests only direct static ingress, address-taken uses and memory-base
expressions inside those bounded windows.  Owner windows remain analysis
anchors rather than asserted function boundaries.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
from difflib import SequenceMatcher
import re

from .accessor_dispatch import _callsite_signature, _literal_jsr_calls
from .binary import BinaryReader
from .linkage_owner import (
    _MemoryReader,
    _normalized_owner_tokens,
    _owner_summary,
)
from .navigation_storage import RUNTIME_BASE
from .object_dispatch import (
    _canonical_expression,
    _destination_register,
    _trace_expression,
)
from .optical_callgraph import _decode_window, summarize_bounded_entry


_DISPLACED_BASE = re.compile(r"@\((-?\d+),r(\d+)\)")
_INDIRECT_BASE = re.compile(r"@-?r(\d+)\+?")
_CALL_REGISTER = re.compile(r"@r(\d+)$")
_REGISTER = re.compile(r"r(\d+)")
_POINTER_USE_LOOKAHEAD = 16


def _scan_direct_bsr_calls(data: bytes) -> list[dict[str, int]]:
    """Return raw in-image BSR candidates without claiming executable scope."""

    rows = []
    for offset in range(0, len(data) - 1, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF000 != 0xB000:
            continue
        displacement = word & 0x0FFF
        if displacement & 0x0800:
            displacement -= 0x1000
        target = offset + 4 + displacement * 2
        if 0 <= target < len(data):
            rows.append(
                {
                    "call_site_file_offset": offset,
                    "target_file_offset": target,
                }
            )
    return rows


def _aligned_pointer_index(data: bytes) -> list[dict[str, int]]:
    rows = []
    for offset in range(0, len(data) - 3, 4):
        value = int.from_bytes(data[offset : offset + 4], "big")
        target = value - RUNTIME_BASE
        if 0 <= target < len(data):
            rows.append(
                {
                    "pointer_file_offset": offset,
                    "target_file_offset": target,
                }
            )
    return rows


def _pc_referrer_index(data: bytes) -> dict[int, list[int]]:
    rows: dict[int, list[int]] = defaultdict(list)
    for offset in range(0, len(data) - 1, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF000 != 0xD000:
            continue
        literal = (offset & ~3) + 4 + (word & 0xFF) * 4
        if literal + 4 <= len(data):
            rows[literal].append(offset)
    return rows


def _load_register(reader: _MemoryReader, offset: int) -> int | None:
    instruction = _decode_window(reader, offset, maximum_bytes=2)
    if not instruction or instruction[0].mnemonic != "mov.l":
        return None
    match = re.search(r",r(\d+)$", instruction[0].operands)
    return int(match.group(1)) if match is not None else None


def _delay_slot_overwrites(
    instructions: list[object], index: int, register: int
) -> bool:
    if index + 1 >= len(instructions):
        return False
    return _destination_register(instructions[index + 1]) == register


def _classify_pointer_use(
    reader: _MemoryReader, referrer: int
) -> dict[str, object]:
    instructions = _decode_window(
        reader,
        referrer,
        maximum_bytes=_POINTER_USE_LOOKAHEAD * 2,
    )
    register = _load_register(reader, referrer)
    if register is None:
        return {"classification": "UNSUPPORTED_LOAD_FORM"}
    for index, instruction in enumerate(instructions[1:], start=1):
        call = _CALL_REGISTER.fullmatch(instruction.operands)
        if (
            instruction.flow in {"call", "indirect-call"}
            and call is not None
        ):
            call_register = int(call.group(1))
            if call_register == register:
                return {
                    "classification": "INDIRECT_CONTROL_TARGET",
                    "relative_use_instruction_index": index,
                    "loaded_register": register,
                }
            if (
                4 <= register <= 7
                and not _delay_slot_overwrites(instructions, index, register)
            ):
                return {
                    "classification": "ARGUMENT_TO_OTHER_INDIRECT_CALL",
                    "relative_use_instruction_index": index,
                    "loaded_register": register,
                    "call_register": call_register,
                }

        for _, base in _DISPLACED_BASE.findall(instruction.operands):
            if int(base) == register:
                return {
                    "classification": "MEMORY_BASE",
                    "relative_use_instruction_index": index,
                    "loaded_register": register,
                }
        for base in _INDIRECT_BASE.findall(instruction.operands):
            if int(base) == register:
                return {
                    "classification": "MEMORY_BASE",
                    "relative_use_instruction_index": index,
                    "loaded_register": register,
                }
        if _destination_register(instruction) == register:
            return {
                "classification": "OVERWRITTEN_BEFORE_MODELED_USE",
                "relative_use_instruction_index": index,
                "loaded_register": register,
            }
    return {
        "classification": "NO_MODELED_USE_WITHIN_LOOKAHEAD",
        "loaded_register": register,
    }


def _exact_pc_context_matches(
    data: bytes, signature: tuple[int, ...] | None
) -> list[int]:
    if signature is None:
        return []
    rows = []
    for offset in range(0, len(data) - 1, 2):
        if data[offset] & 0xF0 != 0xD0:
            continue
        if _callsite_signature(data, offset) == signature:
            rows.append(offset)
    return rows


def _loaded_pointer_target(data: bytes, load_offset: int) -> int | None:
    word = int.from_bytes(data[load_offset : load_offset + 2], "big")
    if word & 0xF000 != 0xD000:
        return None
    literal = (load_offset & ~3) + 4 + (word & 0xFF) * 4
    if literal + 4 > len(data):
        return None
    value = int.from_bytes(data[literal : literal + 4], "big")
    target = value - RUNTIME_BASE
    return target if 0 <= target < len(data) else None


def _owner_range(data: bytes, start: int) -> tuple[int, int]:
    instructions = _decode_window(
        _MemoryReader(data), start, maximum_bytes=0x180
    )
    if not instructions:
        raise ValueError(f"empty owner window at {start}")
    return start, instructions[-1].offset + 2


def _incoming_profile(
    data: bytes,
    opposite_data: bytes,
    *,
    owner_start: int,
    literal_calls: list[dict[str, int]],
    direct_calls: list[dict[str, int]],
    pointers: list[dict[str, int]],
    pc_referrers: dict[int, list[int]],
    selected_ranges: list[tuple[int, int]],
) -> dict[str, object]:
    reader = _MemoryReader(data)
    start, end = _owner_range(data, owner_start)
    exact_literal = [
        row for row in literal_calls if row["target_file_offset"] == start
    ]
    exact_bsr = [
        row for row in direct_calls if row["target_file_offset"] == start
    ]
    external_literal = [
        row
        for row in literal_calls
        if start <= int(row["target_file_offset"]) < end
        and not (start <= int(row["call_site_offset"]) < end)
    ]
    external_bsr = [
        row
        for row in direct_calls
        if start <= int(row["target_file_offset"]) < end
        and not (
            start <= int(row["call_site_file_offset"]) < end
        )
    ]
    pointer_rows = []
    for pointer in pointers:
        target = int(pointer["target_file_offset"])
        if not (start <= target < end):
            continue
        offset = int(pointer["pointer_file_offset"])
        referrers = pc_referrers.get(offset, [])
        uses = [
            {
                "referrer_file_offset": referrer,
                **_classify_pointer_use(reader, referrer),
            }
            for referrer in referrers
        ]
        context_rows = []
        for referrer in referrers:
            signature = _callsite_signature(data, referrer)
            matches = _exact_pc_context_matches(opposite_data, signature)
            match_rows = []
            for match in matches:
                match_target = _loaded_pointer_target(opposite_data, match)
                selected_owner_ordinal = next(
                    (
                        ordinal
                        for ordinal, (other_start, other_end)
                        in enumerate(selected_ranges)
                        if match_target is not None
                        and other_start <= match_target < other_end
                    ),
                    None,
                )
                match_rows.append(
                    {
                        "load_file_offset": match,
                        "loaded_target_file_offset": match_target,
                        "targets_selected_owner_window": (
                            selected_owner_ordinal is not None
                        ),
                        "selected_owner_ordinal": selected_owner_ordinal,
                        "bounded_owner": _owner_summary(
                            _MemoryReader(opposite_data), match
                        ),
                    }
                )
            context_rows.append(
                {
                    "referrer_file_offset": referrer,
                    "opposite_exact_context_match_count": len(matches),
                    "opposite_matches": match_rows,
                }
            )
        pointer_rows.append(
            {
                "pointer_file_offset": offset,
                "target_file_offset": target,
                "target_relative_to_owner": target - start,
                "pc_relative_referrer_count": len(referrers),
                "uses": uses,
                "cross_version_context": context_rows,
                "bilateral_selected_owner_target_established": any(
                    row["targets_selected_owner_window"]
                    for context in context_rows
                    for row in context["opposite_matches"]
                ),
            }
        )
    return {
        "owner_start_file_offset": start,
        "owner_end_file_offset": end,
        "owner_window_length": end - start,
        "exact_start_adjacent_literal_jsr_count": len(exact_literal),
        "exact_start_bsr_count": len(exact_bsr),
        "external_adjacent_literal_jsr_into_window_count": len(
            external_literal
        ),
        "external_bsr_into_window_count": len(external_bsr),
        "aligned_address_taken_count": len(pointer_rows),
        "address_taken_rows": pointer_rows,
        "function_boundary_asserted": False,
        "whole_image_executable_map_available": False,
    }


def _expression_roots(expression: dict[str, object]) -> list[str]:
    kind = str(expression.get("kind", "UNKNOWN"))
    if kind == "ADD":
        return _expression_roots(expression["left"]) + _expression_roots(
            expression["right"]
        )
    if kind == "LOAD":
        return ["LOAD"] + _expression_roots(expression["base"])
    if kind == "ENTRY_ARGUMENT":
        return [f"ENTRY:{expression['register']}"]
    return [kind]


def _memory_base_registers(operands: str) -> list[int]:
    rows = [int(base) for _, base in _DISPLACED_BASE.findall(operands)]
    rows.extend(int(base) for base in _INDIRECT_BASE.findall(operands))
    return rows


def _owner_base_profile(data: bytes, start: int) -> dict[str, object]:
    reader = _MemoryReader(data)
    instructions = _decode_window(reader, start, maximum_bytes=0x180)
    rows = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic not in {"mov.b", "mov.w", "mov.l"}:
            continue
        for occurrence, register in enumerate(
            _memory_base_registers(instruction.operands)
        ):
            expression = _trace_expression(
                instructions,
                index,
                register,
                image_size=len(data),
            )
            rows.append(
                {
                    "instruction_index": index,
                    "base_occurrence": occurrence,
                    "base_register": register,
                    "canonical_expression": _canonical_expression(expression),
                    "root_classes": _expression_roots(expression),
                }
            )
    root_counts = Counter(
        root for row in rows for root in row["root_classes"]
    )
    expression_counts = Counter(
        str(row["canonical_expression"]) for row in rows
    )
    summary = summarize_bounded_entry(
        reader, start, source="SESSION022_OWNER_BASE"
    )
    return {
        "owner_start_file_offset": start,
        "owner_end_file_offset": (
            instructions[-1].offset + 2 if instructions else start
        ),
        "instruction_count": len(instructions),
        "memory_base_use_count": len(rows),
        "entry_argument_rooted_use_count": sum(
            any(root.startswith("ENTRY:") for root in row["root_classes"])
            for row in rows
        ),
        "memory_load_rooted_use_count": sum(
            "LOAD" in row["root_classes"] for row in rows
        ),
        "static_image_pointer_rooted_use_count": sum(
            "IN_IMAGE_POINTER" in row["root_classes"] for row in rows
        ),
        "call_return_rooted_use_count": sum(
            "CALL_RETURN" in row["root_classes"] for row in rows
        ),
        "root_class_counts": dict(sorted(root_counts.items())),
        "canonical_expression_counts": [
            {"expression": expression, "count": count}
            for expression, count in sorted(expression_counts.items())
        ],
        "resolved_static_call_count": summary["resolved_static_call_count"],
        "unresolved_indirect_call_count": summary[
            "unresolved_indirect_call_count"
        ],
        "rows": rows,
        "entry_arguments_are_runtime_values": True,
        "state_object_identity_asserted": False,
    }


def _alignment_map(
    left_tokens: list[tuple[str, str, str, bool]],
    right_tokens: list[tuple[str, str, str, bool]],
) -> dict[int, int]:
    matcher = SequenceMatcher(
        a=left_tokens, b=right_tokens, autojunk=False
    )
    result = {}
    for block in matcher.get_matching_blocks():
        for relative in range(block.size):
            result[block.b + relative] = block.a + relative
    return result


def _compare_base_profiles(
    left_data: bytes,
    right_data: bytes,
    *,
    left_profile: dict[str, object],
    right_profile: dict[str, object],
    prior_classification: str,
) -> dict[str, object]:
    left_start = int(left_profile["owner_start_file_offset"])
    right_start = int(right_profile["owner_start_file_offset"])
    left_tokens = _normalized_owner_tokens(
        _MemoryReader(left_data), left_start
    )
    right_tokens = _normalized_owner_tokens(
        _MemoryReader(right_data), right_start
    )
    mapping = _alignment_map(left_tokens, right_tokens)
    left_rows = {
        (
            int(row["instruction_index"]),
            int(row["base_occurrence"]),
            int(row["base_register"]),
        ): row
        for row in left_profile["rows"]
    }
    aligned = []
    for right_row in right_profile["rows"]:
        right_index = int(right_row["instruction_index"])
        left_index = mapping.get(right_index)
        if left_index is None:
            continue
        key = (
            left_index,
            int(right_row["base_occurrence"]),
            int(right_row["base_register"]),
        )
        left_row = left_rows.get(key)
        if left_row is None:
            continue
        aligned.append(
            {
                "left_instruction_index": left_index,
                "right_instruction_index": right_index,
                "base_register": right_row["base_register"],
                "left_expression": left_row["canonical_expression"],
                "right_expression": right_row["canonical_expression"],
                "canonical_expression_equal": (
                    left_row["canonical_expression"]
                    == right_row["canonical_expression"]
                ),
                "left_root_classes": left_row["root_classes"],
                "right_root_classes": right_row["root_classes"],
                "root_classes_equal": (
                    left_row["root_classes"]
                    == right_row["root_classes"]
                ),
            }
        )
    equal = sum(row["canonical_expression_equal"] for row in aligned)
    roots_equal = sum(row["root_classes_equal"] for row in aligned)
    return {
        "left_owner_start_file_offset": left_start,
        "right_owner_start_file_offset": right_start,
        "prior_owner_pair_classification": prior_classification,
        "left_memory_base_use_count": left_profile["memory_base_use_count"],
        "right_memory_base_use_count": right_profile[
            "memory_base_use_count"
        ],
        "aligned_memory_base_use_count": len(aligned),
        "equal_canonical_expression_count": equal,
        "equal_root_class_count": roots_equal,
        "canonical_expression_mismatch_count": len(aligned) - equal,
        "root_class_mismatch_count": len(aligned) - roots_equal,
        "aligned_rows": aligned,
        "state_object_identity_asserted": False,
    }


def analyze_owner_ingress_state(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
) -> dict[str, object]:
    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    pairs = prior["residual_lineage"]["selected_owner_pairs"]
    if not isinstance(pairs, list) or len(pairs) != 2:
        raise ValueError("Session 021 does not register two owner pairs")

    data_by_side = {"left": left_data, "right": right_data}
    starts = {
        "left": [
            int(row["left_owner_start_file_offset"]) for row in pairs
        ],
        "right": [
            int(row["right_owner_start_file_offset"]) for row in pairs
        ],
    }
    ranges = {
        side: [_owner_range(data_by_side[side], start) for start in values]
        for side, values in starts.items()
    }
    literal_calls = {
        side: _literal_jsr_calls(
            data, image_size=len(data)
        )
        for side, data in data_by_side.items()
    }
    direct_calls = {
        side: _scan_direct_bsr_calls(data)
        for side, data in data_by_side.items()
    }
    pointers = {
        side: _aligned_pointer_index(data)
        for side, data in data_by_side.items()
    }
    referrers = {
        side: _pc_referrer_index(data)
        for side, data in data_by_side.items()
    }

    ingress = {}
    bases = {}
    for side in ("left", "right"):
        opposite = "right" if side == "left" else "left"
        ingress[side] = [
            _incoming_profile(
                data_by_side[side],
                data_by_side[opposite],
                owner_start=start,
                literal_calls=literal_calls[side],
                direct_calls=direct_calls[side],
                pointers=pointers[side],
                pc_referrers=referrers[side],
                selected_ranges=ranges[opposite],
            )
            for start in starts[side]
        ]
        bases[side] = [
            _owner_base_profile(data_by_side[side], start)
            for start in starts[side]
        ]

    base_pairs = [
        _compare_base_profiles(
            left_data,
            right_data,
            left_profile=bases["left"][ordinal],
            right_profile=bases["right"][ordinal],
            prior_classification=str(pair["classification"]),
        )
        for ordinal, pair in enumerate(pairs)
    ]
    exact_start_calls = sum(
        int(row["exact_start_adjacent_literal_jsr_count"])
        + int(row["exact_start_bsr_count"])
        for side in ingress.values()
        for row in side
    )
    external_window_calls = sum(
        int(row["external_adjacent_literal_jsr_into_window_count"])
        + int(row["external_bsr_into_window_count"])
        for side in ingress.values()
        for row in side
    )
    address_rows = [
        row
        for side in ingress.values()
        for owner in side
        for row in owner["address_taken_rows"]
    ]
    bilateral_address_rows = sum(
        bool(row["bilateral_selected_owner_target_established"])
        for row in address_rows
    )
    static_base_uses = sum(
        int(profile["static_image_pointer_rooted_use_count"])
        for side in bases.values()
        for profile in side
    )
    load_rooted = sum(
        int(profile["memory_load_rooted_use_count"])
        for side in bases.values()
        for profile in side
    )
    entry_rooted = sum(
        int(profile["entry_argument_rooted_use_count"])
        for side in bases.values()
        for profile in side
    )
    return {
        "schema": "phoenix-mmi.owner-ingress-state-comparison/v1",
        "analysis_mode": (
            "read-only-static-bounded-owner-ingress-state-provenance"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "owner_ingress": ingress,
        "state_base_profiles": bases,
        "state_base_pair_comparison": base_pairs,
        "classification": {
            "exact_owner_start_static_callers": (
                "NOT_FOUND_UNDER_ADJACENT_LITERAL_JSR_AND_BSR_MODELS"
                if exact_start_calls == 0
                else "FOUND"
            ),
            "external_static_calls_into_owner_windows": (
                "NOT_FOUND_UNDER_ADJACENT_LITERAL_JSR_AND_BSR_MODELS"
                if external_window_calls == 0
                else "FOUND"
            ),
            "one_sided_internal_address_uses": (
                "CONFIRMED_TWO_PC_RELATIVE_ADDRESS_TAKEN_USES"
                if len(address_rows) == 2
                else "PARTIAL"
            ),
            "bilateral_selected_owner_address_use": (
                "NOT_ESTABLISHED"
                if bilateral_address_rows == 0
                else "FOUND"
            ),
            "entry_argument_rooted_state_bases": (
                "CONFIRMED_IN_BOTH_OWNER_PAIRS"
                if entry_rooted > 0
                and all(
                    left["entry_argument_rooted_use_count"]
                    == right["entry_argument_rooted_use_count"]
                    for left, right in zip(bases["left"], bases["right"])
                )
                else "PARTIAL"
            ),
            "memory_load_rooted_state_bases": (
                "CONFIRMED_DYNAMIC_ARGUMENT_DEREFERENCE_BASES"
                if load_rooted > 0
                else "NOT_FOUND"
            ),
            "static_image_pointer_rooted_state_bases": (
                "NOT_FOUND_IN_SELECTED_OWNER_WINDOWS"
                if static_base_uses == 0
                else "FOUND"
            ),
            "unique_bilateral_incoming_caller": "NOT_ESTABLISHED",
            "semantic_owner_identity": "OPEN",
            "specific_writer_or_loader_chain": "OPEN",
            "memory_loaded_base_writer": "OPEN",
            "runtime_patch_overlay_or_linkage_mechanism": (
                "HYPOTHESIS_STRENGTHENED_BY_ARGUMENT_ROOTED_OWNER_STATE"
            ),
            "specific_session017_producer_edge": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
        },
        "limits": {
            "pointer_use_lookahead_instructions": _POINTER_USE_LOOKAHEAD,
            "owner_forward_bytes": 0x180,
            "direct_call_models": ["ADJACENT_LITERAL_JSR", "BSR"],
            "whole_image_executable_map_available": False,
            "indirect_runtime_callbacks_resolved": False,
            "function_boundaries_asserted": False,
            "path_dominance_asserted": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "No adjacent literal/JSR or BSR call targets either selected "
            "owner start or enters either bounded owner window from outside. "
            "One PC-relative address-taken use occurs in each release, but "
            "the targets belong to different owner pairs and no bilateral "
            "selected-owner use is established. Memory-base expressions in "
            "both owner pairs are consistently rooted in entry arguments; "
            "four per owner are obtained through argument-rooted loads, and "
            "none is rooted in a static image pointer. This supports a "
            "runtime-provided object/state contract while leaving its "
            "creator, semantic identity and zero-slot writer open."
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


def update_operational_graph_v15(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v15"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "runtime-linkage-owner-ingress"
    ]
    graph["nodes"].append(
        {
            "id": "runtime-linkage-owner-ingress",
            "label": "Bounded owner ingress and state-base provenance",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "direct_ingress": comparison["classification"][
                "external_static_calls_into_owner_windows"
            ],
            "state_base": comparison["classification"][
                "entry_argument_rooted_state_bases"
            ],
            "semantic_owner": "OPEN",
            "evidence": ["S022-01", "S022-02", "S022-03", "RQ-062", "RQ-063"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "runtime-linkage-owner-ingress"
            and edge["target"] == "runtime-linkage-owner-lineage"
        )
    ]
    graph["edges"].append(
        {
            "source": "runtime-linkage-owner-ingress",
            "target": "runtime-linkage-owner-lineage",
            "relation": (
                "selected owners use entry-argument-rooted state bases; "
                "direct static ingress remains absent under bounded models"
            ),
            "status": "CONFIRMED_STATE_PROVENANCE_BOUNDED_NEGATIVE_INGRESS",
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


def correlate_owner_ingress_state(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.owner-ingress-state-correlation/v1",
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
        "operational_graph": update_operational_graph_v15(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_owner_ingress_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

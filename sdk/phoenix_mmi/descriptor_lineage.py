"""Descriptor producer lineage and initializer search for Session 017.

All results are static and bounded.  A producer call, accessor shape, record
candidate, or field-store opcode is never assigned object, vtable, optical, or
parser semantics without independent cross-version lineage evidence.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import re

from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .object_dispatch import (
    _bounded_context,
    _canonical_expression,
    _resolve_static_expression,
    _trace_expression,
)
from .optical_callgraph import _decode_window, summarize_bounded_entry
from .superh import SHInstruction, decode_instruction_extended


_CALL_REGISTER = re.compile(r"@r(\d+)$")


def _safe_code_evidence(reader: BinaryReader, target: int) -> dict[str, object]:
    summary = summarize_bounded_entry(
        reader, target, source="SESSION017_PRODUCER_TARGET"
    )
    return {
        "known_ratio": summary["known_ratio"],
        "normalized_shape_sha256": summary["normalized_shape_sha256"],
        "prologue_save_pr_in_first_12_instructions": summary[
            "prologue_save_pr_in_first_12_instructions"
        ],
        "return_count": summary["return_count"],
        "resolved_static_call_count": summary["resolved_static_call_count"],
        "unresolved_indirect_call_count": summary[
            "unresolved_indirect_call_count"
        ],
        "bounded_code_gate_passed": summary["bounded_code_gate_passed"],
        "function_boundary_asserted": False,
    }


def _return_path(reader: BinaryReader, target: int) -> str:
    instructions = _decode_window(reader, target)
    for index, instruction in enumerate(instructions):
        if instruction.flow != "return":
            continue
        prefix = list(instructions[:index])
        if instruction.delayed and index + 1 < len(instructions):
            prefix.append(instructions[index + 1])
        expression = _trace_expression(
            prefix, len(prefix), 0, image_size=reader.size
        )
        return _canonical_expression(expression)
    return "NO_BOUNDED_RETURN"


def _resolve_call_target(
    reader: BinaryReader, instructions: list[SHInstruction], index: int
) -> tuple[str, dict[str, object]]:
    instruction = instructions[index]
    if instruction.mnemonic == "bsr" and instruction.target is not None:
        target = int(instruction.target)
        return (
            "DIRECT_BSR",
            {
                "status": (
                    "RESOLVED_IN_IMAGE_POINTER"
                    if 0 <= target < reader.size
                    else "OUT_OF_IMAGE"
                ),
                **(
                    {"target_file_offset": target}
                    if 0 <= target < reader.size
                    else {}
                ),
            },
        )
    match = _CALL_REGISTER.fullmatch(instruction.operands)
    if instruction.mnemonic != "jsr" or match is None:
        return "UNSUPPORTED", {"status": "UNSUPPORTED"}
    expression = _trace_expression(
        instructions,
        index,
        int(match.group(1)),
        image_size=reader.size,
    )
    return _canonical_expression(expression), _resolve_static_expression(
        reader, expression
    )


def trace_dispatch_producer(
    reader: BinaryReader, dispatch: dict[str, object]
) -> dict[str, object]:
    """Trace the nearest call whose r0 feeds one registered dispatch site."""

    site = int(dispatch["call_site_offset"])
    entry = site - int(dispatch["relative_call_offset"])
    instructions, context = _bounded_context(reader, entry)
    index_by_offset = {item.offset: index for index, item in enumerate(instructions)}
    dispatch_index = index_by_offset[site]
    producer_index = next(
        index
        for index in range(dispatch_index - 1, -1, -1)
        if instructions[index].flow in {"call", "indirect-call"}
    )
    producer = instructions[producer_index]
    target_path, target_resolution = _resolve_call_target(
        reader, instructions, producer_index
    )

    prefix = list(instructions[:producer_index])
    if producer.delayed and producer_index + 1 < len(instructions):
        prefix.append(instructions[producer_index + 1])
    arguments = {}
    for register in range(4, 8):
        expression = _trace_expression(
            prefix, len(prefix), register, image_size=reader.size
        )
        resolution = _resolve_static_expression(reader, expression)
        arguments[f"r{register}"] = {
            "path": _canonical_expression(expression),
            "static_status": resolution["status"],
            **(
                {"constant": int(resolution["value"])}
                if resolution.get("status") == "CONSTANT"
                else {}
            ),
        }

    target = target_resolution.get("target_file_offset")
    target_evidence = None
    return_path = "UNRESOLVED_TARGET"
    child_target = None
    child_evidence = None
    child_return_path = None
    if target_resolution.get("status") == "RESOLVED_IN_IMAGE_POINTER" and isinstance(target, int):
        target_evidence = _safe_code_evidence(reader, target)
        return_path = _return_path(reader, target)
        target_summary = summarize_bounded_entry(
            reader, target, source="SESSION017_PRODUCER_TARGET"
        )
        resolved_children = [
            call["resolution"].get("target_file_offset")
            for call in target_summary["calls"]
            if str(call["resolution"].get("status", "")).startswith("RESOLVED")
            and isinstance(call["resolution"].get("target_file_offset"), int)
        ]
        if len(resolved_children) == 1:
            child_target = int(resolved_children[0])
            child_evidence = _safe_code_evidence(reader, child_target)
            child_return_path = _return_path(reader, child_target)

    return {
        "dispatch_call_site_offset": site,
        "producer_call_site_offset": producer.offset,
        "producer_relative_to_dispatch": producer.offset - site,
        "producer_target_path": target_path,
        "producer_target_static_status": target_resolution["status"],
        **(
            {"producer_target_file_offset": int(target)}
            if isinstance(target, int)
            else {}
        ),
        **(
            {"producer_target_code_evidence": target_evidence}
            if target_evidence is not None
            else {}
        ),
        "producer_return_path": return_path,
        **(
            {
                "producer_child_target_file_offset": child_target,
                "producer_child_code_evidence": child_evidence,
                "producer_child_return_path": child_return_path,
            }
            if child_target is not None
            else {}
        ),
        "arguments": arguments,
        "context_start_reason": context["context_start_reason"],
        "predecessor_bytes_included": context["predecessor_bytes_included"],
        "delay_slot_accounted_for": producer.delayed,
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }


def _find_field12_accessors(
    reader: BinaryReader, data: bytes
) -> list[dict[str, object]]:
    offsets = []
    for candidate in reader.find_all(b"\x20\x08"):
        if candidate & 1 or candidate + 16 > reader.size:
            continue
        instructions = [
            decode_instruction_extended(reader, candidate + relative)
            for relative in range(0, 16, 2)
        ]
        if not (
            instructions[0].mnemonic == "tst"
            and instructions[0].operands == "r0,r0"
            and instructions[1].mnemonic == "bt/s"
            and instructions[2].mnemonic == "mov"
            and instructions[2].operands == "#0,r0"
            and instructions[3].mnemonic == "mov.l"
            and instructions[3].operands == "@(12,r4),r0"
            and instructions[4].mnemonic == "add"
            and instructions[4].operands == "#4,r14"
            and instructions[5].mnemonic == "mov"
            and instructions[5].operands == "r14,r15"
            and instructions[6].flow == "return"
            and instructions[7].mnemonic == "mov.l"
            and instructions[7].operands == "@r15+,r14"
        ):
            continue
        runtime_word = (RUNTIME_BASE + candidate).to_bytes(4, "big")
        offsets.append(
            {
                "file_offset": candidate,
                "direct_runtime_word_reference_count": data.count(runtime_word),
            }
        )

    clusters = []
    for row in offsets:
        if not clusters or row["file_offset"] - clusters[-1][-1]["file_offset"] > 0x1000:
            clusters.append([row])
        else:
            clusters[-1].append(row)
    return [
        {
            "members": cluster,
            "occurrence_count": len(cluster),
            "relative_gap_vector": [
                cluster[index]["file_offset"] - cluster[index - 1]["file_offset"]
                for index in range(1, len(cluster))
            ],
        }
        for cluster in clusters
    ]


def _word_role(value: int, *, image_size: int) -> str:
    if RUNTIME_BASE <= value < RUNTIME_BASE + image_size:
        return "IN_IMAGE_POINTER"
    if value == 0:
        return "ZERO"
    if value <= 0xFFFF:
        return "SMALL_UNSIGNED"
    return "OTHER"


def _static_descriptor_census(
    reader: BinaryReader, data: bytes, optical_targets: set[int]
) -> tuple[dict[str, object], list[dict[str, object]]]:
    aligned_words = {
        int.from_bytes(data[offset : offset + 4], "big")
        for offset in range(0, reader.size - 3, 4)
    }
    rows = []
    optical_count = 0
    referenced_count = 0
    for base in range(0, reader.size - 16, 4):
        adjustment = int.from_bytes(data[base + 8 : base + 10], "big", signed=True)
        pointer = int.from_bytes(data[base + 12 : base + 16], "big")
        if not (-0x400 <= adjustment <= 0x400):
            continue
        if not (RUNTIME_BASE <= pointer < RUNTIME_BASE + reader.size):
            continue
        target = pointer - RUNTIME_BASE
        referenced = RUNTIME_BASE + base in aligned_words
        optical_count += target in optical_targets
        referenced_count += referenced
        rows.append(
            {
                "base": base,
                "adjustment": adjustment,
                "target": target,
                "field0_role": _word_role(
                    int.from_bytes(data[base : base + 4], "big"),
                    image_size=reader.size,
                ),
                "field4_role": _word_role(
                    int.from_bytes(data[base + 4 : base + 8], "big"),
                    image_size=reader.size,
                ),
                "base_referenced": referenced,
            }
        )
    return (
        {
            "raw_candidate_count": len(rows),
            "candidate_targeting_accepted_optical_node_count": optical_count,
            "candidate_base_referenced_as_aligned_runtime_word_count": referenced_count,
            "descriptor_identity_asserted": False,
        },
        rows,
    )


def _initializer_census(
    reader: BinaryReader, data: bytes
) -> tuple[dict[str, object], Counter[tuple[object, ...]]]:
    word_stores = []
    long_stores = []
    for offset in range(0, reader.size - 1, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF00F == 0x8001 and ((word >> 4) & 0xF) * 2 == 8:
            word_stores.append((offset, (word >> 8) & 0xF))
        if word & 0xF000 == 0x1000 and (word & 0xF) * 4 == 12:
            long_stores.append(
                (offset, (word >> 8) & 0xF, (word >> 4) & 0xF)
            )

    pairs = []
    cursor = 0
    for word_offset, base_register in word_stores:
        while cursor < len(long_stores) and long_stores[cursor][0] < word_offset - 0x100:
            cursor += 1
        probe = cursor
        while probe < len(long_stores) and long_stores[probe][0] <= word_offset + 0x100:
            long_offset, long_base, source_register = long_stores[probe]
            if long_base == base_register:
                pairs.append(
                    (word_offset, long_offset, base_register, source_register)
                )
            probe += 1

    signatures: Counter[tuple[object, ...]] = Counter()
    analyzed = 0
    code_gated = 0
    for word_offset, long_offset, base_register, source_register in pairs:
        anchor = min(word_offset, long_offset)
        instructions, context = _bounded_context(reader, anchor)
        index_by_offset = {item.offset: index for index, item in enumerate(instructions)}
        word_index = index_by_offset.get(word_offset)
        long_index = index_by_offset.get(long_offset)
        if word_index is None or long_index is None:
            continue
        analyzed += 1
        adjustment = _trace_expression(
            instructions, word_index, 0, image_size=reader.size
        )
        target = _trace_expression(
            instructions,
            long_index,
            source_register,
            image_size=reader.size,
        )
        word_base = _trace_expression(
            instructions, word_index, base_register, image_size=reader.size
        )
        long_base = _trace_expression(
            instructions, long_index, base_register, image_size=reader.size
        )
        gate = summarize_bounded_entry(
            reader,
            int(context["context_start_file_offset"]),
            source="SESSION017_FIELD_INITIALIZER_CANDIDATE",
        )["bounded_code_gate_passed"]
        code_gated += bool(gate)
        signatures[
            (
                long_offset - word_offset,
                _canonical_expression(adjustment),
                _canonical_expression(target),
                _canonical_expression(word_base),
                _canonical_expression(long_base),
                bool(gate),
                context["context_start_reason"],
            )
        ] += 1
    return (
        {
            "word_store_at_adjustment_offset_count": len(word_stores),
            "long_store_at_target_offset_count": len(long_stores),
            "same_base_within_0x100_raw_pair_count": len(pairs),
            "analyzable_pair_count": analyzed,
            "bounded_code_gate_pair_count": code_gated,
            "initializer_semantics_asserted": False,
        },
        signatures,
    )


def analyze_descriptor_lineage(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    dispatch_comparison: dict[str, object],
    optical_comparison: dict[str, object],
) -> dict[str, object]:
    dynamic_pairs = [
        row
        for row in dispatch_comparison["dispatch_pairs"]
        if row["matched_dynamic_descriptor_contract"]
    ]
    producer_pairs = []
    seen_calls = set()
    for dispatch_pair in dynamic_pairs:
        left = trace_dispatch_producer(left_reader, dispatch_pair["left"])
        right = trace_dispatch_producer(right_reader, dispatch_pair["right"])
        key = (
            int(left["producer_call_site_offset"]),
            int(right["producer_call_site_offset"]),
        )
        if key in seen_calls:
            continue
        seen_calls.add(key)
        target_shape_equal = bool(
            left.get("producer_target_code_evidence", {}).get(
                "normalized_shape_sha256"
            )
            == right.get("producer_target_code_evidence", {}).get(
                "normalized_shape_sha256"
            )
        )
        both_gated = bool(
            left.get("producer_target_code_evidence", {}).get(
                "bounded_code_gate_passed"
            )
            and right.get("producer_target_code_evidence", {}).get(
                "bounded_code_gate_passed"
            )
        )
        producer_pairs.append(
            {
                "left": left,
                "right": right,
                "target_path_equal": left["producer_target_path"]
                == right["producer_target_path"],
                "target_shape_equal": target_shape_equal,
                "both_target_code_gates_passed": both_gated,
                "cross_version_producer_target_promoted": bool(
                    target_shape_equal and both_gated
                ),
                "classification": (
                    "CONFIRMED_PAIRED_LITERAL_PRODUCER_CALL_SITES_"
                    "ASYMMETRIC_TARGET_EVIDENCE"
                ),
            }
        )

    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    accessor_clusters = {
        "left": _find_field12_accessors(left_reader, left_data),
        "right": _find_field12_accessors(right_reader, right_data),
    }
    paired_accessor_clusters = []
    for left_cluster in accessor_clusters["left"]:
        if left_cluster["occurrence_count"] < 2:
            continue
        for right_cluster in accessor_clusters["right"]:
            if (
                left_cluster["occurrence_count"]
                == right_cluster["occurrence_count"]
                and left_cluster["relative_gap_vector"]
                == right_cluster["relative_gap_vector"]
            ):
                paired_accessor_clusters.append(
                    {
                        "occurrence_count": left_cluster["occurrence_count"],
                        "relative_gap_vector": copy.deepcopy(
                            left_cluster["relative_gap_vector"]
                        ),
                        "left_members": copy.deepcopy(left_cluster["members"]),
                        "right_members": copy.deepcopy(right_cluster["members"]),
                    }
                )

    right_child_targets = {
        int(pair["right"]["producer_child_target_file_offset"])
        for pair in producer_pairs
        if isinstance(
            pair["right"].get("producer_child_target_file_offset"), int
        )
    }
    linked_accessor_pair = None
    for cluster in paired_accessor_clusters:
        right_offsets = [int(item["file_offset"]) for item in cluster["right_members"]]
        intersection = right_child_targets & set(right_offsets)
        if len(intersection) != 1:
            continue
        right_target = next(iter(intersection))
        ordinal = right_offsets.index(right_target)
        left_member = cluster["left_members"][ordinal]
        right_member = cluster["right_members"][ordinal]
        linked_accessor_pair = {
            "cluster_occurrence_count": cluster["occurrence_count"],
            "member_ordinal": ordinal,
            "left_direct_runtime_word_reference_count": left_member[
                "direct_runtime_word_reference_count"
            ],
            "right_direct_runtime_word_reference_count": right_member[
                "direct_runtime_word_reference_count"
            ],
            "right_producer_to_accessor_edge": "CONFIRMED_SINGLE_RELEASE",
            "left_producer_to_accessor_edge": "NOT_FOUND_UNDER_DIRECT_REFERENCE_MODEL",
            "cross_version_accessor_shape": "CONFIRMED",
            "cross_version_producer_edge": "OPEN",
        }
        break

    optical_nodes = [
        node
        for node in optical_comparison["graph"]["nodes"]
        if node["domain"] == "optical"
    ]
    left_optical = {int(node["left_entry_file_offset"]) for node in optical_nodes}
    right_optical = {int(node["right_entry_file_offset"]) for node in optical_nodes}
    left_census, left_descriptors = _static_descriptor_census(
        left_reader, left_data, left_optical
    )
    right_census, right_descriptors = _static_descriptor_census(
        right_reader, right_data, right_optical
    )

    left_by_target: dict[int, list[dict[str, object]]] = defaultdict(list)
    right_by_target: dict[int, list[dict[str, object]]] = defaultdict(list)
    for row in left_descriptors:
        left_by_target[int(row["target"])].append(row)
    for row in right_descriptors:
        right_by_target[int(row["target"])].append(row)
    matched_families = 0
    matched_signatures = set()
    referenced_both = set()
    for node in optical_nodes:
        left_target = int(node["left_entry_file_offset"])
        right_target = int(node["right_entry_file_offset"])
        family_matched = False
        for left_row in left_by_target.get(left_target, []):
            left_key = (
                left_row["adjustment"],
                left_row["field0_role"],
                left_row["field4_role"],
            )
            for right_row in right_by_target.get(right_target, []):
                right_key = (
                    right_row["adjustment"],
                    right_row["field0_role"],
                    right_row["field4_role"],
                )
                if left_key != right_key:
                    continue
                family_matched = True
                signature = (left_target, right_target, *left_key)
                matched_signatures.add(signature)
                if left_row["base_referenced"] and right_row["base_referenced"]:
                    referenced_both.add(signature)
        matched_families += family_matched

    left_initializer, left_signatures = _initializer_census(
        left_reader, left_data
    )
    right_initializer, right_signatures = _initializer_census(
        right_reader, right_data
    )
    paired_initializer_signatures = sum(
        min(count, right_signatures.get(signature, 0))
        for signature, count in left_signatures.items()
    )
    paired_gated_initializer_signatures = sum(
        min(count, right_signatures.get(signature, 0))
        for signature, count in left_signatures.items()
        if signature[5] is True
    )

    unique_target_pairs = {
        (
            int(pair["left"].get("producer_target_file_offset", -1)),
            int(pair["right"].get("producer_target_file_offset", -1)),
        )
        for pair in producer_pairs
    }
    return {
        "schema": "phoenix-mmi.descriptor-producer-lineage-comparison/v1",
        "analysis_mode": "read-only-static-bounded-producer-and-field-lineage",
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "limits": {
            "registered_session016_dynamic_dispatch_only": True,
            "producer_is_nearest_preceding_call": True,
            "maximum_predecessor_bytes": 0x100,
            "static_descriptor_adjustment_bound": 0x400,
            "field_initializer_distance_bound": 0x100,
            "function_boundary_asserted": False,
            "path_dominance_asserted": False,
        },
        "producer_pairs": producer_pairs,
        "accessor_family": {
            "left_occurrence_count": sum(
                int(cluster["occurrence_count"])
                for cluster in accessor_clusters["left"]
            ),
            "right_occurrence_count": sum(
                int(cluster["occurrence_count"])
                for cluster in accessor_clusters["right"]
            ),
            "paired_non_singleton_cluster_count": len(paired_accessor_clusters),
            "linked_accessor_pair": linked_accessor_pair,
            "accessor_semantics": "RETURNS_32_BIT_FIELD_AT_OFFSET_12",
            "owner_semantics": "OPEN",
        },
        "static_descriptor_census": {
            "left": left_census,
            "right": right_census,
            "accepted_optical_target_pair_count": len(optical_nodes),
            "optical_target_pair_with_matching_signature_count": matched_families,
            "matching_signature_count": len(matched_signatures),
            "matching_signature_referenced_in_both_count": len(referenced_both),
        },
        "field_initializer_census": {
            "left": left_initializer,
            "right": right_initializer,
            "paired_analyzable_signature_count": paired_initializer_signatures,
            "paired_code_gated_signature_count": paired_gated_initializer_signatures,
        },
        "classification": {
            "producer_call_pair_count": len(producer_pairs),
            "unique_producer_target_pair_count": len(unique_target_pairs),
            "cross_version_producer_target_promoted_count": sum(
                pair["cross_version_producer_target_promoted"]
                for pair in producer_pairs
            ),
            "single_release_field12_accessor_chain_count": sum(
                pair["right"].get("producer_child_return_path")
                == "LOAD32[12](ENTRY:r4)"
                for pair in producer_pairs
            ),
            "cross_version_accessor_cluster_confirmed": linked_accessor_pair
            is not None,
            "cross_version_producer_to_accessor_edge": "OPEN",
            "descriptor_initializer": "NOT_FOUND_UNDER_CODE_GATED_MIXED_WIDTH_MODEL",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "actual_fldb_parser": "OPEN",
        },
        "interpretation": (
            "Both dispatch sites have paired literal-backed producer calls with "
            "stable argument roles, but producer target evidence is asymmetric. "
            "CD3 alone forwards through a field-12 accessor. A matching accessor "
            "cluster and optical-targeting descriptor signatures exist across "
            "releases, yet no producer edge or code-gated initializer closes the "
            "lineage in both releases."
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


def update_operational_graph_v10(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v10"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "descriptor-producer-lineage"
    ]
    graph["nodes"].append(
        {
            "id": "descriptor-producer-lineage",
            "label": "Descriptor producer, accessor family and initializer search",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "producer_call_pairs": comparison["classification"][
                "producer_call_pair_count"
            ],
            "producer_target_promotion_count": comparison["classification"][
                "cross_version_producer_target_promoted_count"
            ],
            "producer_to_accessor_edge": "OPEN",
            "evidence": ["S017-01", "S017-02", "S017-03", "RQ-046", "RQ-047"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "descriptor-producer-lineage"
            and edge["target"] == "fldb-parser-routine"
        )
    ]
    graph["edges"].append(
        {
            "source": "descriptor-producer-lineage",
            "target": "fldb-parser-routine",
            "relation": (
                "producer calls and field-12 accessor family found; bilateral "
                "producer edge and code-gated initializer absent"
            ),
            "status": "BOUNDED_NEGATIVE",
        }
    )
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED") for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE") for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(node["status"] == "OPEN" for node in graph["nodes"])
    graph["bounded_negative_edge_count"] = sum(
        edge["status"] == "BOUNDED_NEGATIVE" for edge in graph["edges"]
    )
    graph["interpretation"] = comparison["interpretation"]
    return graph


def correlate_descriptor_lineage(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.descriptor-lineage-correlation/v1",
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
        "operational_graph": update_operational_graph_v10(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_descriptor_lineage_report(
    report: dict[str, object]
) -> dict[str, object]:
    return copy.deepcopy(report)

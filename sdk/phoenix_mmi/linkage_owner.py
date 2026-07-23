"""Bounded owner lineage for residual pointer-zero calls.

Session 021 groups the four residual CD3 calls into prologue-backed owner
windows, correlates them with CD1 calls to one short return-terminated target
and places the result in a global owner census.  Owner windows are bounded
analysis units, never asserted function boundaries.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
from difflib import SequenceMatcher
import re

from .accessor_dispatch import (
    _callsite_signature,
    _literal_jsr_calls,
    _target_reference_profile,
)
from .binary import BinaryReader
from .object_dispatch import _bounded_context
from .optical_callgraph import _decode_window, summarize_bounded_entry
from .runtime_linkage import _pointer_zero_runs


_OWNER_BACKWARD_BYTES = 0x100
_OWNER_FORWARD_BYTES = 0x180
_CONFIRMED_OWNER_SIMILARITY = 0.95
_PROBABLE_OWNER_SIMILARITY = 0.75
_PROBABLE_OWNER_MARGIN = 0.25
_SHORT_LEAF_MAXIMUM_BYTES = 32
_ADDRESS = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)


class _MemoryReader:
    """Read-only in-memory adapter for repeated bounded decoding."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

    def read(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]


def _owner_summary(reader: _MemoryReader, call_offset: int) -> dict[str, object]:
    _, context = _bounded_context(
        reader,
        call_offset,
        maximum_backward_bytes=_OWNER_BACKWARD_BYTES,
        maximum_forward_bytes=_OWNER_FORWARD_BYTES,
    )
    start = int(context["context_start_file_offset"])
    summary = summarize_bounded_entry(
        reader, start, source="SESSION021_BOUNDED_OWNER"
    )
    return {
        "owner_start_file_offset": start,
        "context_start_reason": context["context_start_reason"],
        "predecessor_bytes_included": context["predecessor_bytes_included"],
        "instruction_count": summary["instruction_count"],
        "known_ratio": summary["known_ratio"],
        "call_count": summary["call_count"],
        "return_count": summary["return_count"],
        "normalized_shape_sha256": summary["normalized_shape_sha256"],
        "bounded_code_gate_passed": summary["bounded_code_gate_passed"],
        "prologue_code_gate_passed": bool(
            summary["bounded_code_gate_passed"]
            and context["context_start_reason"] == "LATEST_SAVE_PR_PROLOGUE"
        ),
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }


def _normalized_owner_tokens(
    reader: _MemoryReader, owner_start: int
) -> list[tuple[str, str, str, bool]]:
    return [
        (
            instruction.mnemonic,
            _ADDRESS.sub("<address>", instruction.operands),
            instruction.flow,
            instruction.delayed,
        )
        for instruction in _decode_window(
            reader, owner_start, maximum_bytes=_OWNER_FORWARD_BYTES
        )
    ]


def _active_pointer_zero_targets(
    data: bytes, calls: list[dict[str, int]]
) -> tuple[set[int], dict[int, int]]:
    counts = Counter(int(row["target_file_offset"]) for row in calls)
    targets = set()
    target_to_run = {}
    for run in _pointer_zero_runs(data):
        start = int(run["run_start_file_offset"])
        for record_ordinal in range(int(run["record_count"])):
            record = start + record_ordinal * 16
            for tail_word_ordinal in range(3):
                target = record + 4 + tail_word_ordinal * 4
                if counts[target]:
                    targets.add(target)
                    target_to_run[target] = start
    return targets, target_to_run


def _owner_census(
    data: bytes, calls: list[dict[str, int]]
) -> tuple[dict[str, object], Counter[str]]:
    reader = _MemoryReader(data)
    active_targets, target_to_run = _active_pointer_zero_targets(data, calls)
    selected_calls = [
        row for row in calls if int(row["target_file_offset"]) in active_targets
    ]
    owners = {}
    owner_rows: dict[int, list[dict[str, int]]] = defaultdict(list)
    for row in selected_calls:
        owner = _owner_summary(reader, int(row["load_file_offset"]))
        start = int(owner["owner_start_file_offset"])
        owners.setdefault(start, owner)
        owner_rows[start].append(row)

    rows = []
    for start, owner in owners.items():
        calls_in_owner = owner_rows[start]
        targets = {
            int(call["target_file_offset"]) for call in calls_in_owner
        }
        runs = {target_to_run[target] for target in targets}
        rows.append(
            {
                **owner,
                "active_call_count": len(calls_in_owner),
                "active_target_count": len(targets),
                "active_run_count": len(runs),
            }
        )
    accepted = [row for row in rows if row["prologue_code_gate_passed"]]
    shape_counts = Counter(
        str(row["normalized_shape_sha256"]) for row in accepted
    )
    return (
        {
            "active_pointer_zero_target_count": len(active_targets),
            "active_pointer_zero_call_count": len(selected_calls),
            "bounded_owner_count": len(rows),
            "code_gated_owner_count": sum(
                bool(row["bounded_code_gate_passed"]) for row in rows
            ),
            "code_gated_active_call_count": sum(
                int(row["active_call_count"])
                for row in rows
                if row["bounded_code_gate_passed"]
            ),
            "prologue_code_gated_owner_count": len(accepted),
            "prologue_code_gated_active_call_count": sum(
                int(row["active_call_count"]) for row in accepted
            ),
            "context_start_reason_counts": dict(
                sorted(
                    Counter(
                        str(row["context_start_reason"]) for row in rows
                    ).items()
                )
            ),
            "active_call_count_per_owner_histogram": {
                str(key): value
                for key, value in sorted(
                    Counter(int(row["active_call_count"]) for row in rows).items()
                )
            },
            "active_target_count_per_owner_histogram": {
                str(key): value
                for key, value in sorted(
                    Counter(int(row["active_target_count"]) for row in rows).items()
                )
            },
            "exact_prologue_owner_shape_count": len(shape_counts),
            "function_boundaries_asserted": False,
            "global_call_census_is_syntactic": True,
        },
        shape_counts,
    )


def _group_calls_by_owner(
    reader: _MemoryReader, calls: list[dict[str, int]]
) -> tuple[dict[int, dict[str, object]], dict[int, list[dict[str, int]]]]:
    owners = {}
    grouped: dict[int, list[dict[str, int]]] = defaultdict(list)
    for row in calls:
        owner = _owner_summary(reader, int(row["load_file_offset"]))
        start = int(owner["owner_start_file_offset"])
        owners.setdefault(start, owner)
        grouped[start].append(row)
    return owners, grouped


def _alignment_row(
    left_reader: _MemoryReader,
    right_reader: _MemoryReader,
    *,
    left_owner: dict[str, object],
    right_owner: dict[str, object],
    right_calls: list[dict[str, int]],
    left_target_call_offsets: set[int],
) -> dict[str, object]:
    left_start = int(left_owner["owner_start_file_offset"])
    right_start = int(right_owner["owner_start_file_offset"])
    left_tokens = _normalized_owner_tokens(left_reader, left_start)
    right_tokens = _normalized_owner_tokens(right_reader, right_start)
    matcher = SequenceMatcher(a=left_tokens, b=right_tokens, autojunk=False)
    blocks = matcher.get_matching_blocks()
    aligned = []
    for call in right_calls:
        right_offset = int(call["load_file_offset"])
        right_index = (right_offset - right_start) // 2
        left_index = None
        for block in blocks:
            if block.b <= right_index < block.b + block.size:
                left_index = block.a + (right_index - block.b)
                break
        left_offset = (
            left_start + left_index * 2 if left_index is not None else None
        )
        aligned.append(
            {
                "right_load_file_offset": right_offset,
                "right_relative_instruction_index": right_index,
                "left_load_file_offset": left_offset,
                "left_relative_instruction_index": left_index,
                "aligned_to_left_target_call": bool(
                    left_offset in left_target_call_offsets
                    if left_offset is not None
                    else False
                ),
            }
        )
    return {
        "left_owner_start_file_offset": left_start,
        "right_owner_start_file_offset": right_start,
        "left_instruction_count": len(left_tokens),
        "right_instruction_count": len(right_tokens),
        "matching_instruction_count": sum(block.size for block in blocks),
        "sequence_similarity": round(matcher.ratio(), 6),
        "right_residual_call_count": len(right_calls),
        "aligned_left_target_call_count": sum(
            bool(row["aligned_to_left_target_call"]) for row in aligned
        ),
        "aligned_calls": aligned,
        "semantic_equivalence_asserted": False,
    }


def _short_leaf_profile(
    reader: _MemoryReader,
    data: bytes,
    calls: list[dict[str, int]],
    *,
    target: int,
) -> dict[str, object]:
    references = _target_reference_profile(
        data, calls, target=target, image_size=len(data)
    )
    summary = summarize_bounded_entry(
        reader, target, source="SESSION021_LEFT_SHORT_TARGET"
    )
    short_shape = bool(
        int(references["adjacent_literal_jsr_count"]) >= 4
        and int(summary["window_length"]) <= _SHORT_LEAF_MAXIMUM_BYTES
        and float(summary["known_ratio"]) >= 0.80
        and int(summary["return_count"]) == 1
        and int(summary["call_count"]) == 0
    )
    return {
        "target_file_offset": target,
        "reference_profile": references,
        "window_length": summary["window_length"],
        "instruction_count": summary["instruction_count"],
        "known_ratio": summary["known_ratio"],
        "return_count": summary["return_count"],
        "call_count": summary["call_count"],
        "normalized_shape_sha256": summary["normalized_shape_sha256"],
        "general_bounded_code_gate_passed": summary[
            "bounded_code_gate_passed"
        ],
        "literal_backed_short_return_shape_gate_passed": short_shape,
        "function_semantics_asserted": False,
    }


def _residual_lineage(
    left_data: bytes,
    right_data: bytes,
    prior: dict[str, object],
) -> dict[str, object]:
    left_reader = _MemoryReader(left_data)
    right_reader = _MemoryReader(right_data)
    left_calls = _literal_jsr_calls(left_data, image_size=len(left_data))
    right_calls = _literal_jsr_calls(right_data, image_size=len(right_data))
    right_active = prior["right"]["selected_run_activity"]["active_slots"]
    if not isinstance(right_active, list) or len(right_active) != 1:
        raise ValueError("Session 020 does not register one active right slot")
    right_target = int(right_active[0]["slot_file_offset"])
    residual_calls = [
        row
        for row in right_calls
        if int(row["target_file_offset"]) == right_target
    ]
    if len(residual_calls) != int(
        prior["right"]["selected_run_activity"]["adjacent_literal_jsr_count"]
    ):
        raise ValueError("right residual call count differs from Session 020")

    left_signature_index: dict[tuple[int, ...], list[dict[str, int]]] = (
        defaultdict(list)
    )
    for row in left_calls:
        signature = _callsite_signature(
            left_data, int(row["load_file_offset"])
        )
        if signature is not None:
            left_signature_index[signature].append(row)

    exact_rows = []
    exact_targets: Counter[int] = Counter()
    for row in residual_calls:
        signature = _callsite_signature(
            right_data, int(row["load_file_offset"])
        )
        matches = (
            left_signature_index.get(signature, [])
            if signature is not None
            else []
        )
        target_set = {
            int(match["target_file_offset"]) for match in matches
        }
        unique_target = (
            next(iter(target_set)) if len(target_set) == 1 else None
        )
        if unique_target is not None:
            exact_targets[unique_target] += 1
        exact_rows.append(
            {
                "right_load_file_offset": row["load_file_offset"],
                "left_context_match_count": len(matches),
                "single_left_target_consensus": unique_target,
                "unique_left_call_match": len(matches) == 1,
            }
        )
    if not exact_targets:
        raise ValueError("no left target consensus for residual calls")
    dominant_target, dominant_exact_count = exact_targets.most_common(1)[0]
    if dominant_exact_count < 2:
        raise ValueError("left target consensus is below the Session 021 gate")

    left_target_calls = [
        row
        for row in left_calls
        if int(row["target_file_offset"]) == dominant_target
    ]
    left_owners, left_grouped = _group_calls_by_owner(
        left_reader, left_target_calls
    )
    right_owners, right_grouped = _group_calls_by_owner(
        right_reader, residual_calls
    )
    left_offsets = {
        int(row["load_file_offset"]) for row in left_target_calls
    }

    exact_left_owner_by_call = {}
    for exact in exact_rows:
        if not exact["unique_left_call_match"]:
            continue
        right_row = next(
            row
            for row in residual_calls
            if row["load_file_offset"] == exact["right_load_file_offset"]
        )
        signature = _callsite_signature(
            right_data, int(right_row["load_file_offset"])
        )
        matches = left_signature_index.get(signature, [])
        if len(matches) == 1:
            left_owner = _owner_summary(
                left_reader, int(matches[0]["load_file_offset"])
            )
            exact_left_owner_by_call[int(right_row["load_file_offset"])] = int(
                left_owner["owner_start_file_offset"]
            )

    matrix = []
    for right_start, right_owner in sorted(right_owners.items()):
        for left_start, left_owner in sorted(left_owners.items()):
            row = _alignment_row(
                left_reader,
                right_reader,
                left_owner=left_owner,
                right_owner=right_owner,
                right_calls=right_grouped[right_start],
                left_target_call_offsets=left_offsets,
            )
            row["exact_context_call_count"] = sum(
                exact_left_owner_by_call.get(int(call["load_file_offset"]))
                == left_start
                for call in right_grouped[right_start]
            )
            matrix.append(row)

    selected_pairs = []
    used_left = set()
    for right_start, right_owner in sorted(right_owners.items()):
        candidates = sorted(
            [
                row
                for row in matrix
                if int(row["right_owner_start_file_offset"]) == right_start
            ],
            key=lambda row: (
                -float(row["sequence_similarity"]),
                int(row["left_owner_start_file_offset"]),
            ),
        )
        best = copy.deepcopy(candidates[0])
        second_similarity = (
            float(candidates[1]["sequence_similarity"])
            if len(candidates) > 1
            else 0.0
        )
        margin = float(best["sequence_similarity"]) - second_similarity
        left_start = int(best["left_owner_start_file_offset"])
        left_owner = left_owners[left_start]
        all_aligned = int(best["aligned_left_target_call_count"]) == int(
            best["right_residual_call_count"]
        )
        same_call_return_shape = bool(
            int(left_owner["call_count"]) == int(right_owner["call_count"])
            and int(left_owner["return_count"])
            == int(right_owner["return_count"])
        )
        unique_assignment = left_start not in used_left
        if (
            all_aligned
            and unique_assignment
            and int(best["exact_context_call_count"])
            == int(best["right_residual_call_count"])
            and float(best["sequence_similarity"])
            >= _CONFIRMED_OWNER_SIMILARITY
        ):
            classification = "CONFIRMED_CONTEXT_AND_SEQUENCE_OWNER_PAIR"
        elif (
            all_aligned
            and unique_assignment
            and same_call_return_shape
            and float(best["sequence_similarity"])
            >= _PROBABLE_OWNER_SIMILARITY
            and margin >= _PROBABLE_OWNER_MARGIN
        ):
            classification = "PROBABLE_UNIQUE_SEQUENCE_OWNER_PAIR"
        else:
            classification = "CANDIDATE_OWNER_PAIR"
        if classification != "CANDIDATE_OWNER_PAIR":
            used_left.add(left_start)
        best.update(
            {
                "next_best_sequence_similarity": round(second_similarity, 6),
                "sequence_similarity_margin": round(margin, 6),
                "same_call_and_return_counts": same_call_return_shape,
                "unique_left_owner_assignment": unique_assignment,
                "left_owner": copy.deepcopy(left_owner),
                "right_owner": copy.deepcopy(right_owner),
                "classification": classification,
            }
        )
        selected_pairs.append(best)

    confirmed = sum(
        row["classification"]
        == "CONFIRMED_CONTEXT_AND_SEQUENCE_OWNER_PAIR"
        for row in selected_pairs
    )
    probable = sum(
        row["classification"] == "PROBABLE_UNIQUE_SEQUENCE_OWNER_PAIR"
        for row in selected_pairs
    )
    aligned_calls = sum(
        int(row["aligned_left_target_call_count"])
        for row in selected_pairs
        if row["classification"]
        in {
            "CONFIRMED_CONTEXT_AND_SEQUENCE_OWNER_PAIR",
            "PROBABLE_UNIQUE_SEQUENCE_OWNER_PAIR",
        }
    )
    return {
        "right_residual_target_file_offset": right_target,
        "right_residual_call_count": len(residual_calls),
        "right_residual_owner_count": len(right_owners),
        "exact_context_mapping": {
            "rows": exact_rows,
            "single_target_consensus_call_count": dominant_exact_count,
            "dominant_left_target_file_offset": dominant_target,
        },
        "left_target": _short_leaf_profile(
            left_reader,
            left_data,
            left_calls,
            target=dominant_target,
        ),
        "left_target_call_count": len(left_target_calls),
        "left_target_owner_count": len(left_owners),
        "owner_pair_matrix": matrix,
        "selected_owner_pairs": selected_pairs,
        "confirmed_owner_pair_count": confirmed,
        "probable_owner_pair_count": probable,
        "aligned_residual_call_count": aligned_calls,
        "owner_semantics_asserted": False,
        "runtime_execution_observed": False,
    }


def analyze_linkage_owner_lineage(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
) -> dict[str, object]:
    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    left_calls = _literal_jsr_calls(left_data, image_size=left_reader.size)
    right_calls = _literal_jsr_calls(right_data, image_size=right_reader.size)
    lineage = _residual_lineage(left_data, right_data, prior)
    left_census, left_shapes = _owner_census(left_data, left_calls)
    right_census, right_shapes = _owner_census(right_data, right_calls)
    shared_shapes = set(left_shapes) & set(right_shapes)

    confirmed = int(lineage["confirmed_owner_pair_count"])
    probable = int(lineage["probable_owner_pair_count"])
    aligned_calls = int(lineage["aligned_residual_call_count"])
    return {
        "schema": "phoenix-mmi.linkage-owner-lineage-comparison/v1",
        "analysis_mode": "read-only-static-bounded-linkage-owner-lineage",
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "residual_lineage": lineage,
        "global_owner_census": {
            "left": left_census,
            "right": right_census,
            "shared_exact_prologue_owner_shape_count": len(shared_shapes),
            "left_owner_instances_in_shared_shapes": sum(
                left_shapes[shape] for shape in shared_shapes
            ),
            "right_owner_instances_in_shared_shapes": sum(
                right_shapes[shape] for shape in shared_shapes
            ),
            "semantic_owner_classes_asserted": False,
        },
        "classification": {
            "right_residual_calls": (
                "CONFIRMED_FOUR_CALLS_IN_TWO_PROLOGUE_CODE_GATED_OWNERS"
                if int(lineage["right_residual_call_count"]) == 4
                and int(lineage["right_residual_owner_count"]) == 2
                else "PARTIAL"
            ),
            "dominant_left_target": (
                "CONFIRMED_BY_TWO_EXACT_CONTEXT_MAPPINGS"
            ),
            "left_target_shape": (
                "CONFIRMED_LITERAL_BACKED_SHORT_RETURN_SHAPE"
                if lineage["left_target"][
                    "literal_backed_short_return_shape_gate_passed"
                ]
                else "PARTIAL"
            ),
            "owner_pairing": {
                "confirmed": confirmed,
                "probable": probable,
            },
            "residual_call_lineage": (
                "CONFIRMED_TWO_EXACT_PLUS_TWO_PROBABLE_SEQUENCE_ALIGNED"
                if confirmed == 1 and probable == 1 and aligned_calls == 4
                else "PARTIAL"
            ),
            "runtime_patch_overlay_or_linkage_mechanism": (
                "HYPOTHESIS_STRENGTHENED_BY_RESIDUAL_OWNER_LINEAGE"
            ),
            "runtime_linkage_family_owner_semantics": "OPEN",
            "specific_writer_or_loader_chain": "OPEN",
            "memory_loaded_base_writer": "OPEN",
            "specific_session017_producer_edge": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "actual_fldb_parser": "OPEN",
        },
        "limits": {
            "owner_backward_bytes": _OWNER_BACKWARD_BYTES,
            "owner_forward_bytes": _OWNER_FORWARD_BYTES,
            "confirmed_owner_similarity_gate": _CONFIRMED_OWNER_SIMILARITY,
            "probable_owner_similarity_gate": _PROBABLE_OWNER_SIMILARITY,
            "probable_owner_margin_gate": _PROBABLE_OWNER_MARGIN,
            "function_boundaries_asserted": False,
            "path_dominance_asserted": False,
            "global_call_census_is_syntactic": True,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "The four residual CD3 calls belong to two prologue-backed, code-"
            "gated owner windows. Two calls have unique fixed-context CD1 "
            "matches; complete owner-sequence alignment maps all four to the "
            "same CD1 short return-terminated target. One owner pair is "
            "confirmed by context and 98% sequence similarity, while the "
            "second is probable with a unique 78% match and a wide margin. "
            "This establishes bounded residual-call lineage but does not name "
            "the owner, observe runtime initialization or identify a writer."
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


def update_operational_graph_v14(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v14"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "runtime-linkage-owner-lineage"
    ]
    graph["nodes"].append(
        {
            "id": "runtime-linkage-owner-lineage",
            "label": "Residual runtime-linkage owner lineage",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "call_lineage_status": comparison["classification"][
                "residual_call_lineage"
            ],
            "owner_pairing": comparison["classification"]["owner_pairing"],
            "runtime_mechanism": comparison["classification"][
                "runtime_patch_overlay_or_linkage_mechanism"
            ],
            "evidence": ["S021-01", "S021-02", "S021-03", "RQ-059", "RQ-060"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "runtime-linkage-owner-lineage"
            and edge["target"] == "runtime-linkage-family"
        )
    ]
    graph["edges"].append(
        {
            "source": "runtime-linkage-owner-lineage",
            "target": "runtime-linkage-family",
            "relation": (
                "two residual CD3 owner windows align four calls to one CD1 "
                "short return-terminated target"
            ),
            "status": "CONFIRMED_AND_PROBABLE_STRUCTURAL_LINEAGE",
        }
    )
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED") for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE") for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(
        node["status"] == "OPEN" for node in graph["nodes"]
    )
    graph["bounded_negative_edge_count"] = sum(
        edge["status"] == "BOUNDED_NEGATIVE" for edge in graph["edges"]
    )
    graph["interpretation"] = comparison["interpretation"]
    return graph


def correlate_linkage_owner_lineage(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.linkage-owner-lineage-correlation/v1",
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
        "operational_graph": update_operational_graph_v14(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_linkage_owner_report(
    report: dict[str, object]
) -> dict[str, object]:
    return copy.deepcopy(report)

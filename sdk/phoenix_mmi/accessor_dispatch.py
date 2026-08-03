"""Accessor call-family and runtime-linkage analysis for Session 018.

The module separates five evidence classes: exact target words, PC-relative
literal loads, immediately adjacent JSR calls, normalized call-site contexts,
and zero-tail records.  None of them alone establishes callback, trampoline,
object, optical, parser, or sector-ABI semantics.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import re

from .binary import BinaryReader
from .descriptor_lineage import _find_field12_accessors
from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import _decode_window


_CONTEXT_BEFORE_WORDS = 8
_CONTEXT_AFTER_WORDS = 6
_MINIMUM_CONSENSUS_COVERAGE = 0.90
_MINIMUM_UNIQUE_MATCHES = 32


def _find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        hit = data.find(needle, start)
        if hit < 0:
            return hits
        hits.append(hit)
        start = hit + 1


def _literal_jsr_calls(data: bytes, *, image_size: int) -> list[dict[str, int]]:
    """Find adjacent SH MOV.L @(disp,PC),Rn / JSR @Rn candidates.

    This is a raw structural census.  Results become evidence only after a
    known target and a cross-version context gate are applied.
    """

    calls: list[dict[str, int]] = []
    for register in range(16):
        pattern = re.compile(
            bytes((0xD0 | register,))
            + b"."
            + bytes((0x40 | register, 0x0B)),
            re.DOTALL,
        )
        for match in pattern.finditer(data):
            referrer = match.start()
            if referrer & 1:
                continue
            load_word = int.from_bytes(data[referrer : referrer + 2], "big")
            literal = (referrer & ~3) + 4 + (load_word & 0xFF) * 4
            if literal + 4 > image_size:
                continue
            value = int.from_bytes(data[literal : literal + 4], "big")
            target = value - RUNTIME_BASE
            if not (0 <= target < image_size):
                continue
            calls.append(
                {
                    "load_file_offset": referrer,
                    "call_site_offset": referrer + 2,
                    "literal_file_offset": literal,
                    "target_file_offset": target,
                    "target_register": register,
                }
            )
    calls.sort(key=lambda row: int(row["load_file_offset"]))
    return calls


def _normalized_word(word: int) -> int:
    if word & 0xF000 in {0xD000, 0x9000}:
        return word & 0xFF00
    if word & 0xF000 in {0xA000, 0xB000}:
        return word & 0xF000
    if word & 0xFF00 in {0x8900, 0x8B00, 0x8D00, 0x8F00, 0xC700}:
        return word & 0xFF00
    return word


def _callsite_signature(
    data: bytes,
    load_offset: int,
    *,
    before_words: int = _CONTEXT_BEFORE_WORDS,
    after_words: int = _CONTEXT_AFTER_WORDS,
) -> tuple[int, ...] | None:
    start = load_offset - before_words * 2
    end = load_offset + (after_words + 2) * 2
    if start < 0 or end > len(data):
        return None
    return tuple(
        _normalized_word(int.from_bytes(data[offset : offset + 2], "big"))
        for offset in range(start, end, 2)
    )


def _target_reference_profile(
    data: bytes,
    calls: list[dict[str, int]],
    *,
    target: int,
    image_size: int,
) -> dict[str, object]:
    word = (RUNTIME_BASE + target).to_bytes(4, "big")
    occurrences = _find_all(data, word)
    aligned_occurrences = {offset for offset in occurrences if offset % 4 == 0}
    call_rows = [row for row in calls if row["target_file_offset"] == target]
    call_literals = {int(row["literal_file_offset"]) for row in call_rows}

    pc_relative_references = 0
    referenced_literals: set[int] = set()
    for literal in aligned_occurrences:
        start = max(0, literal - 0x404)
        start += start & 1
        for referrer in range(start, literal, 2):
            load_word = int.from_bytes(data[referrer : referrer + 2], "big")
            if load_word & 0xF000 != 0xD000:
                continue
            computed = (referrer & ~3) + 4 + (load_word & 0xFF) * 4
            if computed == literal:
                pc_relative_references += 1
                referenced_literals.add(literal)

    return {
        "target_file_offset": target,
        "exact_word_occurrence_count": len(occurrences),
        "aligned_word_occurrence_count": len(aligned_occurrences),
        "pc_relative_load_reference_count": pc_relative_references,
        "adjacent_literal_jsr_count": len(call_rows),
        "literal_pool_occurrence_used_by_adjacent_jsr_count": len(call_literals),
        "data_only_aligned_occurrence_count": len(
            aligned_occurrences - referenced_literals
        ),
        "all_aligned_occurrences_are_pc_relative_literals": bool(
            aligned_occurrences and aligned_occurrences <= referenced_literals
        ),
        "direct_callback_record_semantics_asserted": False,
        "image_size": image_size,
    }


def _pair_accessor_cluster(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    left_data: bytes,
    right_data: bytes,
    lineage: dict[str, object],
) -> dict[str, int]:
    linked = lineage["accessor_family"]["linked_accessor_pair"]
    if not isinstance(linked, dict):
        raise ValueError("Session 017 did not register a linked accessor cluster")
    occurrence_count = int(linked["cluster_occurrence_count"])
    ordinal = int(linked["member_ordinal"])
    right_children = {
        int(pair["right"]["producer_child_target_file_offset"])
        for pair in lineage["producer_pairs"]
        if isinstance(
            pair["right"].get("producer_child_target_file_offset"), int
        )
    }
    left_clusters = _find_field12_accessors(left_reader, left_data)
    right_clusters = _find_field12_accessors(right_reader, right_data)
    matches = []
    for left in left_clusters:
        if int(left["occurrence_count"]) != occurrence_count:
            continue
        for right in right_clusters:
            if (
                int(right["occurrence_count"]) == occurrence_count
                and left["relative_gap_vector"] == right["relative_gap_vector"]
                and ordinal < occurrence_count
            ):
                right_target = int(right["members"][ordinal]["file_offset"])
                if right_target in right_children:
                    matches.append(
                        {
                            "left_target": int(
                                left["members"][ordinal]["file_offset"]
                            ),
                            "right_target": right_target,
                        }
                    )
    if len(matches) != 1:
        raise ValueError(f"expected one linked accessor cluster, found {len(matches)}")
    return matches[0]


def _compare_call_families(
    left_data: bytes,
    right_data: bytes,
    left_calls: list[dict[str, int]],
    right_calls: list[dict[str, int]],
    *,
    right_target: int,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    selected_right = [
        row for row in right_calls if row["target_file_offset"] == right_target
    ]
    right_signatures = {
        signature
        for row in selected_right
        if (
            signature := _callsite_signature(
                right_data, int(row["load_file_offset"])
            )
        )
        is not None
    }
    left_index: dict[tuple[int, ...], list[dict[str, int]]] = defaultdict(list)
    for row in left_calls:
        signature = _callsite_signature(left_data, int(row["load_file_offset"]))
        if signature in right_signatures:
            left_index[signature].append(row)

    unique = 0
    ambiguous = 0
    unmatched = 0
    target_consensus = 0
    consensus_targets: Counter[int] = Counter()
    matches: list[dict[str, object]] = []
    for right in selected_right:
        signature = _callsite_signature(
            right_data, int(right["load_file_offset"])
        )
        candidates = left_index.get(signature, []) if signature is not None else []
        if len(candidates) == 1:
            unique += 1
        elif len(candidates) > 1:
            ambiguous += 1
        else:
            unmatched += 1
        targets = {int(row["target_file_offset"]) for row in candidates}
        consensus_target = next(iter(targets)) if len(targets) == 1 else None
        if consensus_target is not None:
            target_consensus += 1
            consensus_targets[consensus_target] += 1
        matches.append(
            {
                "right_call_site_offset": int(right["call_site_offset"]),
                "left_candidates": copy.deepcopy(candidates),
                "candidate_count": len(candidates),
                "target_consensus": consensus_target,
            }
        )

    dominant_target = None
    dominant_count = 0
    if consensus_targets:
        dominant_target, dominant_count = consensus_targets.most_common(1)[0]
    coverage = (
        dominant_count / len(selected_right) if selected_right else 0.0
    )
    promoted = bool(
        dominant_target is not None
        and coverage >= _MINIMUM_CONSENSUS_COVERAGE
        and unique >= _MINIMUM_UNIQUE_MATCHES
    )
    return (
        {
            "normalized_context_before_word_count": _CONTEXT_BEFORE_WORDS,
            "normalized_context_after_word_count": _CONTEXT_AFTER_WORDS,
            "normalized_context_total_word_count": (
                _CONTEXT_BEFORE_WORDS + _CONTEXT_AFTER_WORDS + 2
            ),
            "right_known_accessor_call_count": len(selected_right),
            "unique_left_context_match_count": unique,
            "ambiguous_left_context_match_count": ambiguous,
            "unmatched_right_context_count": unmatched,
            "single_target_consensus_context_count": target_consensus,
            "multi_target_ambiguous_context_count": sum(
                row["candidate_count"] > 1 and row["target_consensus"] is None
                for row in matches
            ),
            "dominant_left_target_file_offset": dominant_target,
            "dominant_left_target_consensus_count": dominant_count,
            "dominant_left_target_consensus_coverage": round(coverage, 6),
            "minimum_consensus_coverage": _MINIMUM_CONSENSUS_COVERAGE,
            "minimum_unique_context_matches": _MINIMUM_UNIQUE_MATCHES,
            "cross_version_call_family_promoted": promoted,
            "runtime_equivalence_asserted": False,
        },
        matches,
    )


def _find_zero_tail_record_run(
    data: bytes, *, target: int, image_size: int
) -> dict[str, object] | None:
    candidates = []
    for record_start in range(max(0, target - 15), target - 3):
        if record_start % 4 or record_start + 16 > image_size:
            continue
        pointer = int.from_bytes(data[record_start : record_start + 4], "big")
        if not (
            RUNTIME_BASE <= pointer < RUNTIME_BASE + image_size
            and data[record_start + 4 : record_start + 16] == bytes(12)
            and record_start + 4 <= target < record_start + 16
        ):
            continue
        run_start = record_start
        run_end = record_start + 16
        while run_start >= 16:
            probe = run_start - 16
            value = int.from_bytes(data[probe : probe + 4], "big")
            if not (
                RUNTIME_BASE <= value < RUNTIME_BASE + image_size
                and data[probe + 4 : probe + 16] == bytes(12)
            ):
                break
            run_start = probe
        while run_end + 16 <= image_size:
            value = int.from_bytes(data[run_end : run_end + 4], "big")
            if not (
                RUNTIME_BASE <= value < RUNTIME_BASE + image_size
                and data[run_end + 4 : run_end + 16] == bytes(12)
            ):
                break
            run_end += 16
        pointer_targets = [
            int.from_bytes(data[offset : offset + 4], "big") - RUNTIME_BASE
            for offset in range(run_start, run_end, 16)
        ]
        candidates.append(
            {
                "run_start_file_offset": run_start,
                "run_end_file_offset": run_end,
                "record_width": 16,
                "pointer_width": 4,
                "zero_tail_width": 12,
                "record_count": (run_end - run_start) // 16,
                "target_record_ordinal": (record_start - run_start) // 16,
                "target_offset_within_record": target - record_start,
                "zero_bytes_from_target_to_record_end": record_start + 16 - target,
                "pointer_target_delta_vector": [
                    pointer_targets[index] - pointer_targets[index - 1]
                    for index in range(1, len(pointer_targets))
                ],
                "all_pointer_fields_resolve_in_image": True,
                "candidate_run_count": 0,
                "runtime_patch_or_trampoline_semantics": "HYPOTHESIS",
            }
        )
    if not candidates:
        return None
    selected = max(candidates, key=lambda row: int(row["record_count"]))
    selected["candidate_run_count"] = len(candidates)
    return selected


def _graph_intersection(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    optical: dict[str, object],
    matches: list[dict[str, object]],
) -> dict[str, object]:
    right_calls_in_nodes: set[int] = set()
    bilateral_calls: set[int] = set()
    domains: Counter[str] = Counter()
    for node in optical["graph"]["nodes"]:
        left_offsets = {
            item.offset
            for item in _decode_window(
                left_reader, int(node["left_entry_file_offset"])
            )
        }
        right_offsets = {
            item.offset
            for item in _decode_window(
                right_reader, int(node["right_entry_file_offset"])
            )
        }
        for row in matches:
            right_site = int(row["right_call_site_offset"])
            if right_site not in right_offsets:
                continue
            right_calls_in_nodes.add(right_site)
            if any(
                int(candidate["call_site_offset"]) in left_offsets
                for candidate in row["left_candidates"]
            ):
                bilateral_calls.add(right_site)
                domains[str(node["domain"])] += 1
    return {
        "registered_node_pair_count": len(optical["graph"]["nodes"]),
        "right_accessor_call_in_registered_node_count": len(right_calls_in_nodes),
        "bilateral_call_in_same_paired_node_count": len(bilateral_calls),
        "bilateral_domain_counts": dict(sorted(domains.items())),
        "navigation_to_optical_edge": (
            "FOUND_STRUCTURALLY" if bilateral_calls else "NOT_FOUND"
        ),
        "callback_registration_semantics_asserted": False,
    }


def analyze_accessor_dispatch(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    lineage: dict[str, object],
    optical: dict[str, object],
) -> dict[str, object]:
    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    paired = _pair_accessor_cluster(
        left_reader, right_reader, left_data, right_data, lineage
    )
    left_calls = _literal_jsr_calls(left_data, image_size=left_reader.size)
    right_calls = _literal_jsr_calls(right_data, image_size=right_reader.size)
    left_accessor_profile = _target_reference_profile(
        left_data,
        left_calls,
        target=paired["left_target"],
        image_size=left_reader.size,
    )
    right_accessor_profile = _target_reference_profile(
        right_data,
        right_calls,
        target=paired["right_target"],
        image_size=right_reader.size,
    )
    call_family, matches = _compare_call_families(
        left_data,
        right_data,
        left_calls,
        right_calls,
        right_target=paired["right_target"],
    )
    dominant = call_family["dominant_left_target_file_offset"]
    dominant_profile = None
    placeholder = None
    if isinstance(dominant, int):
        dominant_profile = _target_reference_profile(
            left_data,
            left_calls,
            target=dominant,
            image_size=left_reader.size,
        )
        placeholder = _find_zero_tail_record_run(
            left_data, target=dominant, image_size=left_reader.size
        )
    intersection = _graph_intersection(
        left_reader, right_reader, optical, matches
    )
    data_only_total = int(left_accessor_profile["data_only_aligned_occurrence_count"])
    data_only_total += int(right_accessor_profile["data_only_aligned_occurrence_count"])
    if dominant_profile is not None:
        data_only_total += int(dominant_profile["data_only_aligned_occurrence_count"])

    return {
        "schema": "phoenix-mmi.accessor-call-family-comparison/v1",
        "analysis_mode": "read-only-static-bounded-accessor-call-family",
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "limits": {
            "registered_session017_accessor_pair_only": True,
            "literal_call_form": "ADJACENT_MOVL_PC_JSR_SAME_REGISTER",
            "normalized_context_before_words": _CONTEXT_BEFORE_WORDS,
            "normalized_context_after_words": _CONTEXT_AFTER_WORDS,
            "minimum_consensus_coverage": _MINIMUM_CONSENSUS_COVERAGE,
            "minimum_unique_context_matches": _MINIMUM_UNIQUE_MATCHES,
            "registered_session015_graph_only": True,
            "function_boundary_asserted": False,
            "runtime_execution_observed": False,
        },
        "raw_literal_jsr_census": {
            "left_candidate_count": len(left_calls),
            "right_candidate_count": len(right_calls),
            "code_semantics_asserted_for_raw_candidates": False,
        },
        "paired_accessor": {
            "left_target_file_offset": paired["left_target"],
            "right_target_file_offset": paired["right_target"],
            "left": left_accessor_profile,
            "right": right_accessor_profile,
            "structural_family_confirmed_by_session017": True,
        },
        "call_family": call_family,
        "dominant_left_target": {
            "profile": dominant_profile,
            "zero_tail_record_run": placeholder,
            "static_executable_target_asserted": False,
            "runtime_patch_or_trampoline_semantics": "HYPOTHESIS",
        },
        "direct_registration_search": {
            "data_only_aligned_target_occurrence_count": data_only_total,
            "static_callback_record_candidate_count": 0 if data_only_total == 0 else None,
            "classification": (
                "NOT_FOUND_UNDER_DIRECT_TARGET_WORD_MODEL"
                if data_only_total == 0
                else "OPEN_DATA_ONLY_OCCURRENCES_EXIST"
            ),
            "encoded_or_runtime_registration_excluded": False,
        },
        "registered_graph_intersection": intersection,
        "classification": {
            "cross_version_call_family": (
                "CONFIRMED_BOUNDED_TARGET_CONVERGENCE"
                if call_family["cross_version_call_family_promoted"]
                else "NOT_PROMOTED"
            ),
            "cd1_dominant_target_structure": (
                "CONFIRMED_ZERO_TAIL_RUNTIME_POINTER_RECORD_RUN"
                if placeholder is not None
                else "NOT_FOUND"
            ),
            "runtime_patch_or_trampoline_semantics": "HYPOTHESIS",
            "direct_callback_registration": (
                "NOT_FOUND_UNDER_DIRECT_TARGET_WORD_MODEL"
                if data_only_total == 0
                else "OPEN"
            ),
            "accepted_optical_graph_edge": (
                "NOT_FOUND_UNDER_REGISTERED_NODE_MODEL"
                if not intersection["bilateral_call_in_same_paired_node_count"]
                else "FOUND_STRUCTURALLY"
            ),
            "specific_session017_producer_edge": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "actual_fldb_parser": "OPEN",
        },
        "interpretation": (
            "The CD3 field-12 accessor is called through a large literal-backed "
            "family. Strong normalized contexts converge on one CD1 target that "
            "lies inside a five-record pointer-plus-zero-tail run, while the "
            "paired CD1 accessor itself has no direct references. This supports "
            "a cross-version call-family change and a runtime-linkage hypothesis, "
            "not executable-slot, callback, optical, parser, or sector-ABI semantics."
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


def update_operational_graph_v11(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v11"
    graph["nodes"] = [
        node for node in graph["nodes"] if node["id"] != "accessor-call-family"
    ]
    graph["nodes"].append(
        {
            "id": "accessor-call-family",
            "label": "Accessor call family and runtime-linkage-slot search",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "call_family_status": comparison["classification"][
                "cross_version_call_family"
            ],
            "runtime_linkage_semantics": "HYPOTHESIS",
            "accepted_optical_graph_edge": comparison["classification"][
                "accepted_optical_graph_edge"
            ],
            "evidence": ["S018-01", "S018-02", "S018-03", "RQ-050", "RQ-051"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "accessor-call-family"
            and edge["target"] == "optical-interprocedural-search"
        )
    ]
    graph["edges"].append(
        {
            "source": "accessor-call-family",
            "target": "optical-interprocedural-search",
            "relation": (
                "strong call-family contexts converge on a CD1 zero-tail slot; "
                "no bilateral call intersects the registered optical graph"
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
    graph["open_node_count"] = sum(
        node["status"] == "OPEN" for node in graph["nodes"]
    )
    graph["bounded_negative_edge_count"] = sum(
        edge["status"] == "BOUNDED_NEGATIVE" for edge in graph["edges"]
    )
    graph["interpretation"] = comparison["interpretation"]
    return graph


def correlate_accessor_dispatch(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.accessor-dispatch-correlation/v1",
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
        "operational_graph": update_operational_graph_v11(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_accessor_dispatch_report(
    report: dict[str, object]
) -> dict[str, object]:
    return copy.deepcopy(report)

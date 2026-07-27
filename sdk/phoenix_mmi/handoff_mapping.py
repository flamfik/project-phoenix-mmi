"""Session 029 local runtime-pointer-prefix mapping analysis.

The analyzer follows only the two Session 027 static handoff target pairs and
the Session 026 producer pair used as a negative control. It never assumes
that the Session 006 runtime-base relation is a universal file mapping.
"""

from __future__ import annotations

from collections import Counter, deque
import copy

from .binary import BinaryReader
from .handoff_field60 import _strict_target_profile
from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import (
    _decode_window,
    summarize_bounded_entry,
)
from .producer_return_family import _register_access


_RUNTIME_LIMIT = RUNTIME_BASE + 0x01000000
_MAX_PREFIX_WORDS = 8
_FUNCTION_WINDOW_BYTES = 0x180


def _leading_runtime_pointer_prefix(
    reader: BinaryReader,
    target: int,
    *,
    maximum_words: int = _MAX_PREFIX_WORDS,
) -> dict[str, object]:
    """Count a maximal aligned runtime-range word prefix without exposing it."""

    if target < 0 or target >= reader.size or target % 4:
        return {
            "target_file_offset": target,
            "aligned_target": False,
            "runtime_pointer_word_count": 0,
            "prefix_bytes": 0,
            "corrected_entry_file_offset": target,
            "maximum_words": maximum_words,
            "raw_pointer_values_included": False,
        }
    count = 0
    while count < maximum_words:
        offset = target + count * 4
        if offset + 4 > reader.size:
            break
        value = int.from_bytes(reader.read(offset, 4), "big")
        if not RUNTIME_BASE <= value < _RUNTIME_LIMIT:
            break
        count += 1
    prefix_bytes = count * 4
    return {
        "target_file_offset": target,
        "aligned_target": True,
        "runtime_pointer_word_count": count,
        "prefix_bytes": prefix_bytes,
        "corrected_entry_file_offset": target + prefix_bytes,
        "maximum_words": maximum_words,
        "prefix_is_maximal_under_bound": count < maximum_words,
        "raw_pointer_values_included": False,
    }


def _apply_register_access(
    instruction: object,
    live: bool,
    *,
    reads: set[int],
    unknowns: set[int],
) -> bool:
    if instruction.mnemonic == "unknown":
        unknowns.add(int(instruction.offset))
    read, write = _register_access(instruction, 5)
    if live and read:
        reads.add(int(instruction.offset))
    if write and not read:
        return False
    return live


def _bounded_entry_r5_cfg(
    reader: BinaryReader,
    entry: int,
) -> dict[str, object]:
    """Follow direct intraprocedural paths and test entry-r5 liveness."""

    instructions = _decode_window(
        reader, entry, maximum_bytes=_FUNCTION_WINDOW_BYTES
    )
    by_offset = {
        int(instruction.offset): instruction
        for instruction in instructions
    }
    queue: deque[tuple[int, bool]] = deque([(entry, True)])
    visited: set[tuple[int, bool]] = set()
    reads: set[int] = set()
    unknowns: set[int] = set()
    terminals: Counter[str] = Counter()
    indirect_or_external = 0

    def apply_delay(offset: int, live: bool) -> bool:
        delay = by_offset.get(offset)
        if delay is None:
            terminals["MISSING_DELAY_SLOT"] += 1
            return live
        return _apply_register_access(
            delay,
            live,
            reads=reads,
            unknowns=unknowns,
        )

    while queue:
        offset, live = queue.popleft()
        state = (offset, live)
        if state in visited:
            continue
        visited.add(state)
        instruction = by_offset.get(offset)
        if instruction is None:
            terminals["OUT_OF_BOUNDED_WINDOW"] += 1
            continue
        live = _apply_register_access(
            instruction,
            live,
            reads=reads,
            unknowns=unknowns,
        )

        if instruction.flow in {"call", "indirect-call"}:
            next_offset = offset + 2
            if instruction.delayed:
                live = apply_delay(offset + 2, live)
                next_offset = offset + 4
            queue.append((next_offset, False))
            continue
        if instruction.flow == "conditional":
            next_offset = offset + 2
            if instruction.delayed:
                live = apply_delay(offset + 2, live)
                next_offset = offset + 4
            if (
                isinstance(instruction.target, int)
                and instruction.target in by_offset
            ):
                queue.append((int(instruction.target), live))
            else:
                indirect_or_external += 1
                terminals["EXTERNAL_CONDITIONAL_TARGET"] += 1
            queue.append((next_offset, live))
            continue
        if instruction.flow == "branch":
            if instruction.delayed:
                live = apply_delay(offset + 2, live)
            if (
                isinstance(instruction.target, int)
                and instruction.target in by_offset
            ):
                queue.append((int(instruction.target), live))
            else:
                indirect_or_external += 1
                terminals["EXTERNAL_DIRECT_BRANCH"] += 1
            continue
        if instruction.flow == "return":
            if instruction.delayed:
                live = apply_delay(offset + 2, live)
            terminals[
                "RETURN_WITH_ENTRY_R5_LIVE"
                if live
                else "RETURN_AFTER_ENTRY_R5_KILL"
            ] += 1
            continue
        if instruction.flow in {
            "indirect-branch",
            "trap",
        }:
            if instruction.delayed:
                live = apply_delay(offset + 2, live)
            indirect_or_external += 1
            terminals[
                "INDIRECT_BRANCH" if instruction.flow == "indirect-branch"
                else "TRAP"
            ] += 1
            continue
        queue.append((offset + 2, live))

    complete = bool(
        terminals
        and not unknowns
        and indirect_or_external == 0
        and set(terminals)
        <= {
            "RETURN_WITH_ENTRY_R5_LIVE",
            "RETURN_AFTER_ENTRY_R5_KILL",
        }
    )
    return {
        "entry_file_offset": entry,
        "bounded_window_bytes": _FUNCTION_WINDOW_BYTES,
        "reachable_state_count": len(visited),
        "entry_r5_read_instruction_count": len(reads),
        "entry_r5_read_file_offsets": sorted(reads),
        "reachable_unknown_instruction_count": len(unknowns),
        "terminal_path_counts": dict(sorted(terminals.items())),
        "indirect_or_external_transfer_count": indirect_or_external,
        "bounded_direct_cfg_complete": complete,
        "entry_r5_read_confirmed": bool(reads),
        "entry_r5_ignored_on_all_modeled_paths": bool(
            complete and not reads
        ),
        "callee_calls_not_followed": True,
        "caller_saved_r5_clobber_applied_after_delay_slot": True,
        "path_dominance_asserted": False,
        "instruction_bytes_included": False,
    }


def _compact_entry_summary(
    reader: BinaryReader, entry: int
) -> dict[str, object]:
    summary = summarize_bounded_entry(
        reader, entry, source="SESSION029_PREFIX_CORRECTED_ENTRY"
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


def _corrected_target_profile(
    reader: BinaryReader,
    target: int,
    *,
    include_r5_cfg: bool,
) -> dict[str, object]:
    prefix = _leading_runtime_pointer_prefix(reader, target)
    entry = int(prefix["corrected_entry_file_offset"])
    strict = _strict_target_profile(reader, entry)
    summary = _compact_entry_summary(reader, entry)
    entry_valid = bool(
        prefix["runtime_pointer_word_count"]
        and prefix["prefix_is_maximal_under_bound"]
        and strict["strict_exact_entry_gate_passed"]
        and summary["bounded_code_gate_passed"]
        and summary["known_ratio"] == 1.0
    )
    return {
        "raw_target_file_offset": target,
        "prefix": prefix,
        "corrected_entry": summary,
        "strict_entry_gate": {
            "passed": strict["strict_exact_entry_gate_passed"],
            "save_pr_delta_from_entry": strict[
                "save_pr_delta_from_target"
            ],
            "unknown_instruction_count_before_save_pr": strict[
                "unknown_instruction_count_before_save_pr"
            ],
            "call_count_before_save_pr": strict[
                "call_count_before_save_pr"
            ],
            "control_transfer_count_before_save_pr": strict[
                "control_transfer_count_before_save_pr"
            ],
        },
        "local_prefix_correction_validated": entry_valid,
        "entry_r5_cfg": (
            _bounded_entry_r5_cfg(reader, entry)
            if entry_valid and include_r5_cfg
            else None
        ),
        "loader_or_section_mechanism_asserted": False,
    }


def analyze_handoff_mapping(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    session026: dict[str, object],
    session027: dict[str, object],
) -> dict[str, object]:
    """Validate local prefix correction for two registered handoff pairs."""

    rows = []
    for prior in session027["static_handoff_pairs"]:
        left = _corrected_target_profile(
            left_reader,
            int(prior["left_target_file_offset"]),
            include_r5_cfg=True,
        )
        right = _corrected_target_profile(
            right_reader,
            int(prior["right_target_file_offset"]),
            include_r5_cfg=True,
        )
        corrected_delta = (
            int(
                right["prefix"]["corrected_entry_file_offset"]
            )
            - int(
                left["prefix"]["corrected_entry_file_offset"]
            )
        )
        gates = {
            "runtime_pointer_prefix_present_both": bool(
                left["prefix"]["runtime_pointer_word_count"]
                and right["prefix"]["runtime_pointer_word_count"]
            ),
            "right_prefix_has_one_additional_word": (
                int(right["prefix"]["runtime_pointer_word_count"])
                == int(left["prefix"]["runtime_pointer_word_count"])
                + 1
            ),
            "local_prefix_correction_validated_both": bool(
                left["local_prefix_correction_validated"]
                and right["local_prefix_correction_validated"]
            ),
            "corrected_normalized_shape_equal": (
                left["corrected_entry"][
                    "normalized_shape_sha256"
                ]
                == right["corrected_entry"][
                    "normalized_shape_sha256"
                ]
            ),
            "corrected_call_return_counts_equal": bool(
                left["corrected_entry"]["call_count"]
                == right["corrected_entry"]["call_count"]
                and left["corrected_entry"]["return_count"]
                == right["corrected_entry"]["return_count"]
            ),
            "bounded_r5_cfg_complete_both": bool(
                left["entry_r5_cfg"]
                and right["entry_r5_cfg"]
                and left["entry_r5_cfg"][
                    "bounded_direct_cfg_complete"
                ]
                and right["entry_r5_cfg"][
                    "bounded_direct_cfg_complete"
                ]
            ),
            "entry_r5_ignored_on_all_modeled_paths_both": bool(
                left["entry_r5_cfg"]
                and right["entry_r5_cfg"]
                and left["entry_r5_cfg"][
                    "entry_r5_ignored_on_all_modeled_paths"
                ]
                and right["entry_r5_cfg"][
                    "entry_r5_ignored_on_all_modeled_paths"
                ]
            ),
        }
        gates["bilateral_corrected_handoff_gate_passed"] = all(
            gates.values()
        )
        rows.append(
            {
                "flow_ordinal": int(prior["flow_ordinal"]),
                "left": left,
                "right": right,
                "corrected_entry_file_offset_delta": corrected_delta,
                "gates": gates,
                "refined_return_use_classification": (
                    "CALL_RETURN_PRESENT_IN_UNUSED_ENTRY_R5"
                    if gates[
                        "bilateral_corrected_handoff_gate_passed"
                    ]
                    else "UNRESOLVED_STATIC_HANDOFF"
                ),
                "registration_path_established": False,
                "runtime_equivalence_asserted": False,
            }
        )

    producer_pair = session026["producer_target_pair"]
    producer_control = {
        "left": _corrected_target_profile(
            left_reader,
            int(producer_pair["left_target_file_offset"]),
            include_r5_cfg=False,
        ),
        "right": _corrected_target_profile(
            right_reader,
            int(producer_pair["right_target_file_offset"]),
            include_r5_cfg=False,
        ),
    }
    producer_control["prefix_correction_applies_both"] = bool(
        producer_control["left"][
            "local_prefix_correction_validated"
        ]
        and producer_control["right"][
            "local_prefix_correction_validated"
        ]
    )
    corrected_deltas = {
        int(row["corrected_entry_file_offset_delta"]) for row in rows
    }
    all_gates = all(
        row["gates"]["bilateral_corrected_handoff_gate_passed"]
        for row in rows
    )
    registration_disproved = bool(
        len(rows) == 2
        and all_gates
        and all(
            row["gates"][
                "entry_r5_ignored_on_all_modeled_paths_both"
            ]
            for row in rows
        )
    )
    return {
        "schema": "phoenix-mmi.handoff-mapping-comparison/v1",
        "analysis_mode": (
            "read-only-static-registered-runtime-prefix-correction"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "handoff_pairs": rows,
        "producer_negative_control": producer_control,
        "classification": {
            "registered_handoff_pair_count": len(rows),
            "bilateral_corrected_handoff_pair_count": sum(
                row["gates"][
                    "bilateral_corrected_handoff_gate_passed"
                ]
                for row in rows
            ),
            "common_corrected_entry_delta": (
                next(iter(corrected_deltas))
                if len(corrected_deltas) == 1
                else None
            ),
            "right_prefix_additional_word_pair_count": sum(
                row["gates"][
                    "right_prefix_has_one_additional_word"
                ]
                for row in rows
            ),
            "entry_r5_ignored_pair_count": sum(
                row["gates"][
                    "entry_r5_ignored_on_all_modeled_paths_both"
                ]
                for row in rows
            ),
            "all_handoff_correction_gates_passed": all_gates,
            "refined_static_flow_classification_counts": {
                "CALL_RETURN_PRESENT_IN_UNUSED_ENTRY_R5": sum(
                    row["refined_return_use_classification"]
                    == "CALL_RETURN_PRESENT_IN_UNUSED_ENTRY_R5"
                    for row in rows
                )
            },
            "session026_producer_prefix_correction": (
                "NOT_APPLICABLE"
                if not producer_control[
                    "prefix_correction_applies_both"
                ]
                else "VALIDATED"
            ),
            "static_handoff_registration_path": (
                "DISPROVED_FOR_TWO_CALLEES"
                if registration_disproved
                else "NOT_ESTABLISHED"
            ),
            "selected_owner_target_link": "NOT_ESTABLISHED",
            "loader_or_section_mechanism": "OPEN",
            "universal_runtime_to_file_mapping": "NOT_ESTABLISHED",
            "returned_object_type": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
        },
        "limits": {
            "handoff_source_session": 27,
            "producer_negative_control_source_session": 26,
            "maximum_prefix_words": _MAX_PREFIX_WORDS,
            "function_window_bytes": _FUNCTION_WINDOW_BYTES,
            "only_registered_target_pairs_followed": True,
            "forward_code_entry_search_performed": False,
            "prefix_end_is_deterministic_correction": True,
            "callee_calls_followed": False,
            "arbitrary_raw_image_code_scan_performed": False,
            "loader_or_section_parser_available": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "Both Session 027 handoff target pairs land on maximal aligned "
            "runtime-range word prefixes. Advancing by exactly each prefix "
            "length produces strict, fully decoded entries; corresponding "
            "CD1/CD3 bodies have equal normalized shapes and both corrected "
            "pairs share one relocation delta. CD3 has one additional prefix "
            "word in each pair. Direct bounded CFG analysis proves that entry "
            "r5 is never read on any modeled path in either callee, refining "
            "the two former handoffs to incidental CALL_RETURN values in an "
            "unused caller-saved register. The Session 026 producer has no "
            "such prefix and remains invalid, so the correction is not "
            "generalized. The physical loader/section mechanism and universal "
            "runtime-to-file map remain open."
        ),
        "publication_safety": {
            "firmware_bytes_included": False,
            "instruction_bytes_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "raw_strings_included": False,
            "local_paths_included": False,
            "map_payload_included": False,
        },
    }


def update_operational_graph_v22(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v22"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "prefix-corrected-static-callees"
    ]
    graph["nodes"].append(
        {
            "id": "prefix-corrected-static-callees",
            "label": "Prefix-corrected static callees",
            "status": "CONFIRMED_BILATERAL_STRUCTURAL_FAMILY",
            "callee_pair_count": comparison["classification"][
                "bilateral_corrected_handoff_pair_count"
            ],
            "entry_r5_ignored_pair_count": comparison[
                "classification"
            ]["entry_r5_ignored_pair_count"],
            "evidence": ["S029-01", "S029-02", "RQ-092", "RQ-093"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "producer-return-use-family"
            and edge["target"] == "prefix-corrected-static-callees"
        )
        and not (
            edge["source"] == "prefix-corrected-static-callees"
            and edge["target"] == "runtime-linkage-owner-ingress"
        )
    ]
    graph["edges"].extend(
        [
            {
                "source": "producer-return-use-family",
                "target": "prefix-corrected-static-callees",
                "relation": (
                    "two static call targets resolve after deterministic "
                    "leading runtime-pointer prefixes"
                ),
                "status": "CONFIRMED_STRUCTURAL",
            },
            {
                "source": "prefix-corrected-static-callees",
                "target": "runtime-linkage-owner-ingress",
                "relation": (
                    "entry r5 is ignored on all modeled paths; no "
                    "registration or selected-owner edge exists"
                ),
                "status": "DISPROVED_FOR_BOUNDED_CALLEE_FAMILY",
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
    graph["disproved_edge_count"] = sum(
        "DISPROVED" in edge["status"] for edge in graph["edges"]
    )
    graph["interpretation"] = comparison["interpretation"]
    return graph


def correlate_handoff_mapping(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.handoff-mapping-correlation/v1",
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
        "operational_graph": update_operational_graph_v22(
            prior_correlation["operational_graph"],
            comparison,
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_handoff_mapping_report(
    report: dict[str, object],
) -> dict[str, object]:
    """Return a detached already-publication-safe report."""

    return copy.deepcopy(report)

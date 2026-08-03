"""Session 030 literal-pool boundary correction.

The analyzer revisits only the two Session 029 registered targets. It tests
whether each alleged prefix is the suffix of a larger PC-relative literal
pool and deliberately separates adjacent code from a proven runtime callee.
"""

from __future__ import annotations

from collections import Counter
import copy
import hashlib
import json

from .binary import BinaryReader
from .handoff_field60 import _strict_target_profile
from .linkage_owner import _MemoryReader
from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import summarize_bounded_entry
from .owner_provenance import (
    _classify_pointer_use,
    _scan_direct_bsr_calls,
)
from .superh import find_pc_relative_referrers


_RUNTIME_LIMIT = RUNTIME_BASE + 0x01000000
_MAX_POOL_WORDS_EACH_DIRECTION = 16


def _runtime_word(
    reader: BinaryReader, offset: int
) -> int | None:
    if offset < 0 or offset + 4 > reader.size or offset % 4:
        return None
    value = int.from_bytes(reader.read(offset, 4), "big")
    if RUNTIME_BASE <= value < _RUNTIME_LIMIT:
        return value
    return None


def _maximal_runtime_pool_containing(
    reader: BinaryReader,
    target: int,
    *,
    maximum_words_each_direction: int = (
        _MAX_POOL_WORDS_EACH_DIRECTION
    ),
) -> dict[str, object]:
    """Find one bounded maximal runtime-word run containing target."""

    if (
        target < 0
        or target >= reader.size
        or target % 4
        or _runtime_word(reader, target) is None
    ):
        return {
            "registered_target_file_offset": target,
            "target_is_aligned_runtime_word": False,
            "pool_found": False,
            "raw_pointer_values_included": False,
        }

    start = target
    backward_words = 0
    while (
        backward_words < maximum_words_each_direction
        and _runtime_word(reader, start - 4) is not None
    ):
        start -= 4
        backward_words += 1
    backward_bound_exhausted = bool(
        backward_words == maximum_words_each_direction
        and _runtime_word(reader, start - 4) is not None
    )

    end = target
    forward_words = 0
    while (
        forward_words < maximum_words_each_direction
        and _runtime_word(reader, end) is not None
    ):
        end += 4
        forward_words += 1
    forward_bound_exhausted = bool(
        forward_words == maximum_words_each_direction
        and _runtime_word(reader, end) is not None
    )
    word_count = (end - start) // 4
    target_index = (target - start) // 4
    complete = bool(
        word_count
        and not backward_bound_exhausted
        and not forward_bound_exhausted
    )
    return {
        "registered_target_file_offset": target,
        "target_is_aligned_runtime_word": True,
        "pool_found": complete,
        "pool_start_file_offset": start,
        "pool_end_file_offset": end,
        "pool_word_count": word_count,
        "registered_target_word_index": target_index,
        "words_before_registered_target": target_index,
        "words_from_registered_target_to_pool_end": (
            word_count - target_index
        ),
        "bytes_from_registered_target_to_pool_end": end - target,
        "registered_target_is_pool_start": target == start,
        "registered_target_is_pool_member": start <= target < end,
        "backward_bound_exhausted": backward_bound_exhausted,
        "forward_bound_exhausted": forward_bound_exhausted,
        "maximum_words_each_direction": maximum_words_each_direction,
        "raw_pointer_values_included": False,
    }


def _pool_reference_profile(
    reader: BinaryReader,
    memory: _MemoryReader,
    pool: dict[str, object],
) -> dict[str, object]:
    if not pool["pool_found"]:
        return {
            "entries": [],
            "pool_word_count": 0,
            "pc_relative_referrer_count": 0,
            "all_pool_words_have_one_pc_relative_referrer": False,
            "all_referrers_precede_pool": False,
            "use_classification_counts": {},
            "relative_role_signature_sha256": None,
            "role_signature_uses_raw_pointer_values": False,
            "raw_pointer_values_included": False,
        }
    start = int(pool["pool_start_file_offset"])
    end = int(pool["pool_end_file_offset"])
    entries = []
    role_signature = []
    for index, literal in enumerate(range(start, end, 4)):
        referrers = find_pc_relative_referrers(reader, literal)
        uses = []
        for referrer in referrers:
            use = _classify_pointer_use(memory, referrer.offset)
            public_use = {
                "referrer_relative_to_pool_start": (
                    int(referrer.offset) - start
                ),
                "referrer_precedes_pool": int(referrer.offset) < start,
                "classification": use["classification"],
                "relative_use_instruction_index": use.get(
                    "relative_use_instruction_index"
                ),
                "loaded_register": use.get("loaded_register"),
                "call_register": use.get("call_register"),
            }
            uses.append(public_use)
            role_signature.append(
                (
                    index,
                    public_use[
                        "referrer_relative_to_pool_start"
                    ],
                    public_use["classification"],
                    public_use[
                        "relative_use_instruction_index"
                    ],
                    public_use["loaded_register"],
                    public_use["call_register"],
                )
            )
        entries.append(
            {
                "word_index": index,
                "word_relative_to_pool_start": literal - start,
                "pc_relative_referrer_count": len(referrers),
                "uses": uses,
                "raw_pointer_value_included": False,
            }
        )
    classifications = Counter(
        use["classification"]
        for entry in entries
        for use in entry["uses"]
    )
    signature_bytes = json.dumps(
        role_signature,
        separators=(",", ":"),
    ).encode("ascii")
    return {
        "entries": entries,
        "pool_word_count": len(entries),
        "pc_relative_referrer_count": sum(
            entry["pc_relative_referrer_count"]
            for entry in entries
        ),
        "all_pool_words_have_one_pc_relative_referrer": all(
            entry["pc_relative_referrer_count"] == 1
            for entry in entries
        ),
        "all_referrers_precede_pool": all(
            use["referrer_precedes_pool"]
            for entry in entries
            for use in entry["uses"]
        ),
        "use_classification_counts": dict(
            sorted(classifications.items())
        ),
        "relative_role_signature_sha256": hashlib.sha256(
            signature_bytes
        ).hexdigest(),
        "role_signature_uses_raw_pointer_values": False,
        "raw_pointer_values_included": False,
    }


def _runtime_address_reference_census(
    reader: BinaryReader,
    memory: _MemoryReader,
    file_offset: int,
    direct_bsr_targets: Counter[int],
) -> dict[str, object]:
    word = (RUNTIME_BASE + file_offset).to_bytes(4, "big")
    occurrences = list(reader.find_all(word))
    aligned = [offset for offset in occurrences if offset % 4 == 0]
    classifications: Counter[str] = Counter()
    pc_referrer_count = 0
    for literal in aligned:
        for referrer in find_pc_relative_referrers(reader, literal):
            pc_referrer_count += 1
            classifications[
                _classify_pointer_use(
                    memory, referrer.offset
                )["classification"]
            ] += 1
    return {
        "file_offset": file_offset,
        "exact_word_occurrence_count": len(occurrences),
        "aligned_word_occurrence_count": len(aligned),
        "pc_relative_referrer_count": pc_referrer_count,
        "use_classification_counts": dict(
            sorted(classifications.items())
        ),
        "direct_bsr_target_count": direct_bsr_targets[file_offset],
        "runtime_address_value_included": False,
    }


def _successor_profile(
    reader: BinaryReader, entry: int
) -> dict[str, object]:
    strict = _strict_target_profile(reader, entry)
    summary = summarize_bounded_entry(
        reader, entry, source="SESSION030_POOL_END_SUCCESSOR"
    )
    return {
        "entry_file_offset": entry,
        "strict_exact_entry_gate_passed": strict[
            "strict_exact_entry_gate_passed"
        ],
        "known_ratio": summary["known_ratio"],
        "normalized_shape_sha256": summary[
            "normalized_shape_sha256"
        ],
        "instruction_count": summary["instruction_count"],
        "call_count": summary["call_count"],
        "return_count": summary["return_count"],
        "bounded_code_gate_passed": summary[
            "bounded_code_gate_passed"
        ],
        "function_boundary_asserted": False,
        "runtime_callee_asserted": False,
        "instruction_bytes_included": False,
    }


def _disc_target_profile(
    reader: BinaryReader,
    target: int,
    *,
    memory: _MemoryReader,
    direct_bsr_targets: Counter[int],
) -> dict[str, object]:
    pool = _maximal_runtime_pool_containing(reader, target)
    references = _pool_reference_profile(reader, memory, pool)
    pool_end = int(pool.get("pool_end_file_offset", target))
    raw_target_references = _runtime_address_reference_census(
        reader, memory, target, direct_bsr_targets
    )
    pool_end_references = _runtime_address_reference_census(
        reader, memory, pool_end, direct_bsr_targets
    )
    successor = _successor_profile(reader, pool_end)
    full_literal_pool = bool(
        pool["pool_found"]
        and references[
            "all_pool_words_have_one_pc_relative_referrer"
        ]
        and references["all_referrers_precede_pool"]
    )
    return {
        "registered_target_file_offset": target,
        "pool": pool,
        "pool_references": references,
        "registered_target_runtime_reference_census": (
            raw_target_references
        ),
        "pool_end_runtime_reference_census": pool_end_references,
        "pool_end_successor": successor,
        "classification": {
            "registered_target_is_literal_pool_member": full_literal_pool,
            "session029_prefix_is_literal_pool_suffix": full_literal_pool,
            "pool_end_is_strict_code_successor": bool(
                successor["strict_exact_entry_gate_passed"]
                and successor["bounded_code_gate_passed"]
                and successor["known_ratio"] == 1.0
            ),
            "pool_end_has_static_runtime_reference": bool(
                pool_end_references[
                    "pc_relative_referrer_count"
                ]
                or pool_end_references["direct_bsr_target_count"]
            ),
            "pool_end_runtime_callee_established": False,
        },
    }


def analyze_literal_pool_boundaries(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    session029: dict[str, object],
) -> dict[str, object]:
    """Correct the Session 029 prefix interpretation for two target pairs."""

    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    memories = {
        "left": _MemoryReader(left_data),
        "right": _MemoryReader(right_data),
    }
    bsr = {
        "left": Counter(
            int(row["target_file_offset"])
            for row in _scan_direct_bsr_calls(left_data)
        ),
        "right": Counter(
            int(row["target_file_offset"])
            for row in _scan_direct_bsr_calls(right_data)
        ),
    }
    rows = []
    for prior in session029["handoff_pairs"]:
        left = _disc_target_profile(
            left_reader,
            int(prior["left"]["raw_target_file_offset"]),
            memory=memories["left"],
            direct_bsr_targets=bsr["left"],
        )
        right = _disc_target_profile(
            right_reader,
            int(prior["right"]["raw_target_file_offset"]),
            memory=memories["right"],
            direct_bsr_targets=bsr["right"],
        )
        pool_start_delta = (
            int(right["pool"]["pool_start_file_offset"])
            - int(left["pool"]["pool_start_file_offset"])
        )
        pool_end_delta = (
            int(right["pool"]["pool_end_file_offset"])
            - int(left["pool"]["pool_end_file_offset"])
        )
        raw_target_delta = (
            int(right["registered_target_file_offset"])
            - int(left["registered_target_file_offset"])
        )
        gates = {
            "registered_target_is_literal_pool_member_both": bool(
                left["classification"][
                    "registered_target_is_literal_pool_member"
                ]
                and right["classification"][
                    "registered_target_is_literal_pool_member"
                ]
            ),
            "pool_word_count_equal": (
                left["pool"]["pool_word_count"]
                == right["pool"]["pool_word_count"]
            ),
            "pool_relative_role_signature_equal": (
                left["pool_references"][
                    "relative_role_signature_sha256"
                ]
                == right["pool_references"][
                    "relative_role_signature_sha256"
                ]
            ),
            "pool_start_end_delta_equal": (
                pool_start_delta == pool_end_delta
            ),
            "right_target_index_is_one_lower": (
                int(right["pool"]["registered_target_word_index"])
                == int(left["pool"]["registered_target_word_index"])
                - 1
            ),
            "pool_end_successor_shape_equal": (
                left["pool_end_successor"][
                    "normalized_shape_sha256"
                ]
                == right["pool_end_successor"][
                    "normalized_shape_sha256"
                ]
            ),
            "pool_end_successor_code_gate_both": bool(
                left["classification"][
                    "pool_end_is_strict_code_successor"
                ]
                and right["classification"][
                    "pool_end_is_strict_code_successor"
                ]
            ),
            "pool_end_has_no_static_runtime_reference_both": not (
                left["classification"][
                    "pool_end_has_static_runtime_reference"
                ]
                or right["classification"][
                    "pool_end_has_static_runtime_reference"
                ]
            ),
        }
        gates["bilateral_literal_pool_gate_passed"] = all(
            gates[key]
            for key in (
                "registered_target_is_literal_pool_member_both",
                "pool_word_count_equal",
                "pool_relative_role_signature_equal",
                "pool_start_end_delta_equal",
            )
        )
        gates["pool_end_successor_adjacency_gate_passed"] = all(
            gates[key]
            for key in (
                "pool_end_successor_shape_equal",
                "pool_end_successor_code_gate_both",
            )
        )
        gates["boundary_correction_gate_passed"] = all(
            gates[key]
            for key in (
                "bilateral_literal_pool_gate_passed",
                "right_target_index_is_one_lower",
                "pool_end_successor_adjacency_gate_passed",
                "pool_end_has_no_static_runtime_reference_both",
            )
        )
        rows.append(
            {
                "flow_ordinal": int(prior["flow_ordinal"]),
                "left": left,
                "right": right,
                "pool_start_file_offset_delta": pool_start_delta,
                "pool_end_file_offset_delta": pool_end_delta,
                "raw_target_file_offset_delta": raw_target_delta,
                "structural_vs_raw_relocation_skew": (
                    pool_start_delta - raw_target_delta
                ),
                "gates": gates,
                "pool_end_runtime_callee_established": False,
                "runtime_equivalence_asserted": False,
            }
        )

    pool_deltas = {
        int(row["pool_start_file_offset_delta"]) for row in rows
    }
    raw_deltas = {
        int(row["raw_target_file_offset_delta"]) for row in rows
    }
    skews = {
        int(row["structural_vs_raw_relocation_skew"])
        for row in rows
    }
    all_pool_references = bool(
        len(rows) == 2
        and all(
            side["pool_references"][
                "all_pool_words_have_one_pc_relative_referrer"
            ]
            and side["pool_references"][
                "all_referrers_precede_pool"
            ]
            for row in rows
            for side in (row["left"], row["right"])
        )
    )
    successor_family = bool(
        len(rows) == 2
        and all(
            row["gates"]["pool_end_successor_code_gate_both"]
            and row["gates"]["pool_end_successor_shape_equal"]
            for row in rows
        )
    )
    registered_targets_are_indirect_control = bool(
        len(rows) == 2
        and all(
            side["registered_target_runtime_reference_census"][
                "exact_word_occurrence_count"
            ]
            == 1
            and side["registered_target_runtime_reference_census"][
                "pc_relative_referrer_count"
            ]
            == 1
            and side["registered_target_runtime_reference_census"][
                "use_classification_counts"
            ]
            == {"INDIRECT_CONTROL_TARGET": 1}
            for row in rows
            for side in (row["left"], row["right"])
        )
    )
    return {
        "schema": "phoenix-mmi.literal-pool-boundary-comparison/v1",
        "analysis_mode": (
            "read-only-static-registered-target-literal-pool-boundary"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "target_pairs": rows,
        "classification": {
            "registered_target_pair_count": len(rows),
            "bilateral_literal_pool_pair_count": sum(
                row["gates"][
                    "bilateral_literal_pool_gate_passed"
                ]
                for row in rows
            ),
            "pool_word_counts": [
                int(row["left"]["pool"]["pool_word_count"])
                for row in rows
            ],
            "pool_entry_count_per_release": sum(
                int(row["left"]["pool"]["pool_word_count"])
                for row in rows
            ),
            "all_pool_entries_have_one_preceding_pc_referrer": (
                all_pool_references
            ),
            "all_registered_targets_are_single_indirect_control_targets": (
                registered_targets_are_indirect_control
            ),
            "common_structural_pool_relocation_delta": (
                next(iter(pool_deltas))
                if len(pool_deltas) == 1
                else None
            ),
            "common_raw_target_relocation_delta": (
                next(iter(raw_deltas))
                if len(raw_deltas) == 1
                else None
            ),
            "common_structural_vs_raw_relocation_skew": (
                next(iter(skews)) if len(skews) == 1 else None
            ),
            "right_target_index_shift": (
                -1
                if all(
                    row["gates"][
                        "right_target_index_is_one_lower"
                    ]
                    for row in rows
                )
                else None
            ),
            "session029_prefix_interpretation": (
                "CORRECTED_TO_LITERAL_POOL_SUFFIX"
                if all_pool_references
                else "NOT_ESTABLISHED"
            ),
            "pool_end_successor_code_family": (
                "CONFIRMED_BILATERAL_STRUCTURAL_ADJACENCY"
                if successor_family
                else "NOT_ESTABLISHED"
            ),
            "pool_end_runtime_callee": "NOT_ESTABLISHED",
            "static_handoff_registration_path": (
                "OPEN_ACTUAL_TARGET_UNRESOLVED"
            ),
            "entry_r5_disproof_scope": (
                "POOL_END_SUCCESSOR_ONLY_NOT_RUNTIME_CALLEE"
            ),
            "local_loader_or_section_metadata_hypothesis": (
                "DISPROVED_FOR_REGISTERED_WORD_RUNS"
                if all_pool_references
                else "OPEN"
            ),
            "universal_runtime_to_file_mapping": "NOT_ESTABLISHED",
            "returned_object_type": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
        },
        "limits": {
            "source_session": 29,
            "registered_target_pairs_only": True,
            "maximum_pool_words_each_direction": (
                _MAX_POOL_WORDS_EACH_DIRECTION
            ),
            "global_exact_runtime_word_census_per_boundary": True,
            "global_direct_bsr_census_per_boundary": True,
            "computed_or_loader_created_references_tested": False,
            "arbitrary_code_entry_search_performed": False,
            "runtime_execution_observed": False,
            "physical_runtime_mapping_recovered": False,
        },
        "interpretation": (
            "Each Session 029 target lies inside a complete PC-relative "
            "literal pool, not at the beginning of a function prefix. The "
            "two bilateral pools contain four and six words; every word has "
            "exactly one preceding PC-relative referrer, and relative "
            "referrer/use-role signatures are equal across releases. The "
            "registered target moves one pool index earlier in CD3, while "
            "pool boundaries retain a separate common structural relocation "
            "delta. Fully decoded shape-equal code begins at each pool end, "
            "but no exact runtime-word reference or direct BSR targets those "
            "successors. Therefore Session 029 correctly found adjacent "
            "code but did not establish the runtime callee. Its entry-r5 "
            "disproof applies only to those adjacent successors; the actual "
            "handoff target, registration path and universal runtime mapping "
            "remain open."
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


def update_operational_graph_v23(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v23"
    removed_nodes = {"prefix-corrected-static-callees"}
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] not in removed_nodes
    ]
    graph["nodes"].extend(
        [
            {
                "id": "handoff-target-literal-pools",
                "label": "Registered handoff target literal pools",
                "status": "CONFIRMED_BILATERAL_STRUCTURAL_FAMILY",
                "pool_pair_count": comparison["classification"][
                    "bilateral_literal_pool_pair_count"
                ],
                "evidence": ["S030-01", "S030-02", "RQ-096"],
            },
            {
                "id": "literal-pool-successor-code-families",
                "label": "Literal-pool-end successor code families",
                "status": "CONFIRMED_BILATERAL_STRUCTURAL_ADJACENCY",
                "runtime_callee_established": False,
                "evidence": ["S030-03", "RQ-097"],
            },
        ]
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if edge["source"] not in removed_nodes
        and edge["target"] not in removed_nodes
    ]
    graph["edges"].extend(
        [
            {
                "source": "producer-return-use-family",
                "target": "handoff-target-literal-pools",
                "relation": (
                    "registered raw target maps inside a fully referenced "
                    "PC-relative literal pool under the tested base model"
                ),
                "status": "CONFIRMED_STRUCTURAL_MAPPING_CONTRADICTION",
            },
            {
                "source": "handoff-target-literal-pools",
                "target": "literal-pool-successor-code-families",
                "relation": (
                    "fully decoded bilateral code begins at each pool end"
                ),
                "status": "CONFIRMED_STRUCTURAL_ADJACENCY",
            },
            {
                "source": "literal-pool-successor-code-families",
                "target": "runtime-linkage-owner-ingress",
                "relation": (
                    "no runtime target edge is established; actual handoff "
                    "callee and registration path remain unresolved"
                ),
                "status": "OPEN",
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


def correlate_literal_pool_boundaries(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.literal-pool-boundary-correlation/v1",
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
        "operational_graph": update_operational_graph_v23(
            prior_correlation["operational_graph"],
            comparison,
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_literal_pool_boundary_report(
    report: dict[str, object],
) -> dict[str, object]:
    """Return a detached already-publication-safe report."""

    return copy.deepcopy(report)

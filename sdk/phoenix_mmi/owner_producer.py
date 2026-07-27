"""Producer-first owner-caller candidate analysis for Session 025.

The analyzer decodes only prologue-backed owner windows already admitted by
the Session 021 pointer-zero call census and only shapes present in both
principal images.  It promotes an indirect-call candidate when its memory
target and complete ``r4``/``r6`` producer expressions agree across releases.
No unresolved target is linked to a selected owner entry.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import re

from .accessor_dispatch import _literal_jsr_calls
from .binary import BinaryReader
from .continuation_contract import _trace_call_argument
from .linkage_owner import (
    _MemoryReader,
    _active_pointer_zero_targets,
    _owner_summary,
)
from .object_dispatch import (
    _canonical_expression,
    _collect_load_offsets,
    _destination_register,
    _resolve_static_expression,
    _trace_expression,
)
from .optical_callgraph import _decode_window
from .owner_provenance import _expression_roots


_CALL_REGISTER = re.compile(r"@r(\d+)$")
_OWNER_FORWARD_BYTES = 0x180
_UNAVAILABLE_ROOTS = {
    "CALLER_SAVED_CLOBBER",
    "NO_DEFINITION",
    "DEPTH_LIMIT",
    "CYCLE",
    "UNSUPPORTED_WRITE",
    "UNKNOWN",
}


def _roots_available(roots: list[str]) -> bool:
    return bool(roots) and not bool(set(roots) & _UNAVAILABLE_ROOTS)


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


def _argument_definition_profile(
    instructions: list[object],
    call_index: int,
    register: int,
) -> dict[str, object]:
    """Locate an explicit argument definition after the last prior call."""

    call = instructions[call_index]
    delay_slot = (
        instructions[call_index + 1]
        if call.delayed and call_index + 1 < len(instructions)
        else None
    )
    prefix = list(instructions[:call_index])
    if delay_slot is not None:
        prefix.append(delay_slot)
    last_prior_call = next(
        (
            int(instruction.offset)
            for instruction in reversed(instructions[:call_index])
            if instruction.flow in {"call", "indirect-call"}
        ),
        None,
    )
    definition = next(
        (
            int(instruction.offset)
            for instruction in reversed(prefix)
            if _destination_register(instruction) == register
        ),
        None,
    )
    lower_bound = (
        last_prior_call
        if last_prior_call is not None
        else int(instructions[0].offset) - 2
    )
    return {
        "definition_file_offset": definition,
        "last_preceding_call_file_offset": last_prior_call,
        "definition_after_last_preceding_call": (
            definition is not None and definition > lower_bound
        ),
        "definition_in_current_call_delay_slot": bool(
            delay_slot is not None
            and definition == int(delay_slot.offset)
        ),
    }


def _registered_owner_windows(
    data: bytes,
) -> tuple[dict[str, object], dict[str, list[dict[str, object]]]]:
    """Reproduce the Session 021 accepted owner registry with instances."""

    calls = _literal_jsr_calls(data, image_size=len(data))
    active_targets, _ = _active_pointer_zero_targets(data, calls)
    selected_calls = [
        row
        for row in calls
        if int(row["target_file_offset"]) in active_targets
    ]
    reader = _MemoryReader(data)
    owners: dict[int, dict[str, object]] = {}
    for row in selected_calls:
        owner = _owner_summary(reader, int(row["load_file_offset"]))
        if owner["prologue_code_gate_passed"]:
            owners[int(owner["owner_start_file_offset"])] = owner
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for owner in owners.values():
        grouped[str(owner["normalized_shape_sha256"])].append(owner)
    return (
        {
            "active_pointer_zero_target_count": len(active_targets),
            "active_pointer_zero_call_count": len(selected_calls),
            "prologue_code_gated_owner_count": len(owners),
            "exact_prologue_owner_shape_count": len(grouped),
            "function_boundaries_asserted": False,
            "global_call_census_is_syntactic": True,
        },
        dict(grouped),
    )


def _verify_session021_registry(
    recomputed: dict[str, object],
    prior: dict[str, object],
) -> dict[str, object]:
    fields = [
        "active_pointer_zero_target_count",
        "active_pointer_zero_call_count",
        "prologue_code_gated_owner_count",
        "exact_prologue_owner_shape_count",
    ]
    rows = [
        {
            "field": field,
            "recomputed": int(recomputed[field]),
            "session021": int(prior[field]),
            "equal": int(recomputed[field]) == int(prior[field]),
        }
        for field in fields
    ]
    return {
        "fields": rows,
        "all_registered_counts_equal": all(row["equal"] for row in rows),
    }


def _indirect_call_contract(
    reader: BinaryReader,
    instructions: list[object],
    call_index: int,
    *,
    owner: dict[str, object],
) -> dict[str, object]:
    call = instructions[call_index]
    match = _CALL_REGISTER.fullmatch(call.operands)
    if call.mnemonic != "jsr" or match is None:
        raise ValueError("selected instruction is not JSR @Rn")
    target_register = int(match.group(1))
    target_expression = _trace_expression(
        instructions,
        call_index,
        target_register,
        image_size=reader.size,
    )
    arguments = {}
    for register in (4, 6):
        expression = _trace_call_argument(
            instructions,
            call_index,
            register,
            image_size=reader.size,
        )
        public = _public_expression(reader, expression)
        public.update(
            _argument_definition_profile(
                instructions, call_index, register
            )
        )
        public["available_at_call"] = _roots_available(
            public["root_classes"]
        )
        arguments[f"r{register}"] = public
    target = _public_expression(reader, target_expression)
    target_memory_loaded_dynamic = bool(
        "LOAD" in target["root_classes"]
        and target["resolution_status"] == "DYNAMIC_OR_UNSUPPORTED"
    )
    explicit_arguments = all(
        arguments[register]["definition_after_last_preceding_call"]
        for register in ("r4", "r6")
    )
    available_arguments = all(
        arguments[register]["available_at_call"]
        for register in ("r4", "r6")
    )
    owner_start = int(owner["owner_start_file_offset"])
    return {
        "owner_start_file_offset": owner_start,
        "owner_shape_sha256": owner["normalized_shape_sha256"],
        "call_site_file_offset": int(call.offset),
        "call_relative_instruction_index": call_index,
        "call_relative_byte_offset": int(call.offset) - owner_start,
        "target_register": f"r{target_register}",
        "target_expression": target,
        "arguments": arguments,
        "gates": {
            "memory_loaded_dynamic_target": target_memory_loaded_dynamic,
            "explicit_r4_r6_after_last_preceding_call": (
                explicit_arguments
            ),
            "available_r4_r6_provenance": available_arguments,
            "local_producer_first_gate_passed": (
                target_memory_loaded_dynamic
                and explicit_arguments
                and available_arguments
            ),
        },
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }


def _scan_shared_owner_instances(
    reader: BinaryReader,
    groups: dict[str, list[dict[str, object]]],
    shared_shapes: set[str],
) -> dict[str, object]:
    stage_counts = Counter()
    explicit_groups: dict[
        tuple[str, int], list[dict[str, object]]
    ] = defaultdict(list)
    available_groups: dict[
        tuple[str, int], list[dict[str, object]]
    ] = defaultdict(list)
    for shape in sorted(shared_shapes):
        for owner in groups[shape]:
            start = int(owner["owner_start_file_offset"])
            instructions = _decode_window(
                reader, start, maximum_bytes=_OWNER_FORWARD_BYTES
            )
            for index, instruction in enumerate(instructions):
                if (
                    instruction.mnemonic != "jsr"
                    or instruction.flow != "indirect-call"
                ):
                    continue
                stage_counts["decoded_indirect_jsr_count"] += 1
                contract = _indirect_call_contract(
                    reader, instructions, index, owner=owner
                )
                gates = contract["gates"]
                if gates["memory_loaded_dynamic_target"]:
                    stage_counts[
                        "memory_loaded_dynamic_target_count"
                    ] += 1
                else:
                    continue
                if gates["explicit_r4_r6_after_last_preceding_call"]:
                    stage_counts[
                        "explicit_r4_r6_after_last_call_count"
                    ] += 1
                    key = (
                        shape,
                        int(contract["call_relative_instruction_index"]),
                    )
                    explicit_groups[key].append(contract)
                else:
                    continue
                if gates["available_r4_r6_provenance"]:
                    stage_counts[
                        "available_producer_first_contract_count"
                    ] += 1
                    available_groups[key].append(contract)
    return {
        "shared_owner_instance_count": sum(
            len(groups[shape]) for shape in shared_shapes
        ),
        "stage_counts": {
            key: int(stage_counts.get(key, 0))
            for key in (
                "decoded_indirect_jsr_count",
                "memory_loaded_dynamic_target_count",
                "explicit_r4_r6_after_last_call_count",
                "available_producer_first_contract_count",
            )
        },
        "explicit_groups": dict(explicit_groups),
        "available_groups": dict(available_groups),
    }


def _contract_path(
    contract: dict[str, object],
) -> tuple[str, str, str]:
    return (
        str(contract["target_expression"]["canonical"]),
        str(contract["arguments"]["r4"]["canonical"]),
        str(contract["arguments"]["r6"]["canonical"]),
    )


def _side_family_summary(
    explicit: list[dict[str, object]],
    available: list[dict[str, object]],
) -> dict[str, object]:
    paths = sorted({_contract_path(row) for row in available})
    return {
        "explicit_contract_count": len(explicit),
        "available_contract_count": len(available),
        "available_path_consensus_count": len(paths),
        "available_paths": [
            {"target": path[0], "r4": path[1], "r6": path[2]}
            for path in paths
        ],
        "contracts": copy.deepcopy(available),
    }


def _correlate_candidate_families(
    left_explicit: dict[tuple[str, int], list[dict[str, object]]],
    right_explicit: dict[tuple[str, int], list[dict[str, object]]],
    left_available: dict[tuple[str, int], list[dict[str, object]]],
    right_available: dict[tuple[str, int], list[dict[str, object]]],
) -> list[dict[str, object]]:
    keys = sorted(set(left_explicit) | set(right_explicit))
    rows = []
    for ordinal, key in enumerate(keys, start=1):
        left = _side_family_summary(
            left_explicit.get(key, []), left_available.get(key, [])
        )
        right = _side_family_summary(
            right_explicit.get(key, []), right_available.get(key, [])
        )
        left_paths = {
            (row["target"], row["r4"], row["r6"])
            for row in left["available_paths"]
        }
        right_paths = {
            (row["target"], row["r4"], row["r6"])
            for row in right["available_paths"]
        }
        bilateral_explicit = bool(
            left["explicit_contract_count"]
            and right["explicit_contract_count"]
        )
        bilateral_available = bool(
            left["available_contract_count"]
            and right["available_contract_count"]
        )
        equal_single_path = bool(
            len(left_paths) == 1 and left_paths == right_paths
        )
        promoted = bilateral_available and equal_single_path
        if promoted:
            classification = (
                "CONFIRMED_BILATERAL_ARGUMENT_COMPATIBLE_CANDIDATE"
            )
        elif bilateral_explicit and not bilateral_available:
            classification = "REJECTED_UNAVAILABLE_ARGUMENT_PROVENANCE"
        elif bilateral_explicit:
            classification = "REJECTED_NON_UNIQUE_OR_ASYMMETRIC_PATH"
        else:
            classification = "REJECTED_ONE_SIDED_EXPLICIT_CONTEXT"
        consensus = None
        if promoted:
            target, r4, r6 = next(iter(left_paths))
            first = left["contracts"][0]
            consensus = {
                "target": target,
                "r4": r4,
                "r6": r6,
                "target_load_path": first["target_expression"][
                    "load_path"
                ],
                "r4_load_path": first["arguments"]["r4"]["load_path"],
                "r6_load_path": first["arguments"]["r6"]["load_path"],
            }
        rows.append(
            {
                "candidate_family_ordinal": ordinal,
                "owner_shape_sha256": key[0],
                "call_relative_instruction_index": key[1],
                "left": left,
                "right": right,
                "bilateral_explicit_context": bilateral_explicit,
                "bilateral_available_context": bilateral_available,
                "equal_single_canonical_path": equal_single_path,
                "argument_compatible_candidate_promoted": promoted,
                "consensus_contract": consensus,
                "classification": classification,
                "selected_owner_target_link_established": False,
                "runtime_equivalence_asserted": False,
            }
        )
    return rows


def analyze_owner_producer_candidates(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    session021: dict[str, object],
    session024: dict[str, object],
) -> dict[str, object]:
    """Build the bounded producer-first candidate set."""

    required = {
        tuple(row["required_entry_arguments"])
        for row in session024["owner_entry_contracts"]
    }
    if required != {("r4", "r6")}:
        raise ValueError("Session 024 does not register one r4/r6 contract")

    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    left_census, left_groups = _registered_owner_windows(left_data)
    right_census, right_groups = _registered_owner_windows(right_data)
    shared_shapes = set(left_groups) & set(right_groups)
    prior_census = session021["global_owner_census"]
    registry_checks = {
        "left": _verify_session021_registry(
            left_census, prior_census["left"]
        ),
        "right": _verify_session021_registry(
            right_census, prior_census["right"]
        ),
    }
    registry_checks["shared_shape_count_equal"] = (
        len(shared_shapes)
        == int(prior_census["shared_exact_prologue_owner_shape_count"])
    )
    registry_checks["left_shared_instance_count_equal"] = (
        sum(len(left_groups[shape]) for shape in shared_shapes)
        == int(prior_census["left_owner_instances_in_shared_shapes"])
    )
    registry_checks["right_shared_instance_count_equal"] = (
        sum(len(right_groups[shape]) for shape in shared_shapes)
        == int(prior_census["right_owner_instances_in_shared_shapes"])
    )
    registry_equal = bool(
        registry_checks["left"]["all_registered_counts_equal"]
        and registry_checks["right"]["all_registered_counts_equal"]
        and registry_checks["shared_shape_count_equal"]
        and registry_checks["left_shared_instance_count_equal"]
        and registry_checks["right_shared_instance_count_equal"]
    )
    if not registry_equal:
        raise ValueError("Session 021 owner registry did not reproduce")

    scans = {
        "left": _scan_shared_owner_instances(
            left_reader, left_groups, shared_shapes
        ),
        "right": _scan_shared_owner_instances(
            right_reader, right_groups, shared_shapes
        ),
    }
    families = _correlate_candidate_families(
        scans["left"]["explicit_groups"],
        scans["right"]["explicit_groups"],
        scans["left"]["available_groups"],
        scans["right"]["available_groups"],
    )
    promoted = [
        row
        for row in families
        if row["argument_compatible_candidate_promoted"]
    ]
    rejected_unavailable = sum(
        row["classification"]
        == "REJECTED_UNAVAILABLE_ARGUMENT_PROVENANCE"
        for row in families
    )
    explicit_bilateral = sum(
        row["bilateral_explicit_context"] for row in families
    )
    target_fields = Counter(
        int(row["consensus_contract"]["target_load_path"][0][
            "displacement"
        ])
        for row in promoted
    )
    r6_contracts = Counter(
        str(row["consensus_contract"]["r6"]) for row in promoted
    )

    public_scans = {}
    for side, scan in scans.items():
        public_scans[side] = {
            "shared_owner_instance_count": scan[
                "shared_owner_instance_count"
            ],
            "stage_counts": scan["stage_counts"],
        }
    return {
        "schema": "phoenix-mmi.owner-producer-candidate-comparison/v1",
        "analysis_mode": (
            "read-only-static-registered-owner-producer-first-census"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "required_owner_entry_arguments": ["r4", "r6"],
        "registered_owner_registry": {
            "left": left_census,
            "right": right_census,
            "shared_exact_prologue_owner_shape_count": len(shared_shapes),
            "registry_reproduction": registry_checks,
        },
        "producer_first_census": public_scans,
        "candidate_families": families,
        "classification": {
            "session021_owner_registry_reproduced": "CONFIRMED",
            "shared_exact_prologue_owner_shape_count": len(
                shared_shapes
            ),
            "explicit_bilateral_candidate_family_count": explicit_bilateral,
            "rejected_unavailable_argument_family_count": (
                rejected_unavailable
            ),
            "bilateral_argument_compatible_candidate_family_count": len(
                promoted
            ),
            "candidate_target_field_displacement_counts": {
                str(key): value for key, value in sorted(target_fields.items())
            },
            "candidate_r6_contract_counts": dict(sorted(r6_contracts.items())),
            "owner_entry_argument_compatible_dispatches": (
                "CONFIRMED_FOUR_STRUCTURAL_CANDIDATE_FAMILIES"
                if len(promoted) == 4
                else "PARTIAL"
            ),
            "selected_owner_target_link": "NOT_ESTABLISHED",
            "unique_bilateral_owner_entry_caller": "NOT_ESTABLISHED",
            "owner_entry_argument_producer": (
                "PARTIAL_ARGUMENT_COMPATIBLE_CANDIDATES_ONLY"
            ),
            "state_creator_or_writer": "OPEN",
            "semantic_owner_identity": "OPEN",
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
        },
        "limits": {
            "candidate_source_session": 21,
            "owner_forward_bytes": _OWNER_FORWARD_BYTES,
            "arbitrary_raw_image_code_scan_performed": False,
            "only_shared_exact_prologue_shapes_decoded": True,
            "whole_image_executable_map_available": False,
            "function_boundaries_asserted": False,
            "path_dominance_asserted": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "The Session 021 owner registry reproduces exactly. Within its "
            "29 cross-version exact prologue shapes, twelve bilateral "
            "memory-loaded call positions explicitly rebuild r4 and r6 "
            "after the last preceding call. Eight retain unavailable roots "
            "and are rejected. Four have one equal target/r4/r6 expression "
            "in both releases: two pass r6 as zero and two pass entry r7, "
            "with target fields 28, 36 and 44. They are structural "
            "argument-compatible candidates only; every target remains "
            "memory-loaded, and no edge to a selected owner entry, unique "
            "caller, state creator or writer is established."
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


def update_operational_graph_v18(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v18"
    graph["nodes"] = [
        node
        for node in graph["nodes"]
        if node["id"] != "owner-entry-producer-first-candidates"
    ]
    graph["nodes"].append(
        {
            "id": "owner-entry-producer-first-candidates",
            "label": "Producer-first indirect caller candidates",
            "status": "CONFIRMED_STRUCTURAL_CANDIDATES",
            "candidate_family_count": comparison["classification"][
                "bilateral_argument_compatible_candidate_family_count"
            ],
            "selected_owner_target_link": comparison["classification"][
                "selected_owner_target_link"
            ],
            "owner_entry_producer": comparison["classification"][
                "owner_entry_argument_producer"
            ],
            "evidence": ["S025-01", "S025-02", "RQ-074", "RQ-075"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "owner-entry-producer-first-candidates"
            and edge["target"] == "runtime-linkage-owner-ingress"
        )
    ]
    graph["edges"].append(
        {
            "source": "owner-entry-producer-first-candidates",
            "target": "runtime-linkage-owner-ingress",
            "relation": (
                "four families supply bilateral r4/r6 contracts but their "
                "memory-loaded targets are not linked to selected owners"
            ),
            "status": "OPEN_TARGET_LINK",
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


def correlate_owner_producer_candidates(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.owner-producer-candidate-correlation/v1",
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
        "operational_graph": update_operational_graph_v18(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_owner_producer_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

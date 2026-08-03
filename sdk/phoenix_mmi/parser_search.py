"""Global, role-sensitive FLDB parser candidate search.

The search treats numeric matches only as seeds.  Promotion requires structural
roles: a 36-byte loop step, reads from one plausible header base, endian work,
cross-version stability and independently established buffer provenance.  The
module never returns instruction bytes, absolute runtime addresses or strings.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import hashlib
import re

from .binary import BinaryReader
from .superh import SHInstruction, decode_instruction_extended


RECORD_SIZE = 36
HEADER_FIELD_OFFSETS = {0, 4, 8, 12, 16, 20}
_ADDRESS = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)


def _word(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _normalized_shape(instructions: list[SHInstruction]) -> str:
    rows = [
        "|".join(
            (
                item.mnemonic,
                _ADDRESS.sub("<address>", item.operands),
                item.flow,
                "delayed" if item.delayed else "plain",
            )
        )
        for item in instructions
    ]
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def _decode_range(
    reader: BinaryReader, start: int, end: int
) -> list[SHInstruction]:
    start = max(0, start) & ~1
    end = min(reader.size, end) & ~1
    return [decode_instruction_extended(reader, offset) for offset in range(start, end, 2)]


def _memory_access(word: int) -> tuple[str, int, int] | None:
    """Return access role, base register and byte displacement."""

    n = (word >> 8) & 0xF
    m = (word >> 4) & 0xF
    family = word & 0xF00F
    if word & 0xF000 == 0x5000:
        return "load", m, (word & 0xF) * 4
    if family in {0x6000, 0x6001, 0x6002, 0x6004, 0x6005, 0x6006}:
        return "load", m, 0
    if word & 0xF000 == 0x1000:
        return "store", n, (word & 0xF) * 4
    if family in {0x2000, 0x2001, 0x2002, 0x2004, 0x2005, 0x2006}:
        return "store", n, 0
    return None


def _access_summary(data: bytes, start: int, end: int) -> dict[str, object]:
    reads: dict[int, set[int]] = defaultdict(set)
    writes: dict[int, set[int]] = defaultdict(set)
    for offset in range(start & ~1, end & ~1, 2):
        access = _memory_access(_word(data, offset))
        if access is None:
            continue
        role, base, displacement = access
        (reads if role == "load" else writes)[base].add(displacement)

    def best(source: dict[int, set[int]]) -> tuple[int | None, list[int]]:
        candidates = [
            (register, sorted(offsets & HEADER_FIELD_OFFSETS))
            for register, offsets in source.items()
        ]
        candidates.sort(key=lambda item: (-len(item[1]), item[0]))
        return candidates[0] if candidates else (None, [])

    read_base, read_offsets = best(reads)
    write_base, write_offsets = best(writes)
    return {
        "best_header_read_base_register": (
            f"r{read_base}" if read_base is not None else None
        ),
        "best_header_read_offsets": read_offsets,
        "best_header_write_base_register": (
            f"r{write_base}" if write_base is not None else None
        ),
        "best_header_write_offsets": write_offsets,
        "absolute_pointer_values_included": False,
    }


def _context_offsets(
    contract: dict[str, object], side: str
) -> dict[str, list[int]]:
    navigation = set()
    optical = set()
    route = set()
    for pair in contract.get("callsite_window_pairs", []):
        navigation.add(int(pair[f"{side}_center"]))
        for call in pair.get("resolved_call_pairs", []):
            navigation.add(int(call[f"{side}_call_site_offset"]))
            navigation.add(int(call[f"{side}_target_file_offset"]))
    for pair in contract.get("neighborhood_pairs", []):
        target = {
            "optical-service": optical,
            "route-data": route,
            "navigation-data": navigation,
        }.get(str(pair.get("category")))
        if target is not None:
            target.add(int(pair[f"{side}_anchor_offset"]))
    return {
        "navigation": sorted(navigation),
        "optical-service": sorted(optical),
        "route-data": sorted(route),
    }


def _nearest_context(
    offset: int, contexts: dict[str, list[int]], *, threshold: int = 0x10000
) -> dict[str, object]:
    rows = [
        (abs(value - offset), value - offset, domain)
        for domain, values in contexts.items()
        for value in values
    ]
    if not rows:
        return {"status": "NO_REGISTERED_CONTEXT"}
    distance, signed, domain = min(rows)
    return {
        "status": "PROXIMITY_ONLY" if distance <= threshold else "OUTSIDE_THRESHOLD",
        "domain": domain,
        "signed_distance": signed,
        "threshold": threshold,
        "buffer_provenance_established": False,
    }


def _endian_count(data: bytes, start: int, end: int) -> int:
    return sum(
        _word(data, offset) & 0xF00F in {0x6008, 0x6009, 0x200D}
        for offset in range(start & ~1, end & ~1, 2)
    )


def _literal_counts(instructions: list[SHInstruction]) -> dict[str, int]:
    values = Counter(
        int(item.literal_value)
        for item in instructions
        if item.literal_value is not None
    )
    return {
        "directory_offset_0x220": values[0x220],
        "logical_sector_size_2048": values[2048],
    }


def _loop_candidate(
    reader: BinaryReader,
    data: bytes,
    seed: int,
    branch: SHInstruction,
    contexts: dict[str, list[int]],
) -> dict[str, object] | None:
    if branch.target is None or not (0 <= branch.target < branch.offset):
        return None
    loop_start = int(branch.target)
    loop_end = seed + 2
    if loop_end - loop_start > 0x400:
        return None
    window_start = max(0, loop_start - 0x80) & ~1
    window_end = min(reader.size, loop_end + 0x80) & ~1
    loop_instructions = _decode_range(reader, loop_start, loop_end)
    window_instructions = _decode_range(reader, window_start, window_end)
    stepped_register = (_word(data, seed) >> 8) & 0xF

    stepped_loads = 0
    stepped_stores = 0
    for offset in range(loop_start, loop_end, 2):
        access = _memory_access(_word(data, offset))
        if access is None or access[1] != stepped_register:
            continue
        if access[0] == "load":
            stepped_loads += 1
        else:
            stepped_stores += 1

    if stepped_loads and stepped_stores:
        role = "READ_WRITE_36_BYTE_RECORD_LOOP"
    elif stepped_loads:
        role = "READING_36_BYTE_RECORD_LOOP"
    elif stepped_stores:
        role = "WRITE_ONLY_36_BYTE_RECORD_LOOP"
    else:
        role = "ARITHMETIC_36_BYTE_LOOP_STEP"

    accesses = _access_summary(data, window_start, window_end)
    endian = _endian_count(data, window_start, window_end)
    literals = _literal_counts(window_instructions)
    context = _nearest_context(seed, contexts)
    known = sum(item.mnemonic != "unknown" for item in loop_instructions)
    header_reads = len(accesses["best_header_read_offsets"])
    independent_signals = sum(
        (
            stepped_loads > 0,
            header_reads >= 3,
            endian > 0,
            literals["directory_offset_0x220"] > 0,
            literals["logical_sector_size_2048"] > 0,
            context.get("status") == "PROXIMITY_ONLY",
        )
    )
    if role == "WRITE_ONLY_36_BYTE_RECORD_LOOP" and stepped_stores >= 3:
        classification = "PROBABLE_FIXED_RECORD_ARRAY_INITIALIZER"
    elif independent_signals >= 3:
        classification = "REQUIRES_TARGETED_BUFFER_DATAFLOW"
    else:
        classification = "GENERIC_36_BYTE_LOOP_NOT_PROMOTED"

    raw = reader.read(loop_start, loop_end - loop_start)
    return {
        "seed_offset": seed,
        "loop_start": loop_start,
        "loop_end": loop_end,
        "loop_length": loop_end - loop_start,
        "stepped_register": f"r{stepped_register}",
        "role": role,
        "stepped_register_load_count": stepped_loads,
        "stepped_register_store_count": stepped_stores,
        "header_access": accesses,
        "endian_instruction_count": endian,
        "literal_signals": literals,
        "call_count": sum(
            item.flow in {"call", "indirect-call"} for item in window_instructions
        ),
        "known_instruction_ratio": round(known / len(loop_instructions), 6),
        "normalized_loop_shape_sha256": _normalized_shape(loop_instructions),
        "raw_loop_sha256": hashlib.sha256(raw).hexdigest(),
        "nearest_registered_context": context,
        "independent_signal_count_beyond_stride": independent_signals,
        "classification": classification,
        "function_boundary_asserted": False,
        "instruction_bytes_included": False,
    }


def _navigation_adjacent_clusters(
    reader: BinaryReader,
    data: bytes,
    centers: list[int],
) -> list[dict[str, object]]:
    if not centers:
        return []
    start = max(0, min(centers) - 0x2000) & ~1
    end = min(reader.size, max(centers) + 0x2000) & ~1
    seeds = [
        offset
        for offset in range(start, end, 2)
        if _word(data, offset) & 0xF0FF == 0x7024
    ]
    groups: list[list[int]] = []
    for seed in seeds:
        if groups and seed - groups[-1][-1] <= 0x20:
            groups[-1].append(seed)
        else:
            groups.append([seed])

    rows = []
    for group in groups:
        center = group[len(group) // 2]
        window_start = max(0, center - 0xC0) & ~1
        window_end = min(reader.size, center + 0xC0) & ~1
        instructions = _decode_range(reader, window_start, window_end)
        call_delay = 0
        call_argument = 0
        loop_steps = []
        for seed in group:
            previous = decode_instruction_extended(reader, seed - 2)
            is_delay = bool(
                previous.delayed and previous.flow in {"call", "indirect-call"}
            )
            call_delay += int(is_delay)
            register = (_word(data, seed) >> 8) & 0xF
            is_argument = is_delay
            if not is_argument and register in {4, 5}:
                for probe in range(seed + 2, min(seed + 10, window_end), 2):
                    instruction = decode_instruction_extended(reader, probe)
                    if instruction.flow in {"call", "indirect-call"}:
                        is_argument = True
                        break
                    # A direct immediate write to the same argument register ends
                    # the bounded look-ahead. Other register preparation is allowed.
                    probe_word = _word(data, probe)
                    if (
                        probe_word & 0xF000 in {0x7000, 0xE000}
                        and ((probe_word >> 8) & 0xF) == register
                    ):
                        break
            call_argument += int(is_argument)
        for offset in range(window_start, window_end - 2, 2):
            branch = decode_instruction_extended(reader, offset)
            if not (
                branch.delayed
                and branch.target is not None
                and branch.target < branch.offset
            ):
                continue
            delay_word = _word(data, offset + 2)
            if delay_word & 0xF000 == 0x7000:
                immediate = delay_word & 0xFF
                if immediate & 0x80:
                    immediate -= 0x100
                loop_steps.append(immediate)
        accesses = _access_summary(data, window_start, window_end)
        known = sum(item.mnemonic != "unknown" for item in instructions)
        rejected = bool(
            call_argument == len(group)
            and RECORD_SIZE not in loop_steps
            and any(value != RECORD_SIZE for value in loop_steps)
        )
        rows.append(
            {
                "center": center,
                "record_size_add_count": len(group),
                "record_size_call_delay_count": call_delay,
                "record_size_call_argument_count": call_argument,
                "observed_backward_loop_steps": sorted(set(loop_steps)),
                "header_access": accesses,
                "endian_instruction_count": _endian_count(
                    data, window_start, window_end
                ),
                "known_instruction_ratio": round(known / len(instructions), 6),
                "normalized_window_shape_sha256": _normalized_shape(instructions),
                "classification": (
                    "REJECTED_CALL_FIELD_OFFSET_NOT_RECORD_STRIDE"
                    if rejected
                    else "UNRESOLVED_NAVIGATION_ADJACENT_NUMERIC_WINDOW"
                ),
                "function_boundary_asserted": False,
                "instruction_bytes_included": False,
            }
        )
    return rows


def scan_global_fldb_parser_candidates(
    reader: BinaryReader,
    contract: dict[str, object],
    *,
    side: str,
) -> dict[str, object]:
    """Scan one principal image using role-sensitive numeric gates."""

    if side not in {"left", "right"}:
        raise ValueError("side must be 'left' or 'right'")
    data = reader.read(0, reader.size)
    contexts = _context_offsets(contract, side)
    census = Counter()
    candidates = []
    for offset in range(2, len(data) - 1, 2):
        word = _word(data, offset)
        if word & 0xF0FF == 0xE024:
            census["mov_immediate_36"] += 1
        if word & 0xF0FF != 0x7024:
            continue
        census["add_immediate_36"] += 1
        previous = decode_instruction_extended(reader, offset - 2)
        if previous.delayed and previous.flow in {"call", "indirect-call"}:
            census["call_delay_field_candidate"] += 1
        if not (
            previous.delayed
            and previous.flow in {"branch", "conditional"}
            and previous.target is not None
            and previous.target < previous.offset
        ):
            continue
        census["backward_branch_delay_loop_step"] += 1
        candidate = _loop_candidate(reader, data, offset, previous, contexts)
        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(key=lambda item: int(item["seed_offset"]))
    navigation_centers = sorted(
        {
            int(pair[f"{side}_center"])
            for pair in contract.get("callsite_window_pairs", [])
        }
    )
    navigation_clusters = _navigation_adjacent_clusters(
        reader, data, navigation_centers
    )
    return {
        "schema": "phoenix-mmi.global-fldb-parser-search/v1",
        "analysis_mode": "read-only-static-global-role-sensitive",
        "artifact": {
            "sha256": reader.sha256(),
            "size_bytes": reader.size,
            "source_path_included": False,
        },
        "numeric_role_census": dict(sorted(census.items())),
        "record_stride_loop_candidates": candidates,
        "navigation_adjacent_numeric_clusters": navigation_clusters,
        "navigation_reference_centers": navigation_centers,
        "classification": {
            "record_stride_loop_candidate_count": len(candidates),
            "write_only_initializer_candidate_count": sum(
                item["classification"] == "PROBABLE_FIXED_RECORD_ARRAY_INITIALIZER"
                for item in candidates
            ),
            "targeted_dataflow_candidate_count": sum(
                item["classification"] == "REQUIRES_TARGETED_BUFFER_DATAFLOW"
                for item in candidates
            ),
            "parser_status": "NOT_IDENTIFIED_UNDER_MULTI_SIGNAL_GATE",
            "optical_buffer_provenance": "OPEN",
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "instruction_bytes_included": False,
            "absolute_runtime_addresses_included": False,
            "raw_strings_included": False,
            "local_paths_included": False,
            "map_payload_included": False,
        },
    }


def _pair_by_shape(
    left: list[dict[str, object]],
    right: list[dict[str, object]],
    *,
    shape_key: str,
    offset_key: str,
) -> list[dict[str, object]]:
    right_by_shape: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in right:
        right_by_shape[str(item[shape_key])].append(item)
    pairs = []
    for left_item in left:
        matches = right_by_shape[str(left_item[shape_key])]
        if not matches:
            continue
        right_item = matches.pop(0)
        pairs.append(
            {
                "left_offset": left_item[offset_key],
                "right_offset": right_item[offset_key],
                "relocation_delta": int(right_item[offset_key])
                - int(left_item[offset_key]),
                "normalized_shape_sha256": left_item[shape_key],
                "left_classification": left_item["classification"],
                "right_classification": right_item["classification"],
                "classification_equal": left_item["classification"]
                == right_item["classification"],
                "raw_loop_bytes_equal_by_hash": (
                    left_item.get("raw_loop_sha256")
                    == right_item.get("raw_loop_sha256")
                    if "raw_loop_sha256" in left_item
                    else None
                ),
                "instruction_bytes_included": False,
            }
        )
    return pairs


def compare_global_fldb_parser_search(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    """Pair role-sensitive candidates across CD1 and CD3."""

    loop_pairs = _pair_by_shape(
        left["record_stride_loop_candidates"],
        right["record_stride_loop_candidates"],
        shape_key="normalized_loop_shape_sha256",
        offset_key="seed_offset",
    )
    center_deltas = Counter(
        int(right_center) - int(left_center)
        for left_center, right_center in zip(
            left.get("navigation_reference_centers", []),
            right.get("navigation_reference_centers", []),
        )
    )
    navigation_delta = center_deltas.most_common(1)[0][0] if center_deltas else None
    right_clusters = {
        int(item["center"]): item
        for item in right["navigation_adjacent_numeric_clusters"]
    }
    navigation_pairs = []
    if navigation_delta is not None:
        for left_item in left["navigation_adjacent_numeric_clusters"]:
            right_item = right_clusters.get(int(left_item["center"]) + navigation_delta)
            if right_item is None:
                continue
            semantic_signature_equal = all(
                left_item[key] == right_item[key]
                for key in (
                    "record_size_add_count",
                    "record_size_call_delay_count",
                    "record_size_call_argument_count",
                    "observed_backward_loop_steps",
                    "endian_instruction_count",
                    "classification",
                )
            ) and left_item["header_access"] == right_item["header_access"]
            navigation_pairs.append(
                {
                    "left_offset": left_item["center"],
                    "right_offset": right_item["center"],
                    "relocation_delta": navigation_delta,
                    "normalized_shape_equal": (
                        left_item["normalized_window_shape_sha256"]
                        == right_item["normalized_window_shape_sha256"]
                    ),
                    "semantic_signature_equal": semantic_signature_equal,
                    "left_classification": left_item["classification"],
                    "right_classification": right_item["classification"],
                    "classification_equal": left_item["classification"]
                    == right_item["classification"],
                    "instruction_bytes_included": False,
                }
            )
    initializer_pairs = sum(
        pair["left_classification"] == "PROBABLE_FIXED_RECORD_ARRAY_INITIALIZER"
        and pair["right_classification"] == "PROBABLE_FIXED_RECORD_ARRAY_INITIALIZER"
        for pair in loop_pairs
    )
    rejected_navigation_pairs = sum(
        pair["left_classification"]
        == "REJECTED_CALL_FIELD_OFFSET_NOT_RECORD_STRIDE"
        and pair["right_classification"]
        == "REJECTED_CALL_FIELD_OFFSET_NOT_RECORD_STRIDE"
        and pair["semantic_signature_equal"]
        for pair in navigation_pairs
    )
    targeted_pairs = sum(
        pair["left_classification"] == "REQUIRES_TARGETED_BUFFER_DATAFLOW"
        and pair["right_classification"] == "REQUIRES_TARGETED_BUFFER_DATAFLOW"
        for pair in loop_pairs
    )
    return {
        "schema": "phoenix-mmi.global-fldb-parser-search-comparison/v1",
        "analysis_mode": "read-only-static-cross-version-role-sensitive",
        "left_artifact_sha256": left["artifact"]["sha256"],
        "right_artifact_sha256": right["artifact"]["sha256"],
        "record_stride_loop_pairs": loop_pairs,
        "navigation_adjacent_cluster_pairs": navigation_pairs,
        "classification": {
            "cross_version_record_stride_loop_pair_count": len(loop_pairs),
            "cross_version_write_only_initializer_pair_count": initializer_pairs,
            "cross_version_rejected_navigation_numeric_pair_count": rejected_navigation_pairs,
            "cross_version_targeted_dataflow_pair_count": targeted_pairs,
            "promoted_fldb_parser_pair_count": 0,
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "search_result": "NO_CANDIDATE_MET_PARSER_PROMOTION_GATE",
        },
        "promotion_gate": {
            "requires_cross_version_structure": True,
            "requires_record_read_role": True,
            "requires_same_base_header_field_reads": True,
            "requires_endian_or_validated_helper_semantics": True,
            "requires_optical_buffer_provenance": True,
            "numeric_match_alone_is_sufficient": False,
        },
        "interpretation": (
            "Cross-version 36-byte loops exist, but none combines record reads, "
            "same-base FLDB header access, endian handling and verified optical-buffer "
            "provenance. The strongest structural pair is a write-only fixed-record "
            "initializer. A navigation-adjacent numeric cluster uses 36 as a call-field "
            "offset while its observed loop step is different. No parser is promoted."
        ),
        "publication_safety": copy.deepcopy(left["publication_safety"]),
    }


def update_operational_graph_v7(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v7"
    graph["nodes"].append(
        {
            "id": "fldb-global-parser-search",
            "label": "Role-sensitive global FLDB parser candidate search",
            "status": "CONFIRMED_BOUNDED_NEGATIVE",
            "parser_result": comparison["classification"]["search_result"],
            "evidence": ["S014-01", "S014-02", "RQ-036", "RQ-039"],
        }
    )
    graph["edges"].append(
        {
            "source": "fldb-global-parser-search",
            "target": "fldb-parser-routine",
            "relation": "screened cross-version numeric and loop candidates; none passed the promotion gate",
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
    graph["interpretation"] = (
        "Session 014 globally screens role-sensitive 36-byte loops and navigation-adjacent "
        "numeric clusters. The search rejects one write-only initializer family and one "
        "field-offset false positive, but keeps the actual FLDB parser and sector ABI open."
    )
    return graph


def correlate_global_fldb_parser_search(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.global-fldb-parser-correlation/v1",
        "analysis_mode": "read-only-static",
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "correlation": {
            "actual_fldb_parser": "OPEN",
            "partition_consumer": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "dynamic_compatibility": "NOT_ESTABLISHED",
        },
        "operational_graph": update_operational_graph_v7(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_global_parser_report(
    report: dict[str, object]
) -> dict[str, object]:
    return copy.deepcopy(report)

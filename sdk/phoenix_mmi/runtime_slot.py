"""Bounded runtime-slot and shadow-accessor analysis for Session 019.

The module distinguishes static layout evidence from runtime behavior.  A
zero-filled on-disk address used as a call target is never decoded as code.
Writer searches are limited to declared address models and a bounded linear
SuperH register model; an absent writer is therefore a bounded negative, not
proof that the slot is never initialized.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import hashlib

from .accessor_dispatch import (
    _callsite_signature,
    _compare_call_families,
    _find_all,
    _literal_jsr_calls,
    _target_reference_profile,
)
from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import summarize_bounded_entry


FLASH_BASE = 0x60000
_WRITER_FORWARD_INSTRUCTION_LIMIT = 64
_RELOCATION_PAIR_DISTANCE = 32
_PROBABLE_CONTEXT_COVERAGE = 0.85


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _literal_fact(value: int, image_size: int) -> tuple[str, int] | None:
    if RUNTIME_BASE <= value < RUNTIME_BASE + image_size:
        return ("runtime", value - RUNTIME_BASE)
    if FLASH_BASE <= value < FLASH_BASE + image_size:
        return ("flash", value - FLASH_BASE)
    if 0 <= value < image_size:
        return ("raw", value)
    if value <= 0x7FFFFFFF:
        return ("constant", value)
    return None


def _scan_bounded_direct_writers(
    data: bytes,
    *,
    run_start: int,
    run_end: int,
    forward_instruction_limit: int = _WRITER_FORWARD_INSTRUCTION_LIMIT,
) -> dict[str, object]:
    """Find direct stores reached from bounded, statically formed addresses.

    Seeds are PC-relative long loads under the runtime/raw/flash models and
    MOVA file-relative addresses.  The trace follows register copies and
    constant add/sub operations, then stops at calls, branches and returns.
    It does not model branch dominance, GBR, memory-loaded bases or helper
    calls, so a zero result is deliberately bounded.
    """

    image_size = len(data)
    seeds: list[tuple[int, int, tuple[str, int], str]] = []
    for offset in range(0, image_size - 2, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF000 == 0xD000:
            literal = (offset & ~3) + 4 + (word & 0xFF) * 4
            if literal + 4 > image_size:
                continue
            value = int.from_bytes(data[literal : literal + 4], "big")
            fact = _literal_fact(value, image_size)
            if fact is not None and fact[0] != "constant":
                seeds.append((offset, (word >> 8) & 0xF, fact, "mov.l-pc"))
        elif word & 0xFF00 == 0xC700:
            target = (offset & ~3) + 4 + (word & 0xFF) * 4
            if target < image_size:
                seeds.append((offset, 0, ("mova", target), "mova"))

    candidates: dict[tuple[object, ...], dict[str, object]] = {}
    for seed_offset, seed_register, seed_fact, seed_kind in seeds:
        registers: dict[int, tuple[str, int]] = {seed_register: seed_fact}
        for step in range(1, forward_instruction_limit + 1):
            offset = seed_offset + step * 2
            if offset + 2 > image_size:
                break
            word = int.from_bytes(data[offset : offset + 2], "big")
            n = (word >> 8) & 0xF
            m = (word >> 4) & 0xF
            family = word & 0xF00F

            stores: list[tuple[int, int, str]] = []
            if word & 0xF000 == 0x1000:
                stores.append((n, (word & 0xF) * 4, "mov.l-displaced"))
            if family in {0x2000, 0x2001, 0x2002}:
                stores.append((n, 0, "mov-indirect"))
            if family in {0x2004, 0x2005, 0x2006}:
                width = {0x2004: 1, 0x2005: 2, 0x2006: 4}[family]
                stores.append((n, -width, "mov-predecrement"))
            for base_register, displacement, store_kind in stores:
                fact = registers.get(base_register)
                if fact is None or fact[0] == "constant":
                    continue
                destination = int(fact[1]) + displacement
                if run_start <= destination < run_end:
                    key = (
                        seed_offset,
                        offset,
                        destination,
                        seed_fact[0],
                        store_kind,
                    )
                    candidates[key] = {
                        "seed_file_offset": seed_offset,
                        "seed_kind": seed_kind,
                        "seed_address_model": seed_fact[0],
                        "seed_target_file_offset": int(seed_fact[1]),
                        "store_file_offset": offset,
                        "store_kind": store_kind,
                        "destination_file_offset": destination,
                        "forward_instruction_distance": step,
                        "path_dominance_asserted": False,
                    }

            if word & 0xF00F == 0x6003:
                if m in registers:
                    registers[n] = registers[m]
                else:
                    registers.pop(n, None)
                continue
            if word & 0xF000 == 0xE000:
                registers[n] = ("constant", _signed8(word & 0xFF))
                continue
            if word & 0xF000 == 0x7000:
                if n in registers:
                    registers[n] = (
                        registers[n][0],
                        int(registers[n][1]) + _signed8(word & 0xFF),
                    )
                continue
            if family in {0x300C, 0x3008}:
                left = registers.get(n)
                right = registers.get(m)
                if (
                    left is not None
                    and right is not None
                    and (left[0] == "constant" or right[0] == "constant")
                ):
                    if family == 0x300C:
                        if left[0] == "constant":
                            registers[n] = (
                                right[0],
                                int(right[1]) + int(left[1]),
                            )
                        else:
                            registers[n] = (
                                left[0],
                                int(left[1]) + int(right[1]),
                            )
                    elif right[0] == "constant":
                        registers[n] = (
                            left[0],
                            int(left[1]) - int(right[1]),
                        )
                    else:
                        registers.pop(n, None)
                else:
                    registers.pop(n, None)
                continue
            if word & 0xF000 == 0xD000:
                literal = (offset & ~3) + 4 + (word & 0xFF) * 4
                value = (
                    int.from_bytes(data[literal : literal + 4], "big")
                    if literal + 4 <= image_size
                    else 0
                )
                fact = _literal_fact(value, image_size)
                if fact is None:
                    registers.pop(n, None)
                else:
                    registers[n] = fact
                continue
            if word & 0xF000 == 0x9000:
                registers.pop(n, None)
                continue
            if (
                word & 0xF000 == 0x5000
                or family in {0x6000, 0x6001, 0x6002, 0x6004, 0x6005, 0x6006}
            ):
                registers.pop(n, None)
            if (
                word & 0xF000 in {0xA000, 0xB000}
                or word & 0xFF00 in {0x8900, 0x8B00, 0x8D00, 0x8F00}
                or word in {0x000B, 0x002B}
                or word & 0xF0FF in {0x400B, 0x402B}
            ):
                break

    model_counts = Counter(seed[2][0] for seed in seeds)
    rows = sorted(
        candidates.values(),
        key=lambda row: (
            int(row["store_file_offset"]),
            int(row["seed_file_offset"]),
        ),
    )
    return {
        "forward_instruction_limit": forward_instruction_limit,
        "seed_count": len(seeds),
        "seed_address_model_counts": dict(sorted(model_counts.items())),
        "candidate_count": len(rows),
        "candidates": rows,
        "models": [
            "PC_RELATIVE_RUNTIME_BASE",
            "PC_RELATIVE_METAINFO_FLASH_BASE",
            "PC_RELATIVE_RAW_FILE_OFFSET",
            "MOVA_FILE_RELATIVE",
        ],
        "linear_path_only": True,
        "path_dominance_asserted": False,
        "memory_loaded_base_modeled": False,
        "gbr_addressing_modeled": False,
        "helper_mediated_copy_modeled": False,
    }


def _map_left_slot_to_right(
    left_data: bytes,
    right_data: bytes,
    left_calls: list[dict[str, int]],
    right_calls: list[dict[str, int]],
    *,
    left_target: int,
) -> dict[str, object]:
    selected = [row for row in left_calls if row["target_file_offset"] == left_target]
    right_index: dict[tuple[int, ...], list[dict[str, int]]] = defaultdict(list)
    for row in right_calls:
        signature = _callsite_signature(right_data, int(row["load_file_offset"]))
        if signature is not None:
            right_index[signature].append(row)

    unique = ambiguous = unmatched = consensus = 0
    targets: Counter[int] = Counter()
    for row in selected:
        signature = _callsite_signature(left_data, int(row["load_file_offset"]))
        candidates = right_index.get(signature, []) if signature is not None else []
        if len(candidates) == 1:
            unique += 1
        elif candidates:
            ambiguous += 1
        else:
            unmatched += 1
        candidate_targets = {
            int(candidate["target_file_offset"]) for candidate in candidates
        }
        if len(candidate_targets) == 1:
            consensus += 1
            targets[next(iter(candidate_targets))] += 1

    dominant_target = dominant_count = None
    if targets:
        dominant_target, dominant_count = targets.most_common(1)[0]
    return {
        "left_adjacent_call_count": len(selected),
        "unique_right_context_match_count": unique,
        "ambiguous_right_context_match_count": ambiguous,
        "unmatched_left_context_count": unmatched,
        "single_target_consensus_context_count": consensus,
        "dominant_right_target_file_offset": dominant_target,
        "dominant_right_target_consensus_count": dominant_count or 0,
        "dominant_right_target_consensus_coverage": round(
            (dominant_count or 0) / len(selected), 6
        )
        if selected
        else 0.0,
        "runtime_equivalence_asserted": False,
    }


def _branch_feasibility(slot: int, target: int, record_end: int) -> dict[str, object]:
    displacement_bytes = target - (slot + 4)
    displacement_words = displacement_bytes // 2 if displacement_bytes % 2 == 0 else None
    in_range = bool(
        displacement_words is not None and -2048 <= displacement_words <= 2047
    )
    available = record_end - slot
    return {
        "target_delta_from_slot": target - slot,
        "pc_relative_displacement_bytes": displacement_bytes,
        "pc_relative_displacement_words": displacement_words,
        "signed_12_bit_branch_range_satisfied": in_range,
        "branch_and_delay_slot_footprint_bytes": 4,
        "available_bytes_to_record_end": available,
        "footprint_fits": bool(in_range and available >= 4),
        "instruction_encoding_observed_on_disk": False,
        "runtime_branch_stub_asserted": False,
    }


def _encoded_address_census(
    data: bytes, labels: dict[str, int]
) -> dict[str, object]:
    model_bases = {
        "runtime": RUNTIME_BASE,
        "raw": 0,
        "metainfo_flash": FLASH_BASE,
    }
    rows = []
    model_target_counts: Counter[str] = Counter()
    model_occurrence_counts: Counter[str] = Counter()
    for label, target in labels.items():
        models = {}
        for model, base in model_bases.items():
            hits = _find_all(data, (base + target).to_bytes(4, "big"))
            aligned = [offset for offset in hits if offset % 4 == 0]
            models[model] = {
                "occurrence_count": len(hits),
                "aligned_occurrence_count": len(aligned),
            }
            if hits:
                model_target_counts[model] += 1
                model_occurrence_counts[model] += len(hits)
        rows.append(
            {
                "label": label,
                "target_file_offset": target,
                "models": models,
            }
        )
    return {
        "tested_target_count": len(rows),
        "targets_with_occurrences_by_model": dict(sorted(model_target_counts.items())),
        "total_occurrences_by_model": dict(sorted(model_occurrence_counts.items())),
        "targets": rows,
    }


def _exact_source_destination_pairs(
    data: bytes,
    source_targets: list[int],
    slot_targets: list[int],
    *,
    maximum_distance: int = _RELOCATION_PAIR_DISTANCE,
) -> dict[str, object]:
    pairs = set()
    for source in source_targets:
        source_hits = _find_all(data, (RUNTIME_BASE + source).to_bytes(4, "big"))
        for slot in slot_targets:
            for model, base in (
                ("runtime", RUNTIME_BASE),
                ("raw", 0),
                ("metainfo_flash", FLASH_BASE),
            ):
                destination_hits = _find_all(data, (base + slot).to_bytes(4, "big"))
                for source_hit in source_hits:
                    for destination_hit in destination_hits:
                        if abs(source_hit - destination_hit) <= maximum_distance:
                            pairs.add(
                                (
                                    source,
                                    slot,
                                    model,
                                    source_hit,
                                    destination_hit,
                                )
                            )
    rows = [
        {
            "source_target_file_offset": source,
            "destination_slot_file_offset": slot,
            "destination_address_model": model,
            "source_word_file_offset": source_word,
            "destination_word_file_offset": destination_word,
        }
        for source, slot, model, source_word, destination_word in sorted(pairs)
    ]
    return {
        "maximum_word_distance_bytes": maximum_distance,
        "candidate_count": len(rows),
        "candidates": rows,
        "record_semantics_asserted": False,
    }


def analyze_runtime_slot_lineage(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
) -> dict[str, object]:
    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    run = prior["dominant_left_target"]["zero_tail_record_run"]
    if not isinstance(run, dict):
        raise ValueError("Session 018 did not register a zero-tail record run")
    run_start = int(run["run_start_file_offset"])
    run_end = int(run["run_end_file_offset"])
    record_width = int(run["record_width"])
    left_calls = _literal_jsr_calls(left_data, image_size=left_reader.size)
    right_calls = _literal_jsr_calls(right_data, image_size=right_reader.size)

    source_targets = []
    labels = {"run_start": run_start, "run_end": run_end}
    slots = []
    for ordinal, record_start in enumerate(range(run_start, run_end, record_width)):
        source = (
            int.from_bytes(left_data[record_start : record_start + 4], "big")
            - RUNTIME_BASE
        )
        source_targets.append(source)
        labels[f"record_{ordinal}_start"] = record_start
        for word_ordinal in range(3):
            slot = record_start + 4 + word_ordinal * 4
            labels[f"record_{ordinal}_tail_{word_ordinal}"] = slot
            profile = _target_reference_profile(
                left_data,
                left_calls,
                target=slot,
                image_size=left_reader.size,
            )
            slots.append(
                {
                    "record_ordinal": ordinal,
                    "tail_word_ordinal": word_ordinal,
                    "slot_file_offset": slot,
                    "bytes_to_record_end": record_start + record_width - slot,
                    "reference_profile": profile,
                    "active_adjacent_call_slot": bool(
                        profile["adjacent_literal_jsr_count"]
                    ),
                }
            )

    source_profiles = []
    for ordinal, target in enumerate(source_targets):
        code = summarize_bounded_entry(
            left_reader, target, source="SESSION019_POINTER_FIELD"
        )
        references = _target_reference_profile(
            left_data,
            left_calls,
            target=target,
            image_size=left_reader.size,
        )
        source_profiles.append(
            {
                "record_ordinal": ordinal,
                "target_file_offset": target,
                "bounded_code_gate_passed": code["bounded_code_gate_passed"],
                "known_ratio": code["known_ratio"],
                "instruction_count": code["instruction_count"],
                "return_count": code["return_count"],
                "call_count": code["call_count"],
                "normalized_shape_sha256": code["normalized_shape_sha256"],
                "reference_profile": references,
                "writer_role_asserted": False,
            }
        )

    anchor_left = int(prior["paired_accessor"]["left_target_file_offset"])
    anchor_right = int(prior["paired_accessor"]["right_target_file_offset"])
    active_members = []
    for slot in slots:
        if not slot["active_adjacent_call_slot"]:
            continue
        left_target = int(slot["slot_file_offset"])
        forward = _map_left_slot_to_right(
            left_data,
            right_data,
            left_calls,
            right_calls,
            left_target=left_target,
        )
        right_target = forward["dominant_right_target_file_offset"]
        if not isinstance(right_target, int):
            active_members.append({**copy.deepcopy(slot), "forward_mapping": forward})
            continue
        reverse, _ = _compare_call_families(
            left_data,
            right_data,
            left_calls,
            right_calls,
            right_target=right_target,
        )
        left_static = anchor_left + (right_target - anchor_right)
        right_code = summarize_bounded_entry(
            right_reader, right_target, source="SESSION019_SHADOW_MEMBER"
        )
        body_width = int(right_code["instruction_count"]) * 2
        right_body = right_data[right_target : right_target + body_width]
        exact_hits = _find_all(left_data, right_body) if right_body else []
        exact_at_translated = bool(
            right_body
            and 0 <= left_static <= left_reader.size - body_width
            and left_data[left_static : left_static + body_width] == right_body
        )
        left_static_profile = _target_reference_profile(
            left_data,
            left_calls,
            target=left_static,
            image_size=left_reader.size,
        )
        if reverse["cross_version_call_family_promoted"] and exact_at_translated:
            status = "CONFIRMED_BOUNDED_SLOT_TO_DIRECT_MEMBER"
        elif (
            float(reverse["dominant_left_target_consensus_coverage"])
            >= _PROBABLE_CONTEXT_COVERAGE
            and int(reverse["dominant_left_target_consensus_count"]) >= 32
            and exact_at_translated
        ):
            status = "PROBABLE_HIGH_CONSENSUS_SHADOW_MEMBER"
        elif (
            int(forward["dominant_right_target_consensus_count"]) >= 8
            and exact_at_translated
        ):
            status = "CANDIDATE_STRUCTURAL_SHADOW_MEMBER"
        else:
            status = "OPEN"
        record_end = (
            run_start + (int(slot["record_ordinal"]) + 1) * record_width
        )
        active_members.append(
            {
                **copy.deepcopy(slot),
                "forward_mapping": forward,
                "reverse_mapping": reverse,
                "right_direct_target_file_offset": right_target,
                "right_relative_to_anchor": right_target - anchor_right,
                "translated_left_static_target_file_offset": left_static,
                "left_relative_to_anchor": left_static - anchor_left,
                "body_instruction_count": right_code["instruction_count"],
                "body_width_bytes": body_width,
                "body_sha256": hashlib.sha256(right_body).hexdigest(),
                "exact_body_at_translated_left_target": exact_at_translated,
                "exact_body_occurrence_count_in_left": len(exact_hits),
                "translated_left_static_reference_profile": left_static_profile,
                "branch_stub_feasibility": _branch_feasibility(
                    left_target, left_static, record_end
                ),
                "classification": status,
            }
        )

    active_targets = [int(row["slot_file_offset"]) for row in active_members]
    writer_search = _scan_bounded_direct_writers(
        left_data, run_start=run_start, run_end=run_end
    )
    pair_search = _exact_source_destination_pairs(
        left_data, source_targets, active_targets
    )
    exact_shadow_count = sum(
        bool(row.get("exact_body_at_translated_left_target"))
        for row in active_members
    )
    promoted_count = sum(
        row.get("classification") == "CONFIRMED_BOUNDED_SLOT_TO_DIRECT_MEMBER"
        for row in active_members
    )
    probable_count = sum(
        row.get("classification") == "PROBABLE_HIGH_CONSENSUS_SHADOW_MEMBER"
        for row in active_members
    )
    candidate_count = sum(
        row.get("classification") == "CANDIDATE_STRUCTURAL_SHADOW_MEMBER"
        for row in active_members
    )

    return {
        "schema": "phoenix-mmi.runtime-slot-lineage-comparison/v1",
        "analysis_mode": "read-only-static-bounded-runtime-slot-lineage",
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "limits": {
            "session018_unique_run_only": True,
            "tail_word_width": 4,
            "fixed_context_gate_reused_from_session018": True,
            "direct_writer_forward_instruction_limit": _WRITER_FORWARD_INSTRUCTION_LIMIT,
            "exact_relocation_pair_distance": _RELOCATION_PAIR_DISTANCE,
            "function_boundary_asserted": False,
            "runtime_execution_observed": False,
        },
        "record_run": {
            **copy.deepcopy(run),
            "source_targets": source_targets,
            "source_target_delta_vector": [
                source_targets[index] - source_targets[index - 1]
                for index in range(1, len(source_targets))
            ],
            "source_profiles": source_profiles,
            "writer_role_asserted_for_pointer_fields": False,
        },
        "tail_slot_census": {
            "slot_count": len(slots),
            "active_adjacent_call_slot_count": len(active_members),
            "inactive_slot_count": len(slots) - len(active_members),
            "slots": slots,
        },
        "shadow_accessor_cluster": {
            "left_static_anchor_file_offset": anchor_left,
            "right_direct_anchor_file_offset": anchor_right,
            "translation_delta": anchor_left - anchor_right,
            "active_members": active_members,
            "exact_translated_body_member_count": exact_shadow_count,
            "confirmed_member_count": promoted_count,
            "probable_member_count": probable_count,
            "candidate_member_count": candidate_count,
            "runtime_equivalence_asserted": False,
        },
        "encoded_address_census": _encoded_address_census(left_data, labels),
        "direct_writer_search": writer_search,
        "exact_source_destination_pair_search": pair_search,
        "classification": {
            "active_zero_tail_slots": "CONFIRMED_THREE_LITERAL_BACKED_CALL_TARGETS",
            "translated_static_body_identity": (
                "CONFIRMED_THREE_BYTE_IDENTICAL_MEMBERS"
                if exact_shadow_count == 3
                else "PARTIAL"
            ),
            "slot_to_direct_member_mapping": {
                "confirmed": promoted_count,
                "probable": probable_count,
                "candidate": candidate_count,
            },
            "direct_static_writer": (
                "NOT_FOUND_UNDER_BOUNDED_PC_RELATIVE_ADDRESS_MODEL"
                if not writer_search["candidate_count"]
                else "CANDIDATES_REQUIRE_VALIDATION"
            ),
            "exact_relocation_record": (
                "NOT_FOUND_UNDER_EXACT_32_BYTE_PAIR_MODEL"
                if not pair_search["candidate_count"]
                else "CANDIDATES_REQUIRE_VALIDATION"
            ),
            "runtime_patch_overlay_or_linkage_mechanism": (
                "HYPOTHESIS_STRENGTHENED_BY_SHADOW_LAYOUT"
            ),
            "specific_writer_or_loader_chain": "OPEN",
            "source_pointer_roles": "OPEN",
            "specific_session017_producer_edge": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "actual_fldb_parser": "OPEN",
        },
        "interpretation": (
            "Three zero-filled CD1 tail words are literal-backed call targets. "
            "Their contexts select three compact CD3 direct entries, and byte-"
            "identical bodies remain at the same translated relative offsets in "
            "CD1 with no direct call references. This confirms a shadow-dispatch "
            "layout and makes a runtime patch, overlay or linkage mechanism more "
            "plausible. The bounded direct-writer and exact relocation-pair models "
            "found no initializer, so no specific runtime mechanism is asserted."
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


def update_operational_graph_v12(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v12"
    graph["nodes"] = [
        node for node in graph["nodes"] if node["id"] != "runtime-slot-lineage"
    ]
    graph["nodes"].append(
        {
            "id": "runtime-slot-lineage",
            "label": "CD1 runtime-slot and shadow-accessor lineage",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "active_slot_status": comparison["classification"][
                "active_zero_tail_slots"
            ],
            "writer_status": comparison["classification"]["direct_static_writer"],
            "runtime_mechanism": comparison["classification"][
                "runtime_patch_overlay_or_linkage_mechanism"
            ],
            "evidence": ["S019-01", "S019-02", "S019-03", "RQ-053", "RQ-054"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "runtime-slot-lineage"
            and edge["target"] == "accessor-call-family"
        )
    ]
    graph["edges"].append(
        {
            "source": "runtime-slot-lineage",
            "target": "accessor-call-family",
            "relation": (
                "three zero-tail call targets correspond to a translated static "
                "accessor cluster; direct writer remains unlocated"
            ),
            "status": "CONFIRMED_STRUCTURAL",
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


def correlate_runtime_slot_lineage(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.runtime-slot-lineage-correlation/v1",
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
        "operational_graph": update_operational_graph_v12(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_runtime_slot_report(report: dict[str, object]) -> dict[str, object]:
    return copy.deepcopy(report)

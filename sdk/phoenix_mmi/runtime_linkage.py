"""Cross-version runtime-linkage family and bounded loader probes.

Session 020 keeps syntactic call forms, static record layout and runtime
semantics separate.  Zero-filled on-disk targets are counted but never decoded
as code.  Writer searches cover only the explicitly reported GBR,
helper-argument and coherent section-copy models.
"""

from __future__ import annotations

from collections import Counter
import copy

from .accessor_dispatch import _literal_jsr_calls
from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .runtime_slot import FLASH_BASE


_RECORD_WIDTH = 16
_TAIL_WIDTH = 12
_WRITER_INSTRUCTION_LIMIT = 64
_GBR_FORWARD_BYTES = 0x200
_MAXIMUM_COPY_LENGTH = 0x100000
_CACHE_MARKERS = (
    b"cacheFlush",
    b"cacheInvalidate",
    b"cacheTextUpdate",
    b"cacheClear",
    b"cacheLib",
)


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _address_models(value: int, image_size: int) -> list[tuple[str, int]]:
    rows = []
    for name, base in (
        ("runtime", RUNTIME_BASE),
        ("raw", 0),
        ("metainfo_flash", FLASH_BASE),
    ):
        target = value - base
        if 0 <= target < image_size:
            rows.append((name, target))
    return rows


def _pointer_zero_runs(data: bytes) -> list[dict[str, object]]:
    records = []
    for offset in range(0, len(data) - _RECORD_WIDTH + 1, 4):
        value = int.from_bytes(data[offset : offset + 4], "big")
        if (
            RUNTIME_BASE <= value < RUNTIME_BASE + len(data)
            and data[offset + 4 : offset + _RECORD_WIDTH] == bytes(_TAIL_WIDTH)
        ):
            records.append(offset)

    record_offsets = set(records)
    runs = []
    for start in records:
        if start - _RECORD_WIDTH in record_offsets:
            continue
        targets = []
        cursor = start
        while cursor in record_offsets:
            targets.append(
                int.from_bytes(data[cursor : cursor + 4], "big") - RUNTIME_BASE
            )
            cursor += _RECORD_WIDTH
        runs.append(
            {
                "run_start_file_offset": start,
                "run_end_file_offset": cursor,
                "record_width": _RECORD_WIDTH,
                "record_count": len(targets),
                "pointer_target_file_offsets": targets,
                "pointer_target_delta_vector": [
                    targets[index] - targets[index - 1]
                    for index in range(1, len(targets))
                ],
                "first_pointer_relative_to_run": targets[0] - start,
            }
        )
    return runs


def _selected_run_activity(
    calls: list[dict[str, int]],
    run: dict[str, object],
    *,
    call_counts: Counter[int] | None = None,
) -> dict[str, object]:
    counts = (
        call_counts
        if call_counts is not None
        else Counter(int(row["target_file_offset"]) for row in calls)
    )
    active = []
    start = int(run["run_start_file_offset"])
    record_width = int(run["record_width"])
    for record_ordinal in range(int(run["record_count"])):
        record = start + record_ordinal * record_width
        for tail_word_ordinal in range(3):
            target = record + 4 + tail_word_ordinal * 4
            count = counts[target]
            if count:
                active.append(
                    {
                        "record_ordinal": record_ordinal,
                        "tail_word_ordinal": tail_word_ordinal,
                        "slot_file_offset": target,
                        "adjacent_literal_jsr_count": count,
                    }
                )
    return {
        "tail_slot_count": int(run["record_count"]) * 3,
        "active_tail_slot_count": len(active),
        "adjacent_literal_jsr_count": sum(
            int(row["adjacent_literal_jsr_count"]) for row in active
        ),
        "active_slots": active,
        "runtime_execution_observed": False,
    }


def _zero_target_family_census(
    data: bytes,
    calls: list[dict[str, int]],
    runs: list[dict[str, object]],
) -> dict[str, object]:
    call_counts = Counter(int(row["target_file_offset"]) for row in calls)
    zero_targets = {
        target: count
        for target, count in call_counts.items()
        if 0 <= target <= len(data) - 4 and data[target : target + 4] == bytes(4)
    }
    covered = set()
    active_runs = 0
    active_run_calls = []
    for run in runs:
        activity = _selected_run_activity(calls, run, call_counts=call_counts)
        if activity["active_tail_slot_count"]:
            active_runs += 1
            active_run_calls.append(int(activity["adjacent_literal_jsr_count"]))
            covered.update(
                int(row["slot_file_offset"]) for row in activity["active_slots"]
            )
    histogram = Counter(zero_targets.values())
    return {
        "adjacent_literal_jsr_count": len(calls),
        "unique_literal_target_count": len(call_counts),
        "zero_filled_target_count": len(zero_targets),
        "calls_to_zero_filled_targets": sum(zero_targets.values()),
        "pointer_zero_run_count": len(runs),
        "active_pointer_zero_run_count": active_runs,
        "zero_filled_targets_covered_by_pointer_zero_runs": len(
            set(zero_targets) & covered
        ),
        "zero_filled_targets_outside_pointer_zero_runs": len(
            set(zero_targets) - covered
        ),
        "zero_target_call_count_histogram": {
            str(key): value for key, value in sorted(histogram.items())
        },
        "largest_active_run_call_count": max(active_run_calls, default=0),
        "code_semantics_asserted_for_global_census": False,
        "runtime_execution_observed": False,
    }


def _find_normalized_run_pair(
    left_run: dict[str, object], right_runs: list[dict[str, object]]
) -> dict[str, object]:
    candidates = [
        run
        for run in right_runs
        if int(run["record_count"]) == int(left_run["record_count"])
        and run["pointer_target_delta_vector"]
        == left_run["pointer_target_delta_vector"]
        and int(run["first_pointer_relative_to_run"])
        == int(left_run["first_pointer_relative_to_run"])
    ]
    if len(candidates) != 1:
        return {
            "normalized_candidate_count": len(candidates),
            "unique_pair_found": False,
            "right_run": None,
        }
    right = candidates[0]
    run_translation = int(right["run_start_file_offset"]) - int(
        left_run["run_start_file_offset"]
    )
    left_targets = [
        int(value) for value in left_run["pointer_target_file_offsets"]
    ]
    right_targets = [
        int(value) for value in right["pointer_target_file_offsets"]
    ]
    pointer_translations = [
        right_value - left_value
        for left_value, right_value in zip(left_targets, right_targets)
    ]
    return {
        "normalized_candidate_count": 1,
        "unique_pair_found": True,
        "right_run": right,
        "run_start_translation_delta": run_translation,
        "pointer_target_translation_deltas": pointer_translations,
        "all_pointer_translations_equal_run_translation": bool(
            pointer_translations
            and all(value == run_translation for value in pointer_translations)
        ),
        "runtime_semantics_asserted": False,
    }


def _resolve_gbr_base(
    data: bytes, offset: int, register: int, *, instruction_limit: int
) -> list[dict[str, object]]:
    addend = 0
    current = register
    for step in range(1, instruction_limit + 1):
        here = offset - step * 2
        if here < 0:
            break
        word = int.from_bytes(data[here : here + 2], "big")
        n = (word >> 8) & 0xF
        m = (word >> 4) & 0xF
        family = word & 0xF00F
        if word & 0xF000 == 0x7000 and n == current:
            addend += _signed8(word & 0xFF)
            continue
        if family == 0x6003 and n == current:
            current = m
            continue
        if word & 0xF000 == 0xD000 and n == current:
            literal = (here & ~3) + 4 + (word & 0xFF) * 4
            if literal + 4 > len(data):
                return []
            value = int.from_bytes(data[literal : literal + 4], "big")
            return [
                {
                    "model": model,
                    "base_file_offset": target + addend,
                    "seed_file_offset": here,
                    "backward_instruction_distance": step,
                }
                for model, target in _address_models(value, len(data))
                if 0 <= target + addend < len(data)
            ]
        if word & 0xFF00 == 0xC700 and current == 0:
            target = (here & ~3) + 4 + (word & 0xFF) * 4 + addend
            if 0 <= target < len(data):
                return [
                    {
                        "model": "mova",
                        "base_file_offset": target,
                        "seed_file_offset": here,
                        "backward_instruction_distance": step,
                    }
                ]
            return []
        if (
            (word & 0xF000 in {0x5000, 0xE000} and n == current)
            or (
                family
                in {0x6000, 0x6001, 0x6002, 0x6004, 0x6005, 0x6006}
                and n == current
            )
        ):
            return []
        if (
            word & 0xF000 in {0xA000, 0xB000}
            or word & 0xFF00 in {0x8900, 0x8B00, 0x8D00, 0x8F00}
            or word in {0x000B, 0x002B}
            or word & 0xF0FF in {0x400B, 0x402B}
        ):
            return []
    return []


def _scan_bounded_gbr_writers(
    data: bytes, *, run_start: int, run_end: int
) -> dict[str, object]:
    initializers = []
    for offset in range(0, len(data) - 2, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF0FF == 0x401E:
            register = (word >> 8) & 0xF
            bases = _resolve_gbr_base(
                data,
                offset,
                register,
                instruction_limit=_WRITER_INSTRUCTION_LIMIT,
            )
            initializers.append(
                {
                    "file_offset": offset,
                    "kind": "ldc-register",
                    "resolved_bases": bases,
                }
            )
        elif word & 0xF0FF == 0x4017:
            initializers.append(
                {
                    "file_offset": offset,
                    "kind": "ldc-memory",
                    "resolved_bases": [],
                }
            )

    candidates = []
    for initializer in initializers:
        for base in initializer["resolved_bases"]:
            start = int(initializer["file_offset"]) + 2
            end = min(len(data) - 2, start + _GBR_FORWARD_BYTES)
            for offset in range(start, end, 2):
                word = int.from_bytes(data[offset : offset + 2], "big")
                family = word & 0xFF00
                if family in {0xC000, 0xC100, 0xC200}:
                    scale = {0xC000: 1, 0xC100: 2, 0xC200: 4}[family]
                    destination = int(base["base_file_offset"]) + (
                        word & 0xFF
                    ) * scale
                    if run_start <= destination < run_end:
                        candidates.append(
                            {
                                "initializer_file_offset": initializer[
                                    "file_offset"
                                ],
                                "store_file_offset": offset,
                                "destination_file_offset": destination,
                                "base_model": base["model"],
                            }
                        )
                if word & 0xF0FF in {0x401E, 0x4017}:
                    break

    kind_counts = Counter(str(row["kind"]) for row in initializers)
    resolved = [
        row for row in initializers if row["kind"] == "ldc-register" and row["resolved_bases"]
    ]
    return {
        "syntactic_initializer_count": len(initializers),
        "initializer_kind_counts": dict(sorted(kind_counts.items())),
        "resolved_register_initializer_count": len(resolved),
        "resolved_base_fact_count": sum(
            len(row["resolved_bases"]) for row in resolved
        ),
        "candidate_store_count": len(candidates),
        "candidates": candidates,
        "backward_instruction_limit": _WRITER_INSTRUCTION_LIMIT,
        "forward_byte_limit": _GBR_FORWARD_BYTES,
        "memory_loaded_gbr_base_modeled": False,
        "path_dominance_asserted": False,
    }


def _scan_helper_mediated_destinations(
    data: bytes, *, run_start: int, run_end: int
) -> dict[str, object]:
    seeds = 0
    candidates = {}
    for offset in range(0, len(data) - 2, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF000 != 0xD000:
            continue
        register = (word >> 8) & 0xF
        literal = (offset & ~3) + 4 + (word & 0xFF) * 4
        if literal + 4 > len(data):
            continue
        value = int.from_bytes(data[literal : literal + 4], "big")
        facts = [
            (model, target)
            for model, target in _address_models(value, len(data))
            if run_start <= target < run_end
        ]
        if not facts:
            continue
        seeds += 1
        registers = {register: facts[0]}
        for step in range(1, _WRITER_INSTRUCTION_LIMIT + 1):
            here = offset + step * 2
            if here + 2 > len(data):
                break
            current = int.from_bytes(data[here : here + 2], "big")
            n = (current >> 8) & 0xF
            m = (current >> 4) & 0xF
            family = current & 0xF00F
            if family == 0x6003:
                if m in registers:
                    registers[n] = registers[m]
                else:
                    registers.pop(n, None)
                continue
            if current & 0xF000 == 0x7000 and n in registers:
                model, target = registers[n]
                registers[n] = (model, target + _signed8(current & 0xFF))
                continue
            if current & 0xF0FF == 0x400B:
                call_register = n
                for argument, fact in registers.items():
                    if (
                        4 <= argument <= 7
                        and argument != call_register
                        and run_start <= fact[1] < run_end
                    ):
                        key = (
                            offset,
                            here,
                            argument,
                            fact[0],
                            fact[1],
                        )
                        candidates[key] = {
                            "seed_file_offset": offset,
                            "call_file_offset": here,
                            "argument_register": argument,
                            "address_model": fact[0],
                            "target_file_offset": fact[1],
                        }
                break
            if (
                current & 0xF000 in {0xA000, 0xB000}
                or current & 0xFF00 in {0x8900, 0x8B00, 0x8D00, 0x8F00}
                or current in {0x000B, 0x002B}
                or current & 0xF0FF == 0x402B
            ):
                break
            destination = None
            if current & 0xF000 in {0x5000, 0x9000, 0xD000, 0xE000}:
                destination = n
            elif family in {
                0x6000,
                0x6001,
                0x6002,
                0x6004,
                0x6005,
                0x6006,
            }:
                destination = n
            if destination is not None:
                registers.pop(destination, None)

    rows = sorted(
        candidates.values(),
        key=lambda row: (
            int(row["call_file_offset"]),
            int(row["seed_file_offset"]),
        ),
    )
    return {
        "exact_run_address_seed_count": seeds,
        "forward_instruction_limit": _WRITER_INSTRUCTION_LIMIT,
        "helper_mediated_candidate_count": len(rows),
        "candidates": rows,
        "helper_identity_resolved": False,
        "path_dominance_asserted": False,
    }


def _scan_coherent_copy_tables(
    data: bytes, *, run_start: int, run_end: int
) -> dict[str, object]:
    records: dict[int, list[dict[str, object]]] = {}
    for offset in range(0, len(data) - 12 + 1, 4):
        source_value = int.from_bytes(data[offset : offset + 4], "big")
        destination_value = int.from_bytes(data[offset + 4 : offset + 8], "big")
        length = int.from_bytes(data[offset + 8 : offset + 12], "big")
        if not 4 <= length <= _MAXIMUM_COPY_LENGTH or length % 4:
            continue
        variants = []
        for source_model, source in _address_models(source_value, len(data)):
            for destination_model, destination in _address_models(
                destination_value, len(data)
            ):
                if source == destination:
                    continue
                if source + length > len(data) or destination + length > len(data):
                    continue
                variants.append(
                    {
                        "source_model": source_model,
                        "source": source,
                        "destination_model": destination_model,
                        "destination": destination,
                        "length": length,
                    }
                )
        if variants:
            records[offset] = variants

    record_offsets = set(records)
    tables = []
    for start in sorted(record_offsets):
        if start - 12 in record_offsets:
            continue
        offsets = []
        cursor = start
        while cursor in record_offsets:
            offsets.append(cursor)
            cursor += 12
        if len(offsets) < 2:
            continue
        common_model_pairs = None
        for offset in offsets:
            pairs = {
                (str(row["source_model"]), str(row["destination_model"]))
                for row in records[offset]
            }
            common_model_pairs = (
                pairs
                if common_model_pairs is None
                else common_model_pairs & pairs
            )
        if not common_model_pairs:
            continue
        covering_pairs = set()
        for model_pair in common_model_pairs:
            for offset in offsets:
                for row in records[offset]:
                    if (
                        (row["source_model"], row["destination_model"])
                        == model_pair
                        and int(row["destination"]) < run_end
                        and int(row["destination"]) + int(row["length"]) > run_start
                    ):
                        covering_pairs.add(model_pair)
        tables.append(
            {
                "start_file_offset": start,
                "record_count": len(offsets),
                "coherent_model_pair_count": len(common_model_pairs),
                "covering_model_pair_count": len(covering_pairs),
            }
        )

    table_starts = {int(table["start_file_offset"]) for table in tables}
    reference_counts: Counter[int] = Counter()
    for offset in range(0, len(data) - 2, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF000 != 0xD000:
            continue
        literal = (offset & ~3) + 4 + (word & 0xFF) * 4
        if literal + 4 > len(data):
            continue
        value = int.from_bytes(data[literal : literal + 4], "big")
        for _, target in _address_models(value, len(data)):
            if target in table_starts:
                reference_counts[target] += 1

    referenced = [
        {**table, "pc_relative_reference_count": reference_counts[int(table["start_file_offset"])]}
        for table in tables
        if reference_counts[int(table["start_file_offset"])]
    ]
    covering = [
        table for table in tables if int(table["covering_model_pair_count"])
    ]
    referenced_covering = [
        table
        for table in referenced
        if int(table["covering_model_pair_count"])
    ]
    return {
        "valid_single_record_offset_count": len(records),
        "coherent_multi_record_table_count": len(tables),
        "referenced_coherent_table_count": len(referenced),
        "covering_coherent_table_count": len(covering),
        "referenced_covering_coherent_table_count": len(referenced_covering),
        "record_count_distribution": {
            str(key): value
            for key, value in sorted(
                Counter(int(table["record_count"]) for table in tables).items()
            )
        },
        "candidate_semantics_asserted": False,
        "table_start_pc_relative_reference_required": True,
        "uniform_address_model_pair_required": True,
        "maximum_copy_length": _MAXIMUM_COPY_LENGTH,
    }


def _cache_marker_census(data: bytes) -> dict[str, object]:
    counts = [data.count(marker) for marker in _CACHE_MARKERS]
    return {
        "tested_exact_marker_count": len(_CACHE_MARKERS),
        "matched_marker_count": sum(bool(count) for count in counts),
        "total_marker_occurrence_count": sum(counts),
        "marker_text_included": False,
        "stripped_imports_or_inlined_cache_operations_modeled": False,
    }


def _disc_analysis(
    data: bytes,
    calls: list[dict[str, int]],
    runs: list[dict[str, object]],
    selected_run: dict[str, object],
) -> dict[str, object]:
    start = int(selected_run["run_start_file_offset"])
    end = int(selected_run["run_end_file_offset"])
    return {
        "selected_run": copy.deepcopy(selected_run),
        "selected_run_activity": _selected_run_activity(calls, selected_run),
        "global_zero_target_family": _zero_target_family_census(data, calls, runs),
        "gbr_writer_search": _scan_bounded_gbr_writers(
            data, run_start=start, run_end=end
        ),
        "helper_mediated_destination_search": _scan_helper_mediated_destinations(
            data, run_start=start, run_end=end
        ),
        "coherent_copy_table_search": _scan_coherent_copy_tables(
            data, run_start=start, run_end=end
        ),
        "cache_marker_census": _cache_marker_census(data),
    }


def analyze_runtime_linkage_family(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
) -> dict[str, object]:
    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    left_calls = _literal_jsr_calls(left_data, image_size=left_reader.size)
    right_calls = _literal_jsr_calls(right_data, image_size=right_reader.size)
    left_runs = _pointer_zero_runs(left_data)
    right_runs = _pointer_zero_runs(right_data)

    prior_run = prior["record_run"]
    prior_start = int(prior_run["run_start_file_offset"])
    left_matches = [
        run for run in left_runs if int(run["run_start_file_offset"]) == prior_start
    ]
    if len(left_matches) != 1:
        raise ValueError("Session 019 run is not unique in the left image")
    left_run = left_matches[0]
    pair = _find_normalized_run_pair(left_run, right_runs)
    if not pair["unique_pair_found"] or not isinstance(pair["right_run"], dict):
        raise ValueError("no unique normalized right-side run pair")
    right_run = pair["right_run"]

    left = _disc_analysis(left_data, left_calls, left_runs, left_run)
    right = _disc_analysis(right_data, right_calls, right_runs, right_run)
    copy_found = (
        int(
            left["coherent_copy_table_search"][
                "referenced_covering_coherent_table_count"
            ]
        )
        + int(
            right["coherent_copy_table_search"][
                "referenced_covering_coherent_table_count"
            ]
        )
    )
    gbr_found = int(left["gbr_writer_search"]["candidate_store_count"]) + int(
        right["gbr_writer_search"]["candidate_store_count"]
    )
    helper_found = int(
        left["helper_mediated_destination_search"][
            "helper_mediated_candidate_count"
        ]
    ) + int(
        right["helper_mediated_destination_search"][
            "helper_mediated_candidate_count"
        ]
    )
    left_active = int(left["selected_run_activity"]["active_tail_slot_count"])
    right_active = int(right["selected_run_activity"]["active_tail_slot_count"])

    return {
        "schema": "phoenix-mmi.runtime-linkage-family-comparison/v1",
        "analysis_mode": "read-only-static-bounded-runtime-linkage-family",
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "normalized_run_pair": pair,
        "left": left,
        "right": right,
        "classification": {
            "cross_version_record_run": (
                "CONFIRMED_UNIQUE_NORMALIZED_BILATERAL_RUN"
            ),
            "pointer_translation": (
                "CONFIRMED_EQUAL_RUN_AND_POINTER_TRANSLATION"
                if pair["all_pointer_translations_equal_run_translation"]
                else "PARTIAL"
            ),
            "selected_run_usage_transition": (
                f"CONFIRMED_SYNTACTIC_{left_active}_TO_{right_active}_ACTIVE_SLOTS"
            ),
            "global_zero_target_family": "CONFIRMED_SYNTACTIC_FAMILY",
            "gbr_writer": (
                "NOT_FOUND_UNDER_BOUNDED_RESOLVED_GBR_MODEL"
                if not gbr_found
                else "CANDIDATES_REQUIRE_VALIDATION"
            ),
            "helper_mediated_writer": (
                "NOT_FOUND_UNDER_EXACT_RUN_ADDRESS_ARGUMENT_MODEL"
                if not helper_found
                else "CANDIDATES_REQUIRE_VALIDATION"
            ),
            "coherent_section_copy_table": (
                "NOT_FOUND_UNDER_REFERENCED_UNIFORM_MODEL_TRIPLE_GATE"
                if not copy_found
                else "CANDIDATES_REQUIRE_VALIDATION"
            ),
            "named_cache_maintenance_marker": (
                "NOT_FOUND_UNDER_FIVE_EXACT_ASCII_MARKERS"
                if not left["cache_marker_census"]["matched_marker_count"]
                and not right["cache_marker_census"]["matched_marker_count"]
                else "MARKERS_PRESENT_REQUIRE_VALIDATION"
            ),
            "runtime_patch_overlay_or_linkage_mechanism": (
                "HYPOTHESIS_STRENGTHENED_BY_BILATERAL_RESIDENT_LAYOUT"
            ),
            "specific_writer_or_loader_chain": "OPEN",
            "memory_loaded_base_writer": "OPEN",
            "specific_session017_producer_edge": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "actual_fldb_parser": "OPEN",
        },
        "limits": {
            "global_call_census_is_syntactic": True,
            "zero_filled_targets_decoded_as_code": False,
            "runtime_execution_observed": False,
            "branch_dominance_asserted": False,
            "memory_loaded_gbr_base_modeled": False,
            "compressed_or_section_relative_loader_metadata_modeled": False,
            "external_loader_or_boot_stage_modeled": False,
        },
        "interpretation": (
            "The five-record pointer-plus-zero-tail layout is a unique normalized "
            "cross-version pair: its run and every pointer target translate by "
            "the same file-offset delta. CD1 has three syntactically active tail "
            "slots and CD3 retains one with residual calls, so the structure is "
            "not CD1-only. Similar zero-filled literal-call targets occur broadly "
            "in both images. Bounded GBR, exact-address helper, coherent copy-table "
            "and named cache-marker probes identify no writer chain; runtime "
            "linkage remains a strengthened hypothesis rather than a mechanism."
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


def update_operational_graph_v13(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v13"
    graph["nodes"] = [
        node for node in graph["nodes"] if node["id"] != "runtime-linkage-family"
    ]
    graph["nodes"].append(
        {
            "id": "runtime-linkage-family",
            "label": "Bilateral pointer-zero runtime-linkage family",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "pair_status": comparison["classification"]["cross_version_record_run"],
            "writer_status": {
                "gbr": comparison["classification"]["gbr_writer"],
                "helper": comparison["classification"]["helper_mediated_writer"],
                "copy_table": comparison["classification"][
                    "coherent_section_copy_table"
                ],
            },
            "evidence": ["S020-01", "S020-02", "S020-03", "RQ-056", "RQ-057"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "runtime-linkage-family"
            and edge["target"] == "runtime-slot-lineage"
        )
    ]
    graph["edges"].append(
        {
            "source": "runtime-linkage-family",
            "target": "runtime-slot-lineage",
            "relation": (
                "the normalized five-record run persists in both releases with "
                "residual CD3 literal-call use"
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


def correlate_runtime_linkage_family(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.runtime-linkage-family-correlation/v1",
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
        "operational_graph": update_operational_graph_v13(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_runtime_linkage_report(
    report: dict[str, object]
) -> dict[str, object]:
    return copy.deepcopy(report)

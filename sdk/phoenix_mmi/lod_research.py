"""Publication-safe structural research for opaque LOD payloads."""

from __future__ import annotations

from collections import Counter
import hashlib
import math


_ALIGNMENT_WIDTHS = (2, 3, 4, 8, 16)
_ZERO_RUN_THRESHOLD = 4096
_FF_RUN_THRESHOLD = 128
_GRID_SIZES = (128, 256, 512, 1024)
_ATLAS_BLOCK_SIZE = 256


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "source_content_hashes_included": False,
        "raw_header_values_included": False,
        "raw_offsets_included": False,
        "raw_strings_included": False,
        "local_paths_included": False,
        "extracted_resources_included": False,
        "runtime_execution_observed": False,
    }


def _lod_rows(
    sources: list[dict[str, object]],
) -> list[tuple[str, bytes]]:
    rows = [
        (str(source["source_id"]), bytes(source["data"]))
        for source in sources
        if source["extension"] == ".LOD"
    ]
    if len(rows) < 2:
        raise ValueError("at least two LOD sources are required")
    return rows


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum(
        (count / len(data)) * math.log2(count / len(data))
        for count in counts.values()
    )


def analyze_lod_alignment(
    sources: list[dict[str, object]],
) -> dict[str, object]:
    rows = _lod_rows(sources)
    minimum = min(len(data) for _, data in rows)
    widths = []
    for width in _ALIGNMENT_WIDTHS:
        ratios = []
        for phase in range(width):
            total = 0
            equal = 0
            for index in range(phase, minimum, width):
                total += 1
                equal += (
                    len({data[index] for _, data in rows}) == 1
                )
            ratios.append(round(equal / total, 8) if total else 0.0)
        widths.append(
            {
                "candidate_width": width,
                "phase_common_byte_ratios": ratios,
                "maximum_phase": max(
                    range(width), key=lambda phase: ratios[phase]
                ),
                "phase_spread": round(max(ratios) - min(ratios), 8),
            }
        )
    width3 = next(
        row for row in widths if row["candidate_width"] == 3
    )
    phase_bias = (
        int(width3["maximum_phase"]) == 0
        and float(width3["phase_spread"]) >= 0.05
    )
    return {
        "schema": "phoenix-mmi.lod-alignment-census/v1",
        "analysis_mode": (
            "read-only-fixed-width-cross-language-phase-invariance"
        ),
        "session": "055",
        "unique_source_count": len(rows),
        "minimum_compared_span": minimum,
        "candidate_widths": list(_ALIGNMENT_WIDTHS),
        "three_byte_phase_bias_threshold": 0.05,
        "width_results": widths,
        "classification": {
            "global_alignment": (
                "THREE_BYTE_PHASE_BIAS_OBSERVED"
                if phase_bias
                else "NO_FIXED_WIDTH_PHASE_BIAS_OVER_THRESHOLD"
            ),
            "record_width": "NOT_ESTABLISHED",
        },
        "operational_graph_version": "v47",
        "publication_safety": _publication_safety(),
    }


def _runs(data: bytes, value: int, minimum: int) -> list[tuple[int, int]]:
    rows = []
    start: int | None = None
    for index, item in enumerate(data):
        if item == value and start is None:
            start = index
        elif item != value and start is not None:
            if index - start >= minimum:
                rows.append((start, index - start))
            start = None
    if start is not None and len(data) - start >= minimum:
        rows.append((start, len(data) - start))
    return rows


def _delimiter_rows(data: bytes) -> list[dict[str, int | str]]:
    rows = [
        {"type": "ZERO", "start": start, "length": length}
        for start, length in _runs(data, 0, _ZERO_RUN_THRESHOLD)
    ]
    rows.extend(
        {"type": "FF", "start": start, "length": length}
        for start, length in _runs(data, 0xFF, _FF_RUN_THRESHOLD)
    )
    return sorted(rows, key=lambda row: int(row["start"]))


def analyze_lod_fill_regions(
    sources: list[dict[str, object]],
) -> dict[str, object]:
    lods = _lod_rows(sources)
    private = [
        (source_id, _delimiter_rows(data)) for source_id, data in lods
    ]
    rows = []
    for source_id, delimiters in private:
        rows.append(
            {
                "source_id": source_id,
                "delimiter_count": len(delimiters),
                "region_count": len(delimiters) + 1,
                "delimiter_sequence": [
                    str(row["type"]) for row in delimiters
                ],
                "delimiter_lengths": [
                    int(row["length"]) for row in delimiters
                ],
                "start_phases_modulo_3": [
                    int(row["start"]) % 3 for row in delimiters
                ],
            }
        )
    ordinal_spans = []
    maximum_count = max(len(delimiters) for _, delimiters in private)
    for ordinal in range(maximum_count):
        starts = [
            int(delimiters[ordinal]["start"])
            for _, delimiters in private
            if ordinal < len(delimiters)
        ]
        ordinal_spans.append(max(starts) - min(starts))
    sequences = {
        tuple(str(row["type"]) for row in delimiters)
        for _, delimiters in private
    }
    ff_phase_zero = all(
        int(row["start"]) % 3 == 0
        for _, delimiters in private
        for row in delimiters
        if row["type"] == "FF"
    )
    return {
        "schema": "phoenix-mmi.lod-fill-regions/v1",
        "analysis_mode": (
            "read-only-fixed-threshold-zero-and-ff-region-segmentation"
        ),
        "session": "056",
        "unique_source_count": len(rows),
        "thresholds": {
            "zero_run_minimum": _ZERO_RUN_THRESHOLD,
            "ff_run_minimum": _FF_RUN_THRESHOLD,
            "frozen_before_corpus_run": True,
        },
        "delimiter_sequence_count": len(sequences),
        "delimiter_position_spans_by_ordinal": ordinal_spans,
        "all_ff_delimiters_begin_at_phase_zero_modulo_3": ff_phase_zero,
        "sources": rows,
        "classification": {
            "fill_topology": (
                "REPEATABLE_ORDERED_DELIMITER_TOPOLOGY"
                if len(sequences) == 1
                else "DELIMITER_TOPOLOGY_DIFFERS"
            ),
            "semantic_region_roles": "UNRESOLVED",
        },
        "operational_graph_version": "v48",
        "publication_safety": _publication_safety(),
    }


def _block_set(data: bytes, size: int, shift: int) -> set[bytes]:
    return {
        hashlib.sha256(data[offset : offset + size]).digest()
        for offset in range(shift, len(data) - size + 1, size)
    }


def analyze_lod_grid_reuse(
    sources: list[dict[str, object]],
) -> dict[str, object]:
    materials = [data for _, data in _lod_rows(sources)]
    results = []
    for size in _GRID_SIZES:
        shifts = (0, size // 4, size // 2, (3 * size) // 4)
        shared_counts = []
        source_unique_ranges: list[list[int]] = [
            [] for _ in materials
        ]
        for shift in shifts:
            sets = [
                _block_set(data, size, shift) for data in materials
            ]
            shared_counts.append(len(set.intersection(*sets)))
            for index, values in enumerate(sets):
                source_unique_ranges[index].append(len(values))
        results.append(
            {
                "block_size": size,
                "fixed_shift_count": len(shifts),
                "shared_all_content_count": {
                    "minimum": min(shared_counts),
                    "maximum": max(shared_counts),
                    "mean": round(
                        sum(shared_counts) / len(shared_counts), 8
                    ),
                },
                "per_source_unique_content_count_ranges": [
                    {
                        "minimum": min(values),
                        "maximum": max(values),
                    }
                    for values in source_unique_ranges
                ],
            }
        )
    persists = all(
        int(row["shared_all_content_count"]["minimum"]) > 0
        for row in results
    )
    return {
        "schema": "phoenix-mmi.lod-grid-reuse/v1",
        "analysis_mode": (
            "read-only-fixed-block-size-quarter-shift-content-reuse"
        ),
        "session": "057",
        "unique_source_count": len(materials),
        "block_sizes": list(_GRID_SIZES),
        "shift_rule": "0, one-quarter, one-half, three-quarters",
        "results": results,
        "classification": {
            "cross_language_reuse": (
                "PERSISTS_ACROSS_ALL_FIXED_GRID_SIZES_AND_SHIFTS"
                if persists
                else "NOT_STABLE_ACROSS_FIXED_GRIDS"
            ),
            "reuse_interpretation": "CONTENT_RELATION_ONLY",
        },
        "operational_graph_version": "v49",
        "publication_safety": _publication_safety(),
    }


def _token_sets(data: bytes, width: int, phase: int) -> set[bytes]:
    return {
        data[offset : offset + width]
        for offset in range(phase, len(data) - width + 1, width)
    }


def analyze_lod_record_hypothesis(
    sources: list[dict[str, object]],
    session055: dict[str, object],
    session056: dict[str, object],
) -> dict[str, object]:
    if session055.get("schema") != (
        "phoenix-mmi.lod-alignment-census/v1"
    ):
        raise ValueError("unsupported Session 055 schema")
    if session056.get("schema") != "phoenix-mmi.lod-fill-regions/v1":
        raise ValueError("unsupported Session 056 schema")
    materials = [data for _, data in _lod_rows(sources)]
    phase_rows = []
    for phase in range(3):
        sets = [_token_sets(data, 3, phase) for data in materials]
        phase_rows.append(
            {
                "phase": phase,
                "shared_all_token_content_count": len(
                    set.intersection(*sets)
                ),
                "per_source_unique_token_count": [
                    len(values) for values in sets
                ],
            }
        )
    common_prefix = 0
    minimum = min(map(len, materials))
    while (
        common_prefix < minimum
        and len({data[common_prefix] for data in materials}) == 1
    ):
        common_prefix += 1
    delimiters = [_delimiter_rows(data) for data in materials]
    tests = {
        "common_prefix_is_exactly_three_bytes": common_prefix == 3,
        "phase_zero_common_byte_bias_exceeds_threshold": (
            session055["classification"]["global_alignment"]
            == "THREE_BYTE_PHASE_BIAS_OBSERVED"
        ),
        "all_ff_delimiters_start_at_phase_zero": bool(
            session056["all_ff_delimiters_begin_at_phase_zero_modulo_3"]
        ),
        "all_delimiter_lengths_are_three_byte_multiples": all(
            int(row["length"]) % 3 == 0
            for rows in delimiters
            for row in rows
        ),
        "phase_zero_has_maximum_shared_three_byte_tokens": (
            phase_rows[0]["shared_all_token_content_count"]
            == max(
                int(row["shared_all_token_content_count"])
                for row in phase_rows
            )
        ),
        "validated_record_header_present": False,
        "validated_address_or_length_fields_present": False,
    }
    return {
        "schema": "phoenix-mmi.lod-record-hypothesis/v1",
        "analysis_mode": (
            "read-only-predeclared-three-byte-alignment-falsification"
        ),
        "session": "058",
        "unique_source_count": len(materials),
        "candidate_record_width": 3,
        "fixed_test_count": len(tests),
        "supporting_test_count": sum(tests.values()),
        "contradicting_or_unresolved_test_count": sum(
            not value for value in tests.values()
        ),
        "tests": tests,
        "token_phase_results": phase_rows,
        "classification": {
            "three_byte_alignment": "SUPPORTED_AS_CANDIDATE",
            "three_byte_record_model": "NOT_ESTABLISHED",
            "address_model": "NOT_ESTABLISHED",
            "length_model": "NOT_ESTABLISHED",
        },
        "operational_graph_version": "v50",
        "publication_safety": _publication_safety(),
    }


def analyze_lod_shared_regions(
    sources: list[dict[str, object]],
) -> dict[str, object]:
    lods = _lod_rows(sources)
    materials = [data for _, data in lods]
    digest_rows = [
        [
            hashlib.sha256(data[offset : offset + _ATLAS_BLOCK_SIZE]).digest()
            for offset in range(
                0, len(data) - _ATLAS_BLOCK_SIZE + 1, _ATLAS_BLOCK_SIZE
            )
        ]
        for data in materials
    ]
    sets = [set(rows) for rows in digest_rows]
    common = set.intersection(*sets)
    samples: dict[bytes, bytes] = {}
    for data, digests in zip(materials, digest_rows):
        for index, digest in enumerate(digests):
            if digest in common and digest not in samples:
                start = index * _ATLAS_BLOCK_SIZE
                samples[digest] = data[start : start + _ATLAS_BLOCK_SIZE]
    content_classes = Counter()
    for data in samples.values():
        if len(set(data)) == 1:
            content_classes["homogeneous"] += 1
        elif _entropy(data) < 1.0:
            content_classes["low_entropy"] += 1
        else:
            content_classes["nontrivial"] += 1
    minimum_blocks = min(map(len, digest_rows))
    flags = [
        len({rows[index] for rows in digest_rows}) == 1
        for index in range(minimum_blocks)
    ]
    longest = current = 0
    for flag in flags:
        if flag:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    aligned_count = sum(flags)
    return {
        "schema": "phoenix-mmi.lod-shared-regions/v1",
        "analysis_mode": (
            "read-only-fixed-256-byte-shared-content-and-aligned-region-atlas"
        ),
        "session": "059",
        "unique_source_count": len(materials),
        "block_size": _ATLAS_BLOCK_SIZE,
        "shared_all_unique_content_count": len(common),
        "shared_content_classes": {
            "homogeneous": content_classes["homogeneous"],
            "low_entropy": content_classes["low_entropy"],
            "nontrivial": content_classes["nontrivial"],
        },
        "same_index_identical_block_count": aligned_count,
        "same_index_identical_bytes": (
            aligned_count * _ATLAS_BLOCK_SIZE
        ),
        "longest_consecutive_same_index_run_blocks": longest,
        "longest_consecutive_same_index_run_bytes": (
            longest * _ATLAS_BLOCK_SIZE
        ),
        "classification": {
            "shared_regions": "BOUNDED_ALIGNED_SHARED_REGIONS_CONFIRMED",
            "shared_content": "INCLUDES_NONTRIVIAL_BINARY_CONTENT",
            "single_monolithic_common_core": "NOT_ESTABLISHED",
            "record_decoder": "NOT_ESTABLISHED",
        },
        "operational_graph_version": "v51",
        "publication_safety": _publication_safety(),
    }

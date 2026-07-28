"""Bounded 2 KiB micro-atlas for the replicated Session 036 RZ-012 overlap."""

from __future__ import annotations

from collections import Counter
import copy
import re

from .binary import BinaryReader
from .superh import decode_instruction_extended


_DEFAULT_MICROBIN_SIZE = 256
_DEFAULT_PHASE_OFFSET = 128
_TILE_ID = re.compile(r"^G([0-9A-F]{4})-T([0-9]{3})$")


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _parse_shifted_tile(
    tile_id: str,
    *,
    lower: int,
    tile_size: int,
) -> dict[str, int]:
    match = _TILE_ID.fullmatch(tile_id)
    if match is None:
        raise ValueError("unsupported Session 036 tile identifier")
    grid_offset = int(match.group(1), 16)
    ordinal = int(match.group(2))
    if ordinal <= 0:
        raise ValueError("tile ordinal must be positive")
    start = lower + grid_offset + (ordinal - 1) * tile_size
    return {
        "grid_offset": grid_offset,
        "ordinal": ordinal,
        "start": start,
        "end": start + tile_size,
    }


def _validate_prior(prior: dict[str, object]) -> dict[str, object]:
    if prior.get("schema") != "phoenix-mmi.content-island-atlas/v1":
        raise ValueError("Session 036 content-island atlas is required")
    classification = prior.get("classification", {})
    if classification.get("island_atlas") != (
        "SPARSE_ONE_SIDED_SUPPORT_REPLICATED"
    ):
        raise ValueError("replicated sparse Session 036 support is required")
    if classification.get("multiple_interleaved_family_model") != (
        "CLOSED_BOUNDED_NEGATIVE"
    ):
        raise ValueError("Session 036 bounded-negative model is required")
    if classification.get("exact_section_boundary") != "OPEN":
        raise ValueError("Session 037 requires an open exact boundary")
    contract = prior.get("search_contract", {})
    lower = int(contract["envelope_lower"])
    upper = int(contract["envelope_upper"])
    tile_size = int(contract["tile_size"])
    if upper <= lower or tile_size != 4096:
        raise ValueError("invalid Session 036 atlas geometry")
    control = prior.get("grid_control", {})
    if control.get("classification") != (
        "REPLICATED_SPARSE_ONE_SIDED_SUPPORT"
    ):
        raise ValueError("Session 036 sparse grid control is required")
    pairs = control.get("overlap_pairs", [])
    if len(pairs) != 1 or pairs[0].get("assignment_equal") is not True:
        raise ValueError("exactly one agreeing overlap pair is required")
    primary_id = str(pairs[0]["primary_tile_id"])
    shifted_id = str(pairs[0]["shifted_tile_id"])
    primary_rows = [
        tile
        for tile in prior.get("tiles", [])
        if tile.get("tile_id") == primary_id
    ]
    if len(primary_rows) != 1:
        raise ValueError("primary overlap tile is missing")
    primary = primary_rows[0]
    if primary.get("assignment") != "LEFT_FAMILY":
        raise ValueError("primary overlap tile must support RZ-012")
    shifted = _parse_shifted_tile(
        shifted_id, lower=lower, tile_size=tile_size
    )
    if shifted["grid_offset"] != tile_size // 2:
        raise ValueError("shifted overlap tile must use half-tile grid")
    overlap_start = max(int(primary["start"]), shifted["start"])
    overlap_end = min(int(primary["end"]), shifted["end"])
    overlap_length = overlap_end - overlap_start
    if overlap_length != int(pairs[0]["overlap_length"]):
        raise ValueError("derived overlap differs from Session 036")
    if overlap_length != tile_size // 2:
        raise ValueError("Session 037 requires one exact 2 KiB overlap")
    return {
        "envelope_lower": lower,
        "envelope_upper": upper,
        "overlap_start": overlap_start,
        "overlap_end": overlap_end,
        "overlap_length": overlap_length,
        "primary_tile_id": primary_id,
        "shifted_tile_id": shifted_id,
        "left_delta": int(contract["left_delta"]),
        "right_delta": int(contract["right_delta"]),
        "left_zone_id": str(contract["left_zone_id"]),
        "right_zone_id": str(contract["right_zone_id"]),
    }


def _equal_runs(
    source: bytes,
    mapped: bytes,
    *,
    absolute_start: int,
    prefix: str,
) -> list[dict[str, object]]:
    runs = []
    index = 0
    while index < len(source):
        if source[index] != mapped[index]:
            index += 1
            continue
        start = index
        while index < len(source) and source[index] == mapped[index]:
            index += 1
        runs.append(
            {
                "run_id": f"{prefix}-RUN-{len(runs) + 1:03d}",
                "start": absolute_start + start,
                "end": absolute_start + index,
                "length": index - start,
            }
        )
    return runs


def _aligned_exact_units(
    source: bytes,
    mapped: bytes,
    *,
    absolute_start: int,
    unit_size: int,
) -> dict[str, object]:
    first = _align_up(absolute_start, unit_size)
    relative = first - absolute_start
    offsets = []
    while relative + unit_size <= len(source):
        if (
            source[relative : relative + unit_size]
            == mapped[relative : relative + unit_size]
        ):
            offsets.append(absolute_start + relative)
        relative += unit_size
    eligible = max(0, (len(source) - (first - absolute_start)) // unit_size)
    return {
        "alignment": unit_size,
        "eligible_unit_count": eligible,
        "exact_unit_count": len(offsets),
        "exact_unit_ratio": round(len(offsets) / max(1, eligible), 8),
        "exact_unit_offsets": offsets,
    }


def _microbins(
    source: bytes,
    mapped: bytes,
    *,
    absolute_start: int,
    bin_size: int,
    phase_offset: int,
    prefix: str,
) -> dict[str, object]:
    bins = []
    relative = phase_offset
    while relative + bin_size <= len(source):
        equal_count = sum(
            left == right
            for left, right in zip(
                source[relative : relative + bin_size],
                mapped[relative : relative + bin_size],
                strict=True,
            )
        )
        bins.append(
            {
                "bin_id": f"{prefix}-B{len(bins) + 1:02d}",
                "start": absolute_start + relative,
                "end": absolute_start + relative + bin_size,
                "length": bin_size,
                "equal_byte_count": equal_count,
                "equal_byte_ratio": round(equal_count / bin_size, 8),
            }
        )
        relative += bin_size
    total = sum(int(row["equal_byte_count"]) for row in bins)
    adjacent = []
    for index in range(max(0, len(bins) - 1)):
        count = (
            int(bins[index]["equal_byte_count"])
            + int(bins[index + 1]["equal_byte_count"])
        )
        adjacent.append(
            {
                "first_bin_id": bins[index]["bin_id"],
                "second_bin_id": bins[index + 1]["bin_id"],
                "equal_byte_count": count,
            }
        )
    maximum = max(
        (int(row["equal_byte_count"]) for row in adjacent), default=0
    )
    share = round(maximum / max(1, total), 8)
    clustered = total >= 64 and maximum * 2 >= total
    return {
        "bin_size": bin_size,
        "phase_offset": phase_offset,
        "covered_start": bins[0]["start"] if bins else None,
        "covered_end": bins[-1]["end"] if bins else None,
        "covered_equal_byte_count": total,
        "bins": bins,
        "maximum_adjacent_bin_equal_byte_count": maximum,
        "maximum_adjacent_bin_share": share,
        "minimum_equal_bytes_for_cluster": 64,
        "minimum_adjacent_share_for_cluster": 0.5,
        "classification": (
            "CLUSTERED_IN_TWO_ADJACENT_BINS"
            if clustered
            else "NOT_CLUSTERED_UNDER_FIXED_GATE"
        ),
    }


def _decoder_profile(
    source_reader: BinaryReader,
    mapped_reader: BinaryReader,
    *,
    source_start: int,
    source_end: int,
    delta: int,
) -> dict[str, object]:
    first = _align_up(source_start, 2)
    total = 0
    source_known = 0
    mapped_known = 0
    both_known = 0
    same_known_mnemonic = 0
    same_flow = 0
    mnemonic_pairs = Counter()
    for source_offset in range(first, source_end - 1, 2):
        mapped_offset = source_offset + delta
        source_instruction = decode_instruction_extended(
            source_reader, source_offset
        )
        mapped_instruction = decode_instruction_extended(
            mapped_reader, mapped_offset
        )
        total += 1
        source_is_known = source_instruction.mnemonic != "unknown"
        mapped_is_known = mapped_instruction.mnemonic != "unknown"
        source_known += source_is_known
        mapped_known += mapped_is_known
        if source_is_known and mapped_is_known:
            both_known += 1
            if source_instruction.mnemonic == mapped_instruction.mnemonic:
                same_known_mnemonic += 1
                mnemonic_pairs[source_instruction.mnemonic] += 1
            if source_instruction.flow == mapped_instruction.flow:
                same_flow += 1
    return {
        "aligned_halfword_count": total,
        "source_known_decoder_count": source_known,
        "mapped_known_decoder_count": mapped_known,
        "both_known_decoder_count": both_known,
        "same_known_mnemonic_count": same_known_mnemonic,
        "same_known_mnemonic_ratio": round(
            same_known_mnemonic / max(1, total), 8
        ),
        "same_flow_class_count": same_flow,
        "same_flow_class_ratio": round(same_flow / max(1, total), 8),
        "same_mnemonic_class_count": len(mnemonic_pairs),
        "mnemonic_names_included": False,
        "instruction_bytes_included": False,
        "code_execution_asserted": False,
    }


def _mapping_profile(
    source: bytes,
    mapped: bytes,
    source_reader: BinaryReader,
    mapped_reader: BinaryReader,
    *,
    absolute_start: int,
    delta: int,
    bin_size: int,
    label: str,
) -> dict[str, object]:
    equal_positions = [
        index
        for index, (left, right) in enumerate(
            zip(source, mapped, strict=True)
        )
        if left == right
    ]
    runs = _equal_runs(
        source,
        mapped,
        absolute_start=absolute_start,
        prefix=label,
    )
    run_lengths = [int(row["length"]) for row in runs]
    aligned_halfwords = _aligned_exact_units(
        source,
        mapped,
        absolute_start=absolute_start,
        unit_size=2,
    )
    aligned_words = _aligned_exact_units(
        source,
        mapped,
        absolute_start=absolute_start,
        unit_size=4,
    )
    phases = [
        _microbins(
            source,
            mapped,
            absolute_start=absolute_start,
            bin_size=bin_size,
            phase_offset=phase_offset,
            prefix=f"{label}-P{phase_offset:03d}",
        )
        for phase_offset in (0, bin_size // 2)
    ]
    phase_classes = [row["classification"] for row in phases]
    if all(
        value == "CLUSTERED_IN_TWO_ADJACENT_BINS"
        for value in phase_classes
    ):
        spatial = "CLUSTERED_PHASE_STABLE"
    elif all(
        value == "NOT_CLUSTERED_UNDER_FIXED_GATE"
        for value in phase_classes
    ):
        spatial = "DISTRIBUTED_PHASE_STABLE"
    else:
        spatial = "PHASE_SENSITIVE"
    decoder = _decoder_profile(
        source_reader,
        mapped_reader,
        source_start=absolute_start,
        source_end=absolute_start + len(source),
        delta=delta,
    )
    return {
        "equal_byte_count": len(equal_positions),
        "equal_byte_ratio": round(len(equal_positions) / len(source), 8),
        "distinct_equal_value_count": len(
            {source[index] for index in equal_positions}
        ),
        "run_count": len(runs),
        "maximum_run_length": max(run_lengths, default=0),
        "runs_at_least_2_bytes": sum(length >= 2 for length in run_lengths),
        "runs_at_least_4_bytes": sum(length >= 4 for length in run_lengths),
        "runs_at_least_8_bytes": sum(length >= 8 for length in run_lengths),
        "bytes_in_runs_at_least_2": sum(
            length for length in run_lengths if length >= 2
        ),
        "runs": runs,
        "aligned_halfwords": aligned_halfwords,
        "aligned_words": aligned_words,
        "microbin_phases": phases,
        "spatial_classification": spatial,
        "decoder_morphology": decoder,
    }


def _comparison_summary(
    left: dict[str, object],
    control: dict[str, object],
) -> dict[str, object]:
    left_count = int(left["equal_byte_count"])
    control_count = int(control["equal_byte_count"])
    byte_enriched = (
        left_count >= control_count * 4
        and left_count - control_count >= 64
    )
    left_decoder = int(
        left["decoder_morphology"]["same_known_mnemonic_count"]
    )
    control_decoder = int(
        control["decoder_morphology"]["same_known_mnemonic_count"]
    )
    decoder_enriched = (
        left_decoder >= control_decoder * 2
        and left_decoder - control_decoder >= 32
        and left_decoder >= 64
    )
    structured_signal = (
        left["spatial_classification"] == "CLUSTERED_PHASE_STABLE"
        or int(left["maximum_run_length"]) >= 8
        or float(left["aligned_words"]["exact_unit_ratio"]) >= 0.125
    )
    if byte_enriched and structured_signal:
        correspondence = "STRUCTURED_CORRESPONDENCE_SUPPORTED"
    elif byte_enriched:
        correspondence = "ENRICHED_BUT_SCATTERED"
    else:
        correspondence = "NOT_DISTINGUISHED_FROM_CONTROL"
    return {
        "left_equal_byte_count": left_count,
        "control_equal_byte_count": control_count,
        "equal_byte_count_difference": left_count - control_count,
        "minimum_enrichment_ratio": 4.0,
        "minimum_enrichment_difference": 64,
        "byte_equality_enrichment": (
            "CONFIRMED_UNDER_FIXED_CONTROL"
            if byte_enriched
            else "NOT_ESTABLISHED"
        ),
        "left_spatial_classification": left[
            "spatial_classification"
        ],
        "control_spatial_classification": control[
            "spatial_classification"
        ],
        "left_same_known_mnemonic_count": left_decoder,
        "control_same_known_mnemonic_count": control_decoder,
        "decoder_mnemonic_enrichment": (
            "ENRICHED_NOT_CODE_PROOF"
            if decoder_enriched
            else "NOT_ESTABLISHED"
        ),
        "structured_signal_gate_passed": structured_signal,
        "correspondence_classification": correspondence,
        "exact_boundary_asserted": False,
        "code_region_asserted": False,
    }


def update_operational_graph_v30(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v30"
    graph["nodes"].extend(
        [
            {
                "id": "reorder-rz012-micro-island",
                "status": comparison["classification"][
                    "micro_island_correspondence"
                ],
                "evidence": comparison["interpretation"],
            },
            {
                "id": "reorder-rz012-decoder-morphology",
                "status": comparison["classification"][
                    "sh_decoder_morphology"
                ],
                "semantic_status": "NOT_CODE_PROOF",
                "evidence": (
                    "Bounded SH decoder mnemonic coverage is morphology "
                    "only; instruction bytes and names are not published."
                ),
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-content-island-atlas",
                "target": "reorder-rz012-micro-island",
                "status": comparison["classification"][
                    "micro_island_correspondence"
                ],
                "relation": "bounds-overlapping-2k-neighborhood",
            },
            {
                "source": "reorder-rz012-micro-island",
                "target": "reorder-rz012-decoder-morphology",
                "status": comparison["classification"][
                    "sh_decoder_morphology"
                ],
                "relation": "profiles-decoder-shape-without-code-claim",
            },
        ]
    )
    return graph


def analyze_micro_island(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
    *,
    microbin_size: int = _DEFAULT_MICROBIN_SIZE,
) -> dict[str, object]:
    """Analyze only the replicated 2 KiB overlap from Session 036."""

    validated = _validate_prior(prior)
    if left_reader.sha256() != prior.get("left_artifact_sha256"):
        raise ValueError("left principal-image hash differs from Session 036")
    if right_reader.sha256() != prior.get("right_artifact_sha256"):
        raise ValueError(
            "right principal-image hash differs from Session 036"
        )
    if microbin_size < 64 or microbin_size % 4:
        raise ValueError("microbin size must be a multiple of four and >= 64")
    if validated["overlap_length"] % microbin_size:
        raise ValueError("microbin size must divide the overlap")
    start = validated["overlap_start"]
    length = validated["overlap_length"]
    source = left_reader.read(start, length)
    left_mapped = right_reader.read(
        start + validated["left_delta"], length
    )
    control_mapped = right_reader.read(
        start + validated["right_delta"], length
    )
    left_profile = _mapping_profile(
        source,
        left_mapped,
        left_reader,
        right_reader,
        absolute_start=start,
        delta=validated["left_delta"],
        bin_size=microbin_size,
        label="RZ012",
    )
    control_profile = _mapping_profile(
        source,
        control_mapped,
        left_reader,
        right_reader,
        absolute_start=start,
        delta=validated["right_delta"],
        bin_size=microbin_size,
        label="RZ013",
    )
    summary = _comparison_summary(left_profile, control_profile)
    classification = {
        "section_reorder_anchor": "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL",
        "sparse_rz012_island": "CONFIRMED_PRIOR_BYTE_LEVEL",
        "byte_equality_enrichment": summary[
            "byte_equality_enrichment"
        ],
        "micro_island_spatial_topology": left_profile[
            "spatial_classification"
        ],
        "micro_island_correspondence": summary[
            "correspondence_classification"
        ],
        "sh_decoder_morphology": summary[
            "decoder_mnemonic_enrichment"
        ],
        "exact_section_boundary": "OPEN",
        "runtime_loader_transform": "NOT_OBSERVED",
        "runtime_execution_observed": False,
    }
    return {
        "schema": "phoenix-mmi.micro-island-comparison/v1",
        "analysis_mode": (
            "read-only-static-bounded-2k-rz012-micro-island-with-rz013-control"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session036_schema": prior["schema"],
        "search_contract": {
            **validated,
            "microbin_size": microbin_size,
            "primary_phase_offset": 0,
            "shifted_phase_offset": microbin_size // 2,
            "natural_halfword_alignment": 2,
            "natural_word_alignment": 4,
            "byte_enrichment_minimum_ratio": 4.0,
            "byte_enrichment_minimum_difference": 64,
            "cluster_minimum_equal_bytes": 64,
            "cluster_minimum_adjacent_bin_share": 0.5,
            "decoder_enrichment_minimum_ratio": 2.0,
            "decoder_enrichment_minimum_difference": 32,
            "new_delta_search_performed": False,
            "whole_image_search_performed": False,
            "adaptive_threshold_used": False,
        },
        "rz012": left_profile,
        "rz013_negative_control": control_profile,
        "summary": summary,
        "classification": classification,
        "interpretation": (
            "The fixed micro-atlas distinguishes byte/run/word clustering "
            "from decoder morphology under RZ-012, using RZ-013 as the "
            "only negative mapped control. No result establishes code, "
            "section ownership, loader behavior or an exact boundary."
        ),
        "limits": [
            "Only the derived 2 KiB Session 036 overlap is read from CD1.",
            "Only RZ-012 and the prior RZ-013 negative mapping are read from CD3.",
            "Microbin and phase thresholds are fixed before artifact inspection.",
            "Decoder coverage is morphology and cannot establish executable code.",
            "Exact-byte runs prove local equality only at their listed offsets.",
            "No exact section or runtime boundary is inferred.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_overlap_bytes_included": False,
            "instruction_bytes_included": False,
            "mnemonic_names_included": False,
            "raw_strings_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def correlate_micro_island(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.micro-island-correlation/v1",
        "analysis_mode": comparison["analysis_mode"],
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_micro_island_edge": "NOT_ASSERTED",
        "interpretation": comparison["interpretation"],
        "operational_graph": update_operational_graph_v30(
            prior_correlation["operational_graph"], comparison
        ),
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_micro_island_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

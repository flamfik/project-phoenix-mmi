"""Fixed 4 KiB content-island atlas for the Session 035 envelope.

Session 036 keeps the two independently established file-layout deltas and
replaces a single-change assumption with non-overlapping fixed tiles.  Reports
contain aggregate metrics only; no firmware bytes or raw word values leave the
analyzer.
"""

from __future__ import annotations

from collections import Counter
import copy

from .binary import BinaryReader
from .entropy import shannon_entropy


_DEFAULT_TILE_SIZE = 4096
_DEFAULT_CONTROL_OFFSET = 2048
_MINIMUM_TERMINAL_FRACTION = 2

_EXACT_WORD = "EXACT_WORD_SUPPORTED"
_REPEATED_WORD_DELTA = "REPEATED_WORD_DELTA_CANDIDATE"
_BYTE_SIMILAR = "BYTE_SIMILAR_SUPPORTED"
_DISTRIBUTION_ONLY = "DISTRIBUTION_SIMILAR_ONLY"
_DIVERGENT = "DIVERGENT"

_LEFT = "LEFT_FAMILY"
_RIGHT = "RIGHT_FAMILY"
_BILATERAL = "BILATERAL_AMBIGUOUS"
_UNRESOLVED = "UNRESOLVED"

_SUPPORT_RANK = {
    _DIVERGENT: 0,
    _DISTRIBUTION_ONLY: 1,
    _BYTE_SIMILAR: 2,
    _REPEATED_WORD_DELTA: 3,
    _EXACT_WORD: 4,
}


def _ceil_fraction(length: int, denominator: int) -> int:
    return (length + denominator - 1) // denominator


def _validate_prior(prior: dict[str, object]) -> dict[str, object]:
    schema = "phoenix-mmi.dual-delta-similarity-comparison/v1"
    if prior.get("schema") != schema:
        raise ValueError("Session 035 dual-delta comparison is required")
    classification = prior.get("classification", {})
    if classification.get("single_dominance_change_model") != (
        "CLOSED_BOUNDED_NEGATIVE"
    ):
        raise ValueError("Session 035 bounded-negative model is required")
    if classification.get("grid_control") != (
        "REPLICATED_BOUNDED_NEGATIVE"
    ):
        raise ValueError("replicated Session 035 grid control is required")
    if classification.get("transition_envelope") != (
        "UNCHANGED_FROM_SESSION034"
    ):
        raise ValueError("unchanged Session 034 envelope is required")
    if classification.get("exact_section_boundary") != "OPEN":
        raise ValueError("Session 036 requires an open exact boundary")
    contract = prior.get("search_contract", {})
    lower = int(contract["envelope_lower"])
    upper = int(contract["envelope_upper"])
    width = int(contract["envelope_width"])
    if upper <= lower or upper - lower != width:
        raise ValueError("invalid Session 035 envelope")
    left_delta = int(contract["left_delta"])
    right_delta = int(contract["right_delta"])
    if left_delta == right_delta:
        raise ValueError("two distinct prior deltas are required")
    return {
        "lower": lower,
        "upper": upper,
        "width": width,
        "left_delta": left_delta,
        "right_delta": right_delta,
        "left_zone_id": str(contract["left_zone_id"]),
        "right_zone_id": str(contract["right_zone_id"]),
    }


def _validate_mapped_range(
    *,
    lower: int,
    upper: int,
    delta: int,
    image_size: int,
    label: str,
) -> None:
    if lower + delta < 0 or upper + delta > image_size:
        raise ValueError(f"{label} mapped envelope is outside CD3")


def _tile_geometry(
    lower: int,
    upper: int,
    *,
    tile_size: int,
    grid_offset: int,
) -> list[dict[str, object]]:
    start = lower + grid_offset
    tiles = []
    ordinal = 1
    while start + tile_size <= upper:
        tiles.append(
            {
                "tile_id": f"G{grid_offset:04X}-T{ordinal:03d}",
                "start": start,
                "end": start + tile_size,
                "length": tile_size,
                "terminal_partial": False,
            }
        )
        start += tile_size
        ordinal += 1
    remainder = upper - start
    if remainder >= tile_size // _MINIMUM_TERMINAL_FRACTION:
        tiles.append(
            {
                "tile_id": f"G{grid_offset:04X}-T{ordinal:03d}",
                "start": start,
                "end": upper,
                "length": remainder,
                "terminal_partial": True,
            }
        )
    if not tiles:
        raise ValueError("atlas grid contains no eligible tile")
    return tiles


def _byte_histogram(data: bytes) -> list[float]:
    counts = Counter(data)
    length = len(data)
    return [counts[value] / length for value in range(256)]


def _total_variation(left: bytes, right: bytes) -> float:
    left_histogram = _byte_histogram(left)
    right_histogram = _byte_histogram(right)
    return 0.5 * sum(
        abs(left_value - right_value)
        for left_value, right_value in zip(
            left_histogram, right_histogram, strict=True
        )
    )


def _word_difference_summary(
    left: bytes, right: bytes
) -> dict[str, object]:
    differences = Counter()
    word_count = min(len(left), len(right)) // 4
    exact_word_count = 0
    for index in range(word_count):
        start = index * 4
        left_word = int.from_bytes(left[start : start + 4], "big")
        right_word = int.from_bytes(right[start : start + 4], "big")
        if left_word == right_word:
            exact_word_count += 1
            continue
        differences[(right_word - left_word) & 0xFFFFFFFF] += 1
    unequal_word_count = word_count - exact_word_count
    dominant_count = (
        max(differences.values()) if differences else 0
    )
    repeated = (
        unequal_word_count >= 16
        and dominant_count >= 8
        and dominant_count * 8 >= unequal_word_count
    )
    return {
        "word_count": word_count,
        "exact_word4_count": exact_word_count,
        "exact_word4_ratio": round(
            exact_word_count / max(1, word_count), 8
        ),
        "unequal_word_count": unequal_word_count,
        "distinct_unequal_word_delta_count": len(differences),
        "dominant_unequal_word_delta_count": dominant_count,
        "dominant_unequal_word_delta_share": round(
            dominant_count / max(1, unequal_word_count), 8
        ),
        "dominant_unequal_word_delta_value_included": False,
        "repeated_word_delta_gate_passed": repeated,
    }


def _mapping_metrics(source: bytes, mapped: bytes) -> dict[str, object]:
    equal_values = set()
    equal_count = 0
    for source_byte, mapped_byte in zip(source, mapped, strict=True):
        if source_byte == mapped_byte:
            equal_count += 1
            equal_values.add(source_byte)
    word_summary = _word_difference_summary(source, mapped)
    source_entropy = shannon_entropy(source)
    mapped_entropy = shannon_entropy(mapped)
    entropy_delta = abs(source_entropy - mapped_entropy)
    variation = _total_variation(source, mapped)
    length = len(source)
    exact_word_gate = (
        int(word_summary["exact_word4_count"])
        >= _ceil_fraction(int(word_summary["word_count"]), 8)
        and len(equal_values) >= 8
    )
    byte_gate = (
        equal_count >= _ceil_fraction(length, 16)
        and len(equal_values) >= 16
    )
    repeated_word_gate = (
        word_summary["repeated_word_delta_gate_passed"]
        and equal_count >= _ceil_fraction(length, 16)
        and len(equal_values) >= 8
    )
    distribution_gate = entropy_delta <= 0.25 and variation <= 0.125
    if exact_word_gate:
        classification = _EXACT_WORD
    elif repeated_word_gate:
        classification = _REPEATED_WORD_DELTA
    elif byte_gate:
        classification = _BYTE_SIMILAR
    elif distribution_gate:
        classification = _DISTRIBUTION_ONLY
    else:
        classification = _DIVERGENT
    return {
        "equal_byte_count": equal_count,
        "equal_byte_ratio": round(equal_count / length, 8),
        "distinct_equal_value_count": len(equal_values),
        "source_entropy": round(source_entropy, 8),
        "mapped_entropy": round(mapped_entropy, 8),
        "absolute_entropy_delta": round(entropy_delta, 8),
        "byte_histogram_total_variation": round(variation, 8),
        "exact_word_gate_passed": exact_word_gate,
        "byte_similarity_gate_passed": byte_gate,
        "distribution_similarity_gate_passed": distribution_gate,
        **word_summary,
        "classification": classification,
    }


def _assignment(
    left_metrics: dict[str, object],
    right_metrics: dict[str, object],
) -> str:
    left_rank = _SUPPORT_RANK[str(left_metrics["classification"])]
    right_rank = _SUPPORT_RANK[str(right_metrics["classification"])]
    if left_rank < 2 and right_rank < 2:
        return _UNRESOLVED
    if left_rank == right_rank:
        return _BILATERAL
    return _LEFT if left_rank > right_rank else _RIGHT


def _tile_analysis(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    geometry: dict[str, object],
    *,
    left_delta: int,
    right_delta: int,
) -> dict[str, object]:
    start = int(geometry["start"])
    length = int(geometry["length"])
    source = left_reader.read(start, length)
    left_metrics = _mapping_metrics(
        source, right_reader.read(start + left_delta, length)
    )
    right_metrics = _mapping_metrics(
        source, right_reader.read(start + right_delta, length)
    )
    return {
        **copy.deepcopy(geometry),
        "left_delta_mapped_start": start + left_delta,
        "right_delta_mapped_start": start + right_delta,
        "left_mapping": left_metrics,
        "right_mapping": right_metrics,
        "assignment": _assignment(left_metrics, right_metrics),
    }


def _islands(tiles: list[dict[str, object]]) -> list[dict[str, object]]:
    islands = []
    for tile in tiles:
        assignment = str(tile["assignment"])
        if assignment not in (_LEFT, _RIGHT):
            continue
        if (
            islands
            and islands[-1]["assignment"] == assignment
            and int(islands[-1]["end"]) == int(tile["start"])
        ):
            islands[-1]["end"] = tile["end"]
            islands[-1]["length"] += int(tile["length"])
            islands[-1]["tile_count"] += 1
            islands[-1]["tile_ids"].append(tile["tile_id"])
            continue
        islands.append(
            {
                "island_id": f"ISL-{len(islands) + 1:03d}",
                "assignment": assignment,
                "start": tile["start"],
                "end": tile["end"],
                "length": tile["length"],
                "tile_count": 1,
                "tile_ids": [tile["tile_id"]],
            }
        )
    return islands


def _atlas_summary(tiles: list[dict[str, object]]) -> dict[str, object]:
    counts = Counter(str(tile["assignment"]) for tile in tiles)
    informative = [
        tile
        for tile in tiles
        if tile["assignment"] in (_LEFT, _RIGHT)
    ]
    changes = []
    previous = None
    for tile in informative:
        if previous is None:
            previous = tile
            continue
        if tile["assignment"] != previous["assignment"]:
            changes.append(
                {
                    "from_assignment": previous["assignment"],
                    "to_assignment": tile["assignment"],
                    "from_tile_id": previous["tile_id"],
                    "to_tile_id": tile["tile_id"],
                    "gap_start": previous["end"],
                    "gap_end": tile["start"],
                }
            )
        previous = tile
    has_left = counts[_LEFT] > 0
    has_right = counts[_RIGHT] > 0
    if has_left and has_right and len(changes) >= 3:
        topology = "MULTIPLE_INTERLEAVED_FAMILIES"
    elif has_left and has_right:
        topology = "MULTIPLE_ORDERED_FAMILIES"
    elif has_left or has_right:
        topology = "ONE_SIDED_FAMILY_SUPPORT"
    else:
        topology = "NO_FAMILY_SUPPORT"
    mapping_class_counts = {
        "left": dict(
            sorted(
                Counter(
                    str(tile["left_mapping"]["classification"])
                    for tile in tiles
                ).items()
            )
        ),
        "right": dict(
            sorted(
                Counter(
                    str(tile["right_mapping"]["classification"])
                    for tile in tiles
                ).items()
            )
        ),
    }
    repeated_word_tiles = {
        "left": sum(
            tile["left_mapping"]["classification"]
            == _REPEATED_WORD_DELTA
            for tile in tiles
        ),
        "right": sum(
            tile["right_mapping"]["classification"]
            == _REPEATED_WORD_DELTA
            for tile in tiles
        ),
    }
    return {
        "tile_count": len(tiles),
        "assignment_counts": {
            _LEFT: counts[_LEFT],
            _RIGHT: counts[_RIGHT],
            _BILATERAL: counts[_BILATERAL],
            _UNRESOLVED: counts[_UNRESOLVED],
        },
        "resolved_family_tile_count": counts[_LEFT] + counts[_RIGHT],
        "assignment_change_count": len(changes),
        "assignment_changes": changes,
        "islands": _islands(tiles),
        "mapping_classification_counts": mapping_class_counts,
        "repeated_word_delta_candidate_tile_counts": repeated_word_tiles,
        "topology": topology,
    }


def _overlap(left: dict[str, object], right: dict[str, object]) -> int:
    return max(
        0,
        min(int(left["end"]), int(right["end"]))
        - max(int(left["start"]), int(right["start"])),
    )


def compare_island_atlas_grid_control(
    primary: dict[str, object],
    shifted: dict[str, object],
) -> dict[str, object]:
    schema = "phoenix-mmi.content-island-atlas/v1"
    if primary.get("schema") != schema or shifted.get("schema") != schema:
        raise ValueError("content-island atlas schemas are required")
    if (
        primary["left_artifact_sha256"]
        != shifted["left_artifact_sha256"]
        or primary["right_artifact_sha256"]
        != shifted["right_artifact_sha256"]
    ):
        raise ValueError("atlas grid-control artifacts differ")
    primary_contract = primary["search_contract"]
    shifted_contract = shifted["search_contract"]
    invariant_keys = (
        "envelope_lower",
        "envelope_upper",
        "envelope_width",
        "left_delta",
        "right_delta",
        "tile_size",
        "minimum_terminal_tile_length",
        "thresholds",
    )
    if any(
        primary_contract[key] != shifted_contract[key]
        for key in invariant_keys
    ):
        raise ValueError("atlas grid-control contracts differ")
    tile_size = int(primary_contract["tile_size"])
    if int(primary_contract["grid_offset"]) != 0:
        raise ValueError("primary atlas grid must start at zero")
    if int(shifted_contract["grid_offset"]) != tile_size // 2:
        raise ValueError("control atlas grid must use a half-tile shift")
    overlap_rows = []
    for primary_tile in primary["tiles"]:
        if primary_tile["assignment"] not in (_LEFT, _RIGHT):
            continue
        for shifted_tile in shifted["tiles"]:
            if shifted_tile["assignment"] not in (_LEFT, _RIGHT):
                continue
            overlap_length = _overlap(primary_tile, shifted_tile)
            if overlap_length < tile_size // 2:
                continue
            overlap_rows.append(
                {
                    "primary_tile_id": primary_tile["tile_id"],
                    "shifted_tile_id": shifted_tile["tile_id"],
                    "overlap_length": overlap_length,
                    "assignment_equal": (
                        primary_tile["assignment"]
                        == shifted_tile["assignment"]
                    ),
                }
            )
    agreement_count = sum(
        row["assignment_equal"] for row in overlap_rows
    )
    agreement_ratio = round(
        agreement_count / max(1, len(overlap_rows)), 8
    )
    both_interleaved = (
        primary["summary"]["topology"]
        == shifted["summary"]["topology"]
        == "MULTIPLE_INTERLEAVED_FAMILIES"
    )
    replicated = (
        both_interleaved
        and len(overlap_rows) >= 4
        and agreement_count * 4 >= len(overlap_rows) * 3
    )
    sparse_one_sided = (
        primary["summary"]["topology"]
        == shifted["summary"]["topology"]
        == "ONE_SIDED_FAMILY_SUPPORT"
        and bool(overlap_rows)
        and agreement_count == len(overlap_rows)
    )
    if replicated:
        classification = "REPLICATED_MULTI_ISLAND_ATLAS"
    elif sparse_one_sided:
        classification = "REPLICATED_SPARSE_ONE_SIDED_SUPPORT"
    elif (
        primary["summary"]["topology"]
        == shifted["summary"]["topology"]
    ):
        classification = "REPLICATED_TOPOLOGY_WITHOUT_SPATIAL_GATE"
    else:
        classification = "GRID_SENSITIVE_TOPOLOGY"
    return {
        "schema": "phoenix-mmi.content-island-grid-control/v1",
        "primary_grid_offset": primary_contract["grid_offset"],
        "shifted_grid_offset": shifted_contract["grid_offset"],
        "primary_topology": primary["summary"]["topology"],
        "shifted_topology": shifted["summary"]["topology"],
        "resolved_overlap_pair_count": len(overlap_rows),
        "equal_assignment_overlap_pair_count": agreement_count,
        "assignment_agreement_ratio": agreement_ratio,
        "minimum_overlap_length": tile_size // 2,
        "minimum_pair_count_for_replication": 4,
        "minimum_agreement_ratio": 0.75,
        "overlap_pairs": overlap_rows,
        "classification": classification,
        "shifted_full_report_published": False,
    }


def update_operational_graph_v29(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v29"
    graph["nodes"].extend(
        [
            {
                "id": "reorder-content-island-atlas",
                "status": comparison["classification"]["island_atlas"],
                "evidence": comparison["interpretation"],
            },
            {
                "id": "reorder-word-difference-morphology",
                "status": comparison["classification"][
                    "repeated_word_delta_morphology"
                ],
                "semantic_status": "CANDIDATE_NOT_RELOCATION_PROOF",
                "evidence": (
                    "Repeated unequal-word differences are counted without "
                    "publishing values or assigning loader semantics."
                ),
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-dual-delta-similarity",
                "target": "reorder-content-island-atlas",
                "status": comparison["classification"]["island_atlas"],
                "relation": "replaces-single-change-with-fixed-atlas",
            },
            {
                "source": "reorder-content-island-atlas",
                "target": "reorder-word-difference-morphology",
                "status": comparison["classification"][
                    "repeated_word_delta_morphology"
                ],
                "relation": "classifies-anonymous-word-difference-pattern",
            },
        ]
    )
    return graph


def analyze_content_island_atlas(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
    *,
    tile_size: int = _DEFAULT_TILE_SIZE,
    grid_offset: int = 0,
) -> dict[str, object]:
    """Build one fixed-grid atlas inside the unchanged Session 034 envelope."""

    validated = _validate_prior(prior)
    if left_reader.sha256() != prior.get("left_artifact_sha256"):
        raise ValueError("left principal-image hash differs from Session 035")
    if right_reader.sha256() != prior.get("right_artifact_sha256"):
        raise ValueError(
            "right principal-image hash differs from Session 035"
        )
    if tile_size < 1024 or tile_size % 4:
        raise ValueError("tile size must be a multiple of four and >= 1024")
    if grid_offset < 0 or grid_offset >= tile_size:
        raise ValueError("grid offset must be in [0, tile_size)")
    for label, delta in (
        ("left delta", validated["left_delta"]),
        ("right delta", validated["right_delta"]),
    ):
        _validate_mapped_range(
            lower=validated["lower"],
            upper=validated["upper"],
            delta=delta,
            image_size=right_reader.size,
            label=label,
        )
    geometry = _tile_geometry(
        validated["lower"],
        validated["upper"],
        tile_size=tile_size,
        grid_offset=grid_offset,
    )
    tiles = [
        _tile_analysis(
            left_reader,
            right_reader,
            tile,
            left_delta=validated["left_delta"],
            right_delta=validated["right_delta"],
        )
        for tile in geometry
    ]
    summary = _atlas_summary(tiles)
    repeated_count = sum(
        summary["repeated_word_delta_candidate_tile_counts"].values()
    )
    classification = {
        "section_reorder_anchor": "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL",
        "single_dominance_change_model": "CLOSED_PRIOR_BOUNDED_NEGATIVE",
        "island_atlas": summary["topology"],
        "repeated_word_delta_morphology": (
            "CANDIDATES_OBSERVED"
            if repeated_count
            else "NOT_OBSERVED_UNDER_FIXED_MODEL"
        ),
        "transition_envelope": "UNCHANGED_FROM_SESSION034",
        "exact_section_boundary": "OPEN",
        "compile_link_layout_explanation": "CONSISTENT_NOT_PROVEN",
        "runtime_loader_transform": "NOT_OBSERVED",
        "runtime_execution_observed": False,
    }
    return {
        "schema": "phoenix-mmi.content-island-atlas/v1",
        "analysis_mode": (
            "read-only-static-bounded-fixed-4k-two-delta-island-atlas"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session035_schema": prior["schema"],
        "search_contract": {
            "envelope_lower": validated["lower"],
            "envelope_upper": validated["upper"],
            "envelope_width": validated["width"],
            "left_zone_id": validated["left_zone_id"],
            "right_zone_id": validated["right_zone_id"],
            "left_delta": validated["left_delta"],
            "right_delta": validated["right_delta"],
            "tile_size": tile_size,
            "grid_offset": grid_offset,
            "minimum_terminal_tile_length": tile_size // 2,
            "thresholds": {
                "exact_word_ratio": 0.125,
                "byte_similarity_ratio": 0.0625,
                "repeated_word_minimum_unequal_words": 16,
                "repeated_word_minimum_count": 8,
                "repeated_word_minimum_share": 0.125,
                "entropy_delta_maximum": 0.25,
                "histogram_total_variation_maximum": 0.125,
            },
            "new_delta_search_performed": False,
            "whole_image_search_performed": False,
            "adaptive_threshold_used": False,
        },
        "tiles": tiles,
        "summary": summary,
        "classification": classification,
        "interpretation": (
            "The fixed atlas reports local file-content support under only "
            "the two prior deltas. Tile families, anonymous repeated word "
            "differences and distribution similarity do not establish "
            "section ownership, relocation semantics or runtime behavior."
        ),
        "limits": [
            "Only the unchanged Session 034 envelope is read from CD1.",
            "Only two independently established mappings are read from CD3.",
            "Tiles are fixed and non-overlapping within each grid.",
            "A terminal partial tile is admitted only when at least 2 KiB.",
            "Distribution similarity is never treated as content identity.",
            "Repeated word differences are anonymous morphology, not relocation proof.",
            "No exact section or runtime boundary is inferred.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_tile_bytes_included": False,
            "raw_word_values_included": False,
            "dominant_word_delta_values_included": False,
            "raw_strings_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def finalize_content_island_atlas(
    primary: dict[str, object],
    shifted: dict[str, object],
) -> dict[str, object]:
    report = copy.deepcopy(primary)
    control = compare_island_atlas_grid_control(primary, shifted)
    report["grid_control"] = control
    report["classification"]["grid_control"] = control["classification"]
    if control["classification"] == "REPLICATED_MULTI_ISLAND_ATLAS":
        report["classification"]["island_atlas"] = (
            "REPLICATED_MULTIPLE_INTERLEAVED_FAMILIES"
        )
        report["interpretation"] = (
            "Both fixed grids support multiple interleaved file-content "
            "families under the two prior deltas and pass the spatial "
            "agreement gate. This is a bounded file-layout atlas, not an "
            "exact section map or runtime model."
        )
        report["classification"]["multiple_interleaved_family_model"] = (
            "SUPPORTED_UNDER_FIXED_ATLAS"
        )
    elif control["classification"] == (
        "REPLICATED_SPARSE_ONE_SIDED_SUPPORT"
    ):
        report["classification"]["island_atlas"] = (
            "SPARSE_ONE_SIDED_SUPPORT_REPLICATED"
        )
        report["classification"]["multiple_interleaved_family_model"] = (
            "CLOSED_BOUNDED_NEGATIVE"
        )
        report["interpretation"] = (
            "Both fixed grids find one overlapping RZ-012-supported tile "
            "and no RZ-013-supported tile. The multiple-interleaved-4-KiB "
            "model is closed as a bounded negative; sparse one-sided "
            "file-content support remains descriptive."
        )
    elif control["classification"] == (
        "REPLICATED_TOPOLOGY_WITHOUT_SPATIAL_GATE"
    ):
        report["classification"]["island_atlas"] = (
            "TOPOLOGY_REPLICATED_SPATIAL_GATE_NOT_MET"
        )
        report["classification"]["multiple_interleaved_family_model"] = (
            "INCONCLUSIVE"
        )
        report["interpretation"] = (
            "Both grids share one atlas topology, but resolved overlapping "
            "tiles do not pass the fixed spatial agreement gate. The result "
            "remains descriptive and the prior envelope is unchanged."
        )
    else:
        report["classification"]["island_atlas"] = (
            "INCONCLUSIVE_GRID_SENSITIVE"
        )
        report["classification"]["multiple_interleaved_family_model"] = (
            "INCONCLUSIVE"
        )
        report["interpretation"] = (
            "The origin and half-tile grids produce different atlas "
            "topologies. No multi-island model is promoted and the prior "
            "envelope remains unchanged."
        )
    return report


def correlate_content_island_atlas(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.content-island-atlas-correlation/v1",
        "analysis_mode": comparison["analysis_mode"],
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_island_edge": "NOT_ASSERTED",
        "interpretation": comparison["interpretation"],
        "operational_graph": update_operational_graph_v29(
            prior_correlation["operational_graph"], comparison
        ),
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_content_island_atlas_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

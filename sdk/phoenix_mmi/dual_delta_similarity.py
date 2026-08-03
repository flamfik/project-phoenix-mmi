"""Bounded dual-delta similarity profiling for the Session 034 envelope.

Session 035 compares each fixed CD1 window against exactly two CD3 locations:
the two independently established relocation deltas bounding RB-015.  It does
not search for additional deltas, decode code, or infer runtime behavior.
"""

from __future__ import annotations

import copy
from collections import Counter

from .binary import BinaryReader


_DEFAULT_WINDOW_SIZES = (256, 512, 1024)
_DEFAULT_STEP = 128
_DEFAULT_MATCH_NUMERATOR = 1
_DEFAULT_MATCH_DENOMINATOR = 16
_DEFAULT_ADVANTAGE_NUMERATOR = 1
_DEFAULT_ADVANTAGE_DENOMINATOR = 32
_DEFAULT_MINIMUM_DISTINCT_EXCLUSIVE_VALUES = 4

_LEFT = "LEFT_DELTA_DOMINANT"
_RIGHT = "RIGHT_DELTA_DOMINANT"
_AMBIGUOUS = "AMBIGUOUS"


def _ceil_ratio(length: int, numerator: int, denominator: int) -> int:
    return (length * numerator + denominator - 1) // denominator


def _validate_ratio(name: str, numerator: int, denominator: int) -> None:
    if denominator <= 0 or numerator <= 0 or numerator >= denominator:
        raise ValueError(f"{name} must be strictly between zero and one")


def _validate_prior(prior: dict[str, object]) -> dict[str, object]:
    if prior.get("schema") != "phoenix-mmi.exact-block-map-comparison/v1":
        raise ValueError("Session 034 exact-block comparison is required")
    classification = prior.get("classification", {})
    if classification.get("file_layout_reorder_exact_block_support") != (
        "CONFIRMED_AT_EXACT_BLOCKS"
    ):
        raise ValueError("bilateral exact-block support is required")
    if classification.get("strict_seed_control") != "CONFIRMED_STABLE":
        raise ValueError("stable Session 034 seed control is required")
    if classification.get("exact_section_boundary") != "OPEN":
        raise ValueError("Session 035 requires an open exact boundary")
    envelope = prior.get("transition_envelope", {})
    if envelope.get("classification") != "NARROWED_BY_EXACT_BLOCKS":
        raise ValueError("narrowed Session 034 envelope is required")
    if envelope.get("exact_breakpoint_asserted") is not False:
        raise ValueError("prior report must not assert an exact breakpoint")
    lower = int(envelope["narrowed_lower_bound"])
    upper = int(envelope["narrowed_upper_bound"])
    if upper <= lower or upper - lower != int(envelope["narrowed_width"]):
        raise ValueError("invalid Session 034 transition envelope")
    lanes = prior.get("lanes", [])
    if len(lanes) != 2:
        raise ValueError("exactly two Session 034 lanes are required")
    if [str(row["zone_id"]) for row in lanes] != ["RZ-012", "RZ-013"]:
        raise ValueError("RZ-012 and RZ-013 must retain their order")
    deltas = [int(row["expected_zone_delta"]) for row in lanes]
    if deltas[0] == deltas[1]:
        raise ValueError("two distinct relocation deltas are required")
    return {
        "lower": lower,
        "upper": upper,
        "width": upper - lower,
        "left_delta": deltas[0],
        "right_delta": deltas[1],
        "left_zone_id": str(lanes[0]["zone_id"]),
        "right_zone_id": str(lanes[1]["zone_id"]),
    }


def _validate_mapped_range(
    *,
    lower: int,
    upper: int,
    delta: int,
    image_size: int,
    label: str,
) -> None:
    mapped_lower = lower + delta
    mapped_upper = upper + delta
    if mapped_lower < 0 or mapped_upper > image_size:
        raise ValueError(f"{label} mapped envelope is outside CD3")


def _grid_starts(
    lower: int,
    upper: int,
    *,
    window_size: int,
    step: int,
    grid_offset: int,
) -> list[int]:
    first = lower + grid_offset
    if first + window_size > upper:
        return []
    return list(range(first, upper - window_size + 1, step))


def _longest_equal_run(left: bytes, right: bytes) -> int:
    best = 0
    current = 0
    for left_byte, right_byte in zip(left, right, strict=True):
        if left_byte == right_byte:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _mapping_metrics(left: bytes, right: bytes) -> dict[str, object]:
    equal_positions = [
        index
        for index, (left_byte, right_byte) in enumerate(
            zip(left, right, strict=True)
        )
        if left_byte == right_byte
    ]
    exact_words = sum(
        left[index : index + 4] == right[index : index + 4]
        for index in range(0, len(left) - 3, 4)
    )
    return {
        "equal_byte_count": len(equal_positions),
        "equal_byte_ratio": round(len(equal_positions) / len(left), 8),
        "distinct_equal_value_count": len(
            {left[index] for index in equal_positions}
        ),
        "exact_word4_count": exact_words,
        "exact_word4_ratio": round(
            exact_words / max(1, len(left) // 4), 8
        ),
        "longest_equal_byte_run": _longest_equal_run(left, right),
    }


def _window_metrics(
    left: bytes,
    left_mapped: bytes,
    right_mapped: bytes,
) -> dict[str, object]:
    left_metrics = _mapping_metrics(left, left_mapped)
    right_metrics = _mapping_metrics(left, right_mapped)
    left_exclusive_values = set()
    right_exclusive_values = set()
    left_exclusive = 0
    right_exclusive = 0
    for source, first, second in zip(
        left, left_mapped, right_mapped, strict=True
    ):
        first_equal = source == first
        second_equal = source == second
        if first_equal and not second_equal:
            left_exclusive += 1
            left_exclusive_values.add(source)
        elif second_equal and not first_equal:
            right_exclusive += 1
            right_exclusive_values.add(source)
    return {
        "left_delta": left_metrics,
        "right_delta": right_metrics,
        "left_exclusive_equal_byte_count": left_exclusive,
        "right_exclusive_equal_byte_count": right_exclusive,
        "left_distinct_exclusive_value_count": len(left_exclusive_values),
        "right_distinct_exclusive_value_count": len(right_exclusive_values),
    }


def _classify_window(
    metrics: dict[str, object],
    *,
    window_size: int,
    match_numerator: int,
    match_denominator: int,
    advantage_numerator: int,
    advantage_denominator: int,
    minimum_distinct_exclusive_values: int,
) -> str:
    minimum_match = _ceil_ratio(
        window_size, match_numerator, match_denominator
    )
    minimum_advantage = _ceil_ratio(
        window_size, advantage_numerator, advantage_denominator
    )
    left_count = int(metrics["left_delta"]["equal_byte_count"])
    right_count = int(metrics["right_delta"]["equal_byte_count"])
    left_distinct = int(
        metrics["left_distinct_exclusive_value_count"]
    )
    right_distinct = int(
        metrics["right_distinct_exclusive_value_count"]
    )
    if (
        left_count >= minimum_match
        and left_count - right_count >= minimum_advantage
        and left_distinct >= minimum_distinct_exclusive_values
    ):
        return _LEFT
    if (
        right_count >= minimum_match
        and right_count - left_count >= minimum_advantage
        and right_distinct >= minimum_distinct_exclusive_values
    ):
        return _RIGHT
    return _AMBIGUOUS


def _profile_runs(windows: list[dict[str, object]]) -> list[dict[str, object]]:
    runs = []
    for row in windows:
        classification = str(row["classification"])
        if runs and runs[-1]["classification"] == classification:
            runs[-1]["last_window_start"] = row["left_start"]
            runs[-1]["last_window_end"] = row["left_end"]
            runs[-1]["last_center"] = row["center"]
            runs[-1]["window_count"] += 1
            continue
        runs.append(
            {
                "classification": classification,
                "first_window_start": row["left_start"],
                "last_window_start": row["left_start"],
                "first_window_end": row["left_end"],
                "last_window_end": row["left_end"],
                "first_center": row["center"],
                "last_center": row["center"],
                "window_count": 1,
            }
        )
    return runs


def _crossings(windows: list[dict[str, object]]) -> list[dict[str, object]]:
    informative = [
        row for row in windows if row["classification"] != _AMBIGUOUS
    ]
    crossings = []
    previous = None
    for row in informative:
        if previous is None:
            previous = row
            continue
        if row["classification"] == previous["classification"]:
            previous = row
            continue
        direction = (
            "LEFT_TO_RIGHT"
            if previous["classification"] == _LEFT
            and row["classification"] == _RIGHT
            else "RIGHT_TO_LEFT"
        )
        crossings.append(
            {
                "direction": direction,
                "from_center": previous["center"],
                "to_center": row["center"],
                "lower_center": min(
                    int(previous["center"]), int(row["center"])
                ),
                "upper_center": max(
                    int(previous["center"]), int(row["center"])
                ),
                "center_gap": abs(
                    int(row["center"]) - int(previous["center"])
                ),
            }
        )
        previous = row
    return crossings


def _profile_summary(
    windows: list[dict[str, object]], *, window_size: int
) -> dict[str, object]:
    counts = Counter(str(row["classification"]) for row in windows)
    crossings = _crossings(windows)
    forward = [
        row for row in crossings if row["direction"] == "LEFT_TO_RIGHT"
    ]
    reverse = [
        row for row in crossings if row["direction"] == "RIGHT_TO_LEFT"
    ]
    informative = [
        row for row in windows if row["classification"] != _AMBIGUOUS
    ]
    single_forward = (
        len(forward) == 1
        and not reverse
        and informative
        and informative[0]["classification"] == _LEFT
        and informative[-1]["classification"] == _RIGHT
    )
    if single_forward:
        classification = "SINGLE_FORWARD_DOMINANCE_CHANGE"
    elif not informative:
        classification = "NO_DOMINANT_WINDOWS"
    elif not crossings:
        classification = "ONE_SIDED_DOMINANCE_ONLY"
    else:
        classification = "MULTIPLE_OR_REVERSED_DOMINANCE_CHANGES"
    return {
        "window_size": window_size,
        "window_count": len(windows),
        "classification_counts": {
            _LEFT: counts[_LEFT],
            _RIGHT: counts[_RIGHT],
            _AMBIGUOUS: counts[_AMBIGUOUS],
        },
        "first_informative_classification": (
            informative[0]["classification"] if informative else None
        ),
        "last_informative_classification": (
            informative[-1]["classification"] if informative else None
        ),
        "crossings": crossings,
        "forward_crossing_count": len(forward),
        "reverse_crossing_count": len(reverse),
        "classification": classification,
        "runs": _profile_runs(windows),
    }


def _multiscale_summary(
    profiles: list[dict[str, object]],
) -> dict[str, object]:
    stable_profiles = [
        row
        for row in profiles
        if row["summary"]["classification"]
        == "SINGLE_FORWARD_DOMINANCE_CHANGE"
    ]
    bands = [
        row["summary"]["crossings"][0] for row in stable_profiles
    ]
    all_stable = len(stable_profiles) == len(profiles) and bool(profiles)
    if bands:
        hull_lower = min(int(row["lower_center"]) for row in bands)
        hull_upper = max(int(row["upper_center"]) for row in bands)
        intersection_lower = max(
            int(row["lower_center"]) for row in bands
        )
        intersection_upper = min(
            int(row["upper_center"]) for row in bands
        )
        bands_intersect = intersection_lower <= intersection_upper
    else:
        hull_lower = None
        hull_upper = None
        intersection_lower = None
        intersection_upper = None
        bands_intersect = False
    if all_stable and bands_intersect:
        classification = "REPRODUCIBLE_MULTISCALE_DOMINANCE_CHANGE"
    elif all_stable:
        classification = "DIRECTION_STABLE_LOCATION_DISPERSED"
    else:
        classification = "NOT_STABLE_ACROSS_WINDOW_SIZES"
    return {
        "tested_window_size_count": len(profiles),
        "single_forward_change_profile_count": len(stable_profiles),
        "all_window_sizes_single_forward": all_stable,
        "crossing_bands_intersect": bands_intersect,
        "crossing_hull_lower": hull_lower,
        "crossing_hull_upper": hull_upper,
        "crossing_hull_width": (
            hull_upper - hull_lower if bands else None
        ),
        "crossing_intersection_lower": intersection_lower,
        "crossing_intersection_upper": intersection_upper,
        "crossing_intersection_width": (
            intersection_upper - intersection_lower
            if bands_intersect
            else None
        ),
        "exact_breakpoint_asserted": False,
        "classification": classification,
    }


def _one_profile(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    *,
    lower: int,
    upper: int,
    left_delta: int,
    right_delta: int,
    window_size: int,
    step: int,
    grid_offset: int,
    match_numerator: int,
    match_denominator: int,
    advantage_numerator: int,
    advantage_denominator: int,
    minimum_distinct_exclusive_values: int,
) -> dict[str, object]:
    windows = []
    for start in _grid_starts(
        lower,
        upper,
        window_size=window_size,
        step=step,
        grid_offset=grid_offset,
    ):
        source = left_reader.read(start, window_size)
        left_start = start + left_delta
        right_start = start + right_delta
        metrics = _window_metrics(
            source,
            right_reader.read(left_start, window_size),
            right_reader.read(right_start, window_size),
        )
        classification = _classify_window(
            metrics,
            window_size=window_size,
            match_numerator=match_numerator,
            match_denominator=match_denominator,
            advantage_numerator=advantage_numerator,
            advantage_denominator=advantage_denominator,
            minimum_distinct_exclusive_values=(
                minimum_distinct_exclusive_values
            ),
        )
        windows.append(
            {
                "left_start": start,
                "left_end": start + window_size,
                "center": start + window_size // 2,
                "left_delta_mapped_start": left_start,
                "right_delta_mapped_start": right_start,
                "classification": classification,
                "metrics": metrics,
            }
        )
    if not windows:
        raise ValueError("profile grid contains no complete window")
    return {
        "window_size": window_size,
        "step": step,
        "grid_offset": grid_offset,
        "windows": windows,
        "summary": _profile_summary(windows, window_size=window_size),
    }


def update_operational_graph_v28(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v28"
    multiscale = comparison["multiscale"]
    graph["nodes"].extend(
        [
            {
                "id": "reorder-dual-delta-similarity",
                "status": multiscale["classification"],
                "evidence": comparison["interpretation"],
            },
            {
                "id": "reorder-similarity-transition",
                "status": comparison["classification"][
                    "similarity_transition"
                ],
                "exact_boundary": False,
                "evidence": (
                    "Fixed two-delta profiles measure file-byte "
                    "correspondence only; no section or runtime boundary "
                    "is asserted."
                ),
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-exact-block-map",
                "target": "reorder-dual-delta-similarity",
                "status": multiscale["classification"],
                "relation": "bounds-two-delta-profile",
            },
            {
                "source": "reorder-dual-delta-similarity",
                "target": "reorder-similarity-transition",
                "status": comparison["classification"][
                    "similarity_transition"
                ],
                "relation": "locates-non-exact-dominance-change",
            },
        ]
    )
    return graph


def analyze_dual_delta_similarity(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
    *,
    window_sizes: tuple[int, ...] = _DEFAULT_WINDOW_SIZES,
    step: int = _DEFAULT_STEP,
    grid_offset: int = 0,
    match_numerator: int = _DEFAULT_MATCH_NUMERATOR,
    match_denominator: int = _DEFAULT_MATCH_DENOMINATOR,
    advantage_numerator: int = _DEFAULT_ADVANTAGE_NUMERATOR,
    advantage_denominator: int = _DEFAULT_ADVANTAGE_DENOMINATOR,
    minimum_distinct_exclusive_values: int = (
        _DEFAULT_MINIMUM_DISTINCT_EXCLUSIVE_VALUES
    ),
) -> dict[str, object]:
    """Compare the open envelope under exactly two prior relocation deltas."""

    validated = _validate_prior(prior)
    if left_reader.sha256() != prior.get("left_artifact_sha256"):
        raise ValueError("left principal-image hash differs from Session 034")
    if right_reader.sha256() != prior.get("right_artifact_sha256"):
        raise ValueError(
            "right principal-image hash differs from Session 034"
        )
    if not window_sizes or len(set(window_sizes)) != len(window_sizes):
        raise ValueError("window sizes must be non-empty and unique")
    if any(size < 64 or size % 4 for size in window_sizes):
        raise ValueError("window sizes must be multiples of four and >= 64")
    if tuple(sorted(window_sizes)) != window_sizes:
        raise ValueError("window sizes must be strictly increasing")
    if step <= 0 or step > min(window_sizes):
        raise ValueError("step must be positive and no larger than a window")
    if grid_offset < 0 or grid_offset >= step:
        raise ValueError("grid offset must be in [0, step)")
    _validate_ratio(
        "minimum match ratio", match_numerator, match_denominator
    )
    _validate_ratio(
        "minimum advantage ratio",
        advantage_numerator,
        advantage_denominator,
    )
    if minimum_distinct_exclusive_values <= 0:
        raise ValueError("minimum distinct exclusive values must be positive")
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
    profiles = [
        _one_profile(
            left_reader,
            right_reader,
            lower=validated["lower"],
            upper=validated["upper"],
            left_delta=validated["left_delta"],
            right_delta=validated["right_delta"],
            window_size=window_size,
            step=step,
            grid_offset=grid_offset,
            match_numerator=match_numerator,
            match_denominator=match_denominator,
            advantage_numerator=advantage_numerator,
            advantage_denominator=advantage_denominator,
            minimum_distinct_exclusive_values=(
                minimum_distinct_exclusive_values
            ),
        )
        for window_size in window_sizes
    ]
    multiscale = _multiscale_summary(profiles)
    similarity_transition = (
        "LOCATED_AS_NON_EXACT_MULTISCALE_BAND"
        if multiscale["classification"]
        == "REPRODUCIBLE_MULTISCALE_DOMINANCE_CHANGE"
        else "NOT_STABLE"
    )
    classification = {
        "section_reorder_anchor": "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL",
        "exact_block_support": "CONFIRMED_PRIOR_AT_EXACT_BLOCKS",
        "dual_delta_profile": multiscale["classification"],
        "similarity_transition": similarity_transition,
        "exact_section_boundary": "OPEN",
        "compile_link_layout_explanation": "CONSISTENT_NOT_PROVEN",
        "runtime_loader_transform": "NOT_OBSERVED",
        "runtime_execution_observed": False,
    }
    interpretation = (
        "All fixed window sizes show one left-to-right change between "
        "the two independently established file-layout deltas, and their "
        "crossing bands overlap. This locates a reproducible similarity "
        "transition but does not establish an exact section boundary."
        if similarity_transition
        == "LOCATED_AS_NON_EXACT_MULTISCALE_BAND"
        else (
            "The fixed two-delta profiles do not produce one overlapping "
            "multiscale dominance transition. Session 034 exact-block "
            "bounds remain authoritative."
        )
    )
    return {
        "schema": "phoenix-mmi.dual-delta-similarity-comparison/v1",
        "analysis_mode": (
            "read-only-static-bounded-fixed-two-delta-similarity-profile"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session034_schema": prior["schema"],
        "search_contract": {
            "envelope_lower": validated["lower"],
            "envelope_upper": validated["upper"],
            "envelope_width": validated["width"],
            "left_zone_id": validated["left_zone_id"],
            "right_zone_id": validated["right_zone_id"],
            "left_delta": validated["left_delta"],
            "right_delta": validated["right_delta"],
            "window_sizes": list(window_sizes),
            "step": step,
            "grid_offset": grid_offset,
            "minimum_match_ratio": {
                "numerator": match_numerator,
                "denominator": match_denominator,
            },
            "minimum_advantage_ratio": {
                "numerator": advantage_numerator,
                "denominator": advantage_denominator,
            },
            "minimum_distinct_exclusive_values": (
                minimum_distinct_exclusive_values
            ),
            "new_delta_search_performed": False,
            "whole_image_search_performed": False,
            "adaptive_threshold_used": False,
        },
        "profiles": profiles,
        "multiscale": multiscale,
        "classification": classification,
        "interpretation": interpretation,
        "limits": [
            "Only the Session 034 open envelope is read from CD1.",
            "Only the two prior relocation deltas are read from CD3.",
            "The fixed thresholds are descriptive gates, not a decoded format.",
            "Window overlap introduces scale-dependent spatial uncertainty.",
            "Similarity can reflect shared bytes without semantic ownership.",
            "A dominance crossing is not an exact section boundary.",
            "Compile/link placement and loader transformation remain unresolved.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_window_bytes_included": False,
            "raw_strings_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def compare_similarity_grid_control(
    primary: dict[str, object],
    shifted: dict[str, object],
) -> dict[str, object]:
    """Compare an origin grid with one shifted by half a fixed step."""

    schema = "phoenix-mmi.dual-delta-similarity-comparison/v1"
    if primary.get("schema") != schema or shifted.get("schema") != schema:
        raise ValueError("dual-delta similarity schemas are required")
    if (
        primary["left_artifact_sha256"]
        != shifted["left_artifact_sha256"]
        or primary["right_artifact_sha256"]
        != shifted["right_artifact_sha256"]
    ):
        raise ValueError("grid-control artifacts differ")
    primary_contract = primary["search_contract"]
    shifted_contract = shifted["search_contract"]
    invariant_keys = (
        "envelope_lower",
        "envelope_upper",
        "envelope_width",
        "left_delta",
        "right_delta",
        "window_sizes",
        "step",
        "minimum_match_ratio",
        "minimum_advantage_ratio",
        "minimum_distinct_exclusive_values",
    )
    if any(
        primary_contract[key] != shifted_contract[key]
        for key in invariant_keys
    ):
        raise ValueError("grid-control contracts differ")
    if int(primary_contract["grid_offset"]) != 0:
        raise ValueError("primary grid must start at offset zero")
    expected_shift = int(primary_contract["step"]) // 2
    if int(shifted_contract["grid_offset"]) != expected_shift:
        raise ValueError("control grid must be shifted by half one step")
    primary_band = primary["multiscale"]
    shifted_band = shifted["multiscale"]
    both_multiscale = (
        primary_band["classification"]
        == shifted_band["classification"]
        == "REPRODUCIBLE_MULTISCALE_DOMINANCE_CHANGE"
    )
    if both_multiscale:
        overlap_lower = max(
            int(primary_band["crossing_hull_lower"]),
            int(shifted_band["crossing_hull_lower"]),
        )
        overlap_upper = min(
            int(primary_band["crossing_hull_upper"]),
            int(shifted_band["crossing_hull_upper"]),
        )
        hulls_overlap = overlap_lower <= overlap_upper
    else:
        overlap_lower = None
        overlap_upper = None
        hulls_overlap = False
    profile_rows = []
    for primary_profile, shifted_profile in zip(
        primary["profiles"], shifted["profiles"], strict=True
    ):
        if primary_profile["window_size"] != shifted_profile["window_size"]:
            raise ValueError("grid-control window-size order differs")
        primary_summary = primary_profile["summary"]
        shifted_summary = shifted_profile["summary"]
        profile_rows.append(
            {
                "window_size": primary_profile["window_size"],
                "primary": {
                    "classification": primary_summary["classification"],
                    "classification_counts": copy.deepcopy(
                        primary_summary["classification_counts"]
                    ),
                    "forward_crossing_count": primary_summary[
                        "forward_crossing_count"
                    ],
                    "reverse_crossing_count": primary_summary[
                        "reverse_crossing_count"
                    ],
                },
                "shifted": {
                    "classification": shifted_summary["classification"],
                    "classification_counts": copy.deepcopy(
                        shifted_summary["classification_counts"]
                    ),
                    "forward_crossing_count": shifted_summary[
                        "forward_crossing_count"
                    ],
                    "reverse_crossing_count": shifted_summary[
                        "reverse_crossing_count"
                    ],
                },
            }
        )
    replicated_negative = (
        primary_band["classification"]
        == shifted_band["classification"]
        == "NOT_STABLE_ACROSS_WINDOW_SIZES"
        and all(
            row["primary"]["classification"]
            == row["shifted"]["classification"]
            for row in profile_rows
        )
    )
    if both_multiscale and hulls_overlap:
        control_classification = "CONFIRMED_POSITIVE_GRID_STABLE"
    elif replicated_negative:
        control_classification = "REPLICATED_BOUNDED_NEGATIVE"
    else:
        control_classification = "NOT_GRID_STABLE"
    return {
        "schema": "phoenix-mmi.dual-delta-grid-control/v1",
        "primary_grid_offset": primary_contract["grid_offset"],
        "shifted_grid_offset": shifted_contract["grid_offset"],
        "same_fixed_contract_except_grid_offset": True,
        "primary_multiscale_classification": primary_band[
            "classification"
        ],
        "shifted_multiscale_classification": shifted_band[
            "classification"
        ],
        "profiles": profile_rows,
        "both_grids_multiscale": both_multiscale,
        "negative_topology_replicated": replicated_negative,
        "crossing_hulls_overlap": hulls_overlap,
        "overlap_lower": overlap_lower,
        "overlap_upper": overlap_upper,
        "overlap_width": (
            overlap_upper - overlap_lower if hulls_overlap else None
        ),
        "classification": control_classification,
        "shifted_full_report_published": False,
    }


def finalize_dual_delta_similarity(
    primary: dict[str, object],
    shifted: dict[str, object],
) -> dict[str, object]:
    """Attach the half-step control and close only the declared model."""

    report = copy.deepcopy(primary)
    control = compare_similarity_grid_control(primary, shifted)
    report["grid_control"] = control
    report["classification"]["grid_control"] = control["classification"]
    if control["classification"] == "CONFIRMED_POSITIVE_GRID_STABLE":
        report["classification"]["single_dominance_change_model"] = (
            "SUPPORTED_UNDER_FIXED_PROFILE"
        )
        report["classification"]["transition_envelope"] = (
            "LOCATED_AS_NON_EXACT_SIMILARITY_BAND"
        )
        report["interpretation"] = (
            "The origin and half-step grids reproduce one overlapping "
            "multiscale left-to-right dominance change under the two prior "
            "file-layout deltas. This is a similarity band, not an exact "
            "section or runtime boundary."
        )
    elif control["classification"] == "REPLICATED_BOUNDED_NEGATIVE":
        report["classification"]["single_dominance_change_model"] = (
            "CLOSED_BOUNDED_NEGATIVE"
        )
        report["classification"]["similarity_transition"] = (
            "NOT_LOCATED_UNDER_FIXED_MODEL"
        )
        report["classification"]["transition_envelope"] = (
            "UNCHANGED_FROM_SESSION034"
        )
        report["interpretation"] = (
            "Neither the origin nor half-step grid produces one stable "
            "multiscale left-to-right dominance change. The fixed "
            "two-delta single-transition model is closed as a bounded "
            "negative; the Session 034 envelope remains authoritative."
        )
    else:
        report["classification"]["single_dominance_change_model"] = (
            "INCONCLUSIVE"
        )
        report["classification"]["similarity_transition"] = (
            "NOT_LOCATED_UNDER_FIXED_MODEL"
        )
        report["classification"]["transition_envelope"] = (
            "UNCHANGED_FROM_SESSION034"
        )
        report["interpretation"] = (
            "The origin and half-step grids do not reproduce the same "
            "positive or negative topology. The fixed two-delta model is "
            "inconclusive and the Session 034 envelope remains "
            "authoritative."
        )
    return report


def correlate_dual_delta_similarity(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.dual-delta-similarity-correlation/v1",
        "analysis_mode": comparison["analysis_mode"],
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_similarity_edge": "NOT_ASSERTED",
        "interpretation": comparison["interpretation"],
        "operational_graph": update_operational_graph_v28(
            prior_correlation["operational_graph"], comparison
        ),
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_dual_delta_similarity_report(
    report: dict[str, object],
) -> dict[str, object]:
    """Return a detached report without per-window metric samples."""

    public = copy.deepcopy(report)
    for profile in public.get("profiles", []):
        profile.pop("windows", None)
    return public

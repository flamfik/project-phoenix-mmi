"""Bounded run-gap topology for the Session 037 RZ-012 micro-island."""

from __future__ import annotations

from collections import Counter
import copy

from .binary import BinaryReader


_PRIMARY_GAP_CAP = 1
_RELAXED_GAP_CAP = 2
_MINIMUM_COMPONENT_SPAN = 64
_MINIMUM_COMPONENT_RUNS = 4
_MINIMUM_COMPONENT_EQUAL_BYTES = 64
_MINIMUM_COMPONENT_COVERAGE = 0.75
_MINIMUM_PERIOD_SHARE = 0.75


def _validate_prior(prior: dict[str, object]) -> dict[str, object]:
    if prior.get("schema") != "phoenix-mmi.micro-island-comparison/v1":
        raise ValueError("Session 037 micro-island comparison is required")
    classification = prior.get("classification", {})
    if classification.get("micro_island_correspondence") != (
        "STRUCTURED_CORRESPONDENCE_SUPPORTED"
    ):
        raise ValueError("structured Session 037 correspondence is required")
    if classification.get("byte_equality_enrichment") != (
        "CONFIRMED_UNDER_FIXED_CONTROL"
    ):
        raise ValueError("Session 037 equality enrichment is required")
    if classification.get("micro_island_spatial_topology") != (
        "CLUSTERED_PHASE_STABLE"
    ):
        raise ValueError("phase-stable Session 037 cluster is required")
    if classification.get("exact_section_boundary") != "OPEN":
        raise ValueError("Session 038 requires an open exact boundary")
    contract = prior.get("search_contract", {})
    start = int(contract["overlap_start"])
    end = int(contract["overlap_end"])
    length = int(contract["overlap_length"])
    if end - start != length or length != 2048:
        raise ValueError("Session 038 requires the exact prior 2 KiB overlap")
    return {
        "overlap_start": start,
        "overlap_end": end,
        "overlap_length": length,
        "left_delta": int(contract["left_delta"]),
        "right_delta": int(contract["right_delta"]),
        "left_zone_id": str(contract["left_zone_id"]),
        "right_zone_id": str(contract["right_zone_id"]),
        "primary_tile_id": str(contract["primary_tile_id"]),
        "shifted_tile_id": str(contract["shifted_tile_id"]),
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


def _prior_run_geometry(profile: dict[str, object]) -> list[tuple[int, int, int]]:
    return [
        (int(run["start"]), int(run["end"]), int(run["length"]))
        for run in profile.get("runs", [])
    ]


def _run_geometry(runs: list[dict[str, object]]) -> list[tuple[int, int, int]]:
    return [
        (int(run["start"]), int(run["end"]), int(run["length"]))
        for run in runs
    ]


def _histogram(values: list[int], key: str) -> list[dict[str, int]]:
    return [
        {key: value, "count": count}
        for value, count in sorted(Counter(values).items())
    ]


def _component(
    runs: list[dict[str, object]],
    *,
    component_id: str,
    gap_cap: int,
) -> dict[str, object]:
    gaps = [
        int(runs[index]["start"]) - int(runs[index - 1]["end"])
        for index in range(1, len(runs))
    ]
    start = int(runs[0]["start"])
    end = int(runs[-1]["end"])
    span = end - start
    equal_bytes = sum(int(run["length"]) for run in runs)
    coverage = equal_bytes / max(1, span)
    promoted = (
        span >= _MINIMUM_COMPONENT_SPAN
        and len(runs) >= _MINIMUM_COMPONENT_RUNS
        and equal_bytes >= _MINIMUM_COMPONENT_EQUAL_BYTES
        and coverage >= _MINIMUM_COMPONENT_COVERAGE
    )
    return {
        "component_id": component_id,
        "start": start,
        "end": end,
        "span": span,
        "run_count": len(runs),
        "equal_byte_count": equal_bytes,
        "unequal_gap_byte_count": sum(gaps),
        "equality_coverage": round(coverage, 8),
        "gap_count": len(gaps),
        "maximum_gap_length": max(gaps, default=0),
        "gap_length_histogram": _histogram(gaps, "gap_length"),
        "run_length_histogram": _histogram(
            [int(run["length"]) for run in runs], "run_length"
        ),
        "run_ids": [str(run["run_id"]) for run in runs],
        "gap_cap": gap_cap,
        "promotion_gate_passed": promoted,
        "classification": (
            "PROMOTED_RUN_GAP_COMPONENT"
            if promoted
            else "BELOW_COMPONENT_GATE"
        ),
    }


def _components(
    runs: list[dict[str, object]],
    *,
    gap_cap: int,
    prefix: str,
) -> list[dict[str, object]]:
    if not runs:
        return []
    groups: list[list[dict[str, object]]] = [[runs[0]]]
    for run in runs[1:]:
        gap = int(run["start"]) - int(groups[-1][-1]["end"])
        if gap <= gap_cap:
            groups[-1].append(run)
        else:
            groups.append([run])
    return [
        _component(
            group,
            component_id=f"{prefix}-G{gap_cap}-C{index + 1:03d}",
            gap_cap=gap_cap,
        )
        for index, group in enumerate(groups)
    ]


def _dominant_promoted(
    components: list[dict[str, object]],
) -> dict[str, object] | None:
    promoted = [
        component
        for component in components
        if component["promotion_gate_passed"]
    ]
    if not promoted:
        return None
    return max(
        promoted,
        key=lambda row: (
            int(row["equal_byte_count"]),
            int(row["span"]),
            -int(row["start"]),
        ),
    )


def _period_profile(
    runs: list[dict[str, object]],
    component: dict[str, object],
) -> dict[str, object]:
    selected = [
        run
        for run in runs
        if int(run["start"]) >= int(component["start"])
        and int(run["end"]) <= int(component["end"])
    ]
    gap_positions = [int(run["end"]) for run in selected[:-1]]
    gap_strides = [
        gap_positions[index] - gap_positions[index - 1]
        for index in range(1, len(gap_positions))
    ]
    stride_counts = Counter(gap_strides)
    if stride_counts:
        dominant_stride, dominant_stride_count = sorted(
            stride_counts.items(), key=lambda row: (-row[1], row[0])
        )[0]
    else:
        dominant_stride, dominant_stride_count = None, 0
    dominant_stride_share = dominant_stride_count / max(1, len(gap_strides))
    direct_stride_gate = (
        len(gap_positions) >= 5
        and dominant_stride_count >= 4
        and dominant_stride_share >= _MINIMUM_PERIOD_SHARE
    )

    period_rows = []
    maximum_period = min(64, int(component["span"]) // 3)
    for period in range(4, maximum_period + 1):
        phases = Counter(position % period for position in gap_positions)
        support = max(phases.values(), default=0)
        share = support / max(1, len(gap_positions))
        period_rows.append(
            {
                "period": period,
                "dominant_phase_support": support,
                "dominant_phase_share": round(share, 8),
                "phase_value_included": False,
            }
        )
    best_period = max(
        period_rows,
        key=lambda row: (
            float(row["dominant_phase_share"]),
            int(row["dominant_phase_support"]),
            -int(row["period"]),
        ),
        default=None,
    )
    lattice_gate = (
        best_period is not None
        and int(best_period["dominant_phase_support"]) >= 4
        and float(best_period["dominant_phase_share"])
        >= _MINIMUM_PERIOD_SHARE
    )

    run_lengths = [int(run["length"]) for run in selected]
    length_counts = Counter(run_lengths)
    repeated = []
    for length, count in sorted(length_counts.items()):
        if length < 2 or count < 4:
            continue
        starts = [
            int(run["start"])
            for run in selected
            if int(run["length"]) == length
        ]
        spacings = [
            starts[index] - starts[index - 1]
            for index in range(1, len(starts))
        ]
        spacing_counts = Counter(spacings)
        if spacing_counts:
            spacing, spacing_count = sorted(
                spacing_counts.items(), key=lambda row: (-row[1], row[0])
            )[0]
        else:
            spacing, spacing_count = None, 0
        spacing_share = spacing_count / max(1, len(spacings))
        gate = (
            len(spacings) >= 3
            and spacing_count >= 3
            and spacing_share >= _MINIMUM_PERIOD_SHARE
        )
        repeated.append(
            {
                "run_length": length,
                "occurrence_count": count,
                "component_run_share": round(count / len(selected), 8),
                "spacing_count": len(spacings),
                "dominant_spacing": spacing,
                "dominant_spacing_count": spacing_count,
                "dominant_spacing_share": round(spacing_share, 8),
                "record_spacing_gate_passed": gate,
            }
        )
    repeated_gate = any(
        row["record_spacing_gate_passed"] for row in repeated
    )
    return {
        "gap_event_count": len(gap_positions),
        "gap_stride_count": len(gap_strides),
        "gap_stride_histogram": _histogram(gap_strides, "stride"),
        "dominant_gap_stride": dominant_stride,
        "dominant_gap_stride_count": dominant_stride_count,
        "dominant_gap_stride_share": round(dominant_stride_share, 8),
        "minimum_period_share": _MINIMUM_PERIOD_SHARE,
        "direct_stride_gate_passed": direct_stride_gate,
        "tested_period_minimum": 4,
        "tested_period_maximum": maximum_period,
        "best_lattice_period": (
            int(best_period["period"]) if best_period else None
        ),
        "best_lattice_phase_support": (
            int(best_period["dominant_phase_support"])
            if best_period
            else 0
        ),
        "best_lattice_phase_share": (
            float(best_period["dominant_phase_share"])
            if best_period
            else 0.0
        ),
        "lattice_phase_value_included": False,
        "lattice_gate_passed": lattice_gate,
        "fixed_stride_record_gate_passed": (
            direct_stride_gate and lattice_gate
        ),
        "repeated_run_length_candidates": repeated,
        "repeated_run_record_gate_passed": repeated_gate,
    }


def _mapping_profile(
    source: bytes,
    mapped: bytes,
    *,
    absolute_start: int,
    label: str,
) -> dict[str, object]:
    runs = _equal_runs(
        source, mapped, absolute_start=absolute_start, prefix=label
    )
    primary = _components(runs, gap_cap=_PRIMARY_GAP_CAP, prefix=label)
    relaxed = _components(runs, gap_cap=_RELAXED_GAP_CAP, prefix=label)
    primary_promoted = [
        row for row in primary if row["promotion_gate_passed"]
    ]
    relaxed_promoted = [
        row for row in relaxed if row["promotion_gate_passed"]
    ]
    dominant = _dominant_promoted(primary)
    relaxed_dominant = _dominant_promoted(relaxed)
    stable = (
        len(primary_promoted) == 1
        and len(relaxed_promoted) == 1
        and dominant is not None
        and relaxed_dominant is not None
        and int(dominant["start"]) == int(relaxed_dominant["start"])
        and int(dominant["end"]) == int(relaxed_dominant["end"])
        and int(dominant["equal_byte_count"])
        == int(relaxed_dominant["equal_byte_count"])
    )
    selected_runs = []
    if dominant is not None:
        selected_ids = set(dominant["run_ids"])
        selected_runs = [
            run for run in runs if run["run_id"] in selected_ids
        ]
    period = (
        _period_profile(selected_runs, dominant)
        if dominant is not None
        else {
            "gap_event_count": 0,
            "fixed_stride_record_gate_passed": False,
            "repeated_run_length_candidates": [],
            "repeated_run_record_gate_passed": False,
        }
    )
    single_byte = (
        dominant is not None
        and int(dominant["gap_count"]) >= 4
        and int(dominant["maximum_gap_length"]) == 1
        and int(dominant["unequal_gap_byte_count"])
        == int(dominant["gap_count"])
    )
    return {
        "run_count": len(runs),
        "runs": runs,
        "primary_gap_cap": _PRIMARY_GAP_CAP,
        "primary_components": primary,
        "promoted_component_count": len(primary_promoted),
        "dominant_promoted_component": dominant,
        "relaxed_gap_cap": _RELAXED_GAP_CAP,
        "relaxed_component_count": len(relaxed),
        "relaxed_promoted_component_count": len(relaxed_promoted),
        "dominant_component_stable_under_relaxed_cap": stable,
        "single_byte_gap_skeleton": (
            "CONFIRMED_BOUNDED_STRUCTURAL"
            if single_byte
            else "NOT_ESTABLISHED"
        ),
        "record_periodicity": period,
    }


def _comparison(
    rz012: dict[str, object],
    rz013: dict[str, object],
) -> dict[str, object]:
    component = rz012["dominant_promoted_component"]
    control_component = rz013["dominant_promoted_component"]
    stable_skeleton = (
        component is not None
        and control_component is None
        and rz012["dominant_component_stable_under_relaxed_cap"]
        and rz012["single_byte_gap_skeleton"]
        == "CONFIRMED_BOUNDED_STRUCTURAL"
    )
    periodic = bool(
        rz012["record_periodicity"]["fixed_stride_record_gate_passed"]
    )
    repeated = bool(
        rz012["record_periodicity"]["repeated_run_record_gate_passed"]
    )
    return {
        "rz012_promoted_component_count": rz012[
            "promoted_component_count"
        ],
        "rz013_promoted_component_count": rz013[
            "promoted_component_count"
        ],
        "negative_control_distinguished": (
            component is not None and control_component is None
        ),
        "gap_cap_control": (
            "STABLE_AT_CAPS_1_AND_2"
            if rz012["dominant_component_stable_under_relaxed_cap"]
            else "NOT_STABLE"
        ),
        "stable_single_byte_gap_skeleton": stable_skeleton,
        "fixed_stride_record_model": (
            "SUPPORTED_UNDER_FIXED_GATE"
            if periodic
            else "NOT_ESTABLISHED"
        ),
        "repeated_run_record_model": (
            "SUPPORTED_UNDER_FIXED_GATE"
            if repeated
            else "NOT_ESTABLISHED"
        ),
        "micro_island_structural_model": (
            "STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON"
            if stable_skeleton
            else "NO_STABLE_RUN_GAP_MODEL"
        ),
        "record_grammar_established": periodic or repeated,
        "semantic_owner_established": False,
        "exact_section_boundary_asserted": False,
    }


def update_operational_graph_v31(
    prior_graph: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v31"
    graph["nodes"].extend(
        [
            {
                "id": "reorder-rz012-run-gap-skeleton",
                "status": report["classification"][
                    "micro_island_structural_model"
                ],
                "semantic_status": "STRUCTURAL_NOT_OWNER_PROOF",
                "evidence": report["interpretation"],
            },
            {
                "id": "reorder-rz012-record-periodicity",
                "status": report["classification"][
                    "fixed_stride_record_model"
                ],
                "semantic_status": "BOUNDED_PERIOD_MODEL_ONLY",
                "evidence": (
                    "Fixed gap-stride and repeated-run spacing gates do "
                    "not assign a record or resource grammar."
                ),
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-rz012-micro-island",
                "target": "reorder-rz012-run-gap-skeleton",
                "status": report["classification"][
                    "micro_island_structural_model"
                ],
                "relation": "refines-exact-run-gap-topology",
            },
            {
                "source": "reorder-rz012-run-gap-skeleton",
                "target": "reorder-rz012-record-periodicity",
                "status": report["classification"][
                    "fixed_stride_record_model"
                ],
                "relation": "tests-fixed-period-without-semantic-promotion",
            },
        ]
    )
    return graph


def analyze_run_gap_topology(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
) -> dict[str, object]:
    """Analyze exact-run bridging only inside the prior 2 KiB overlap."""

    validated = _validate_prior(prior)
    if left_reader.sha256() != prior.get("left_artifact_sha256"):
        raise ValueError("left principal-image hash differs from Session 037")
    if right_reader.sha256() != prior.get("right_artifact_sha256"):
        raise ValueError("right principal-image hash differs from Session 037")
    start = int(validated["overlap_start"])
    length = int(validated["overlap_length"])
    source = left_reader.read(start, length)
    rz012_mapped = right_reader.read(
        start + int(validated["left_delta"]), length
    )
    rz013_mapped = right_reader.read(
        start + int(validated["right_delta"]), length
    )
    if len(source) != length:
        raise ValueError("left overlap read was truncated")
    if len(rz012_mapped) != length or len(rz013_mapped) != length:
        raise ValueError("right mapped overlap read was truncated")

    rz012 = _mapping_profile(
        source, rz012_mapped, absolute_start=start, label="RZ012"
    )
    rz013 = _mapping_profile(
        source, rz013_mapped, absolute_start=start, label="RZ013"
    )
    if _run_geometry(rz012["runs"]) != _prior_run_geometry(prior["rz012"]):
        raise ValueError("RZ-012 exact runs differ from Session 037")
    if _run_geometry(rz013["runs"]) != _prior_run_geometry(
        prior["rz013_negative_control"]
    ):
        raise ValueError("RZ-013 exact runs differ from Session 037")
    summary = _comparison(rz012, rz013)
    classification = {
        "micro_island_correspondence": (
            "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL"
        ),
        "run_gap_topology": (
            "CONTROL_DISTINGUISHED_SINGLE_BYTE_GAP_SKELETON"
            if summary["stable_single_byte_gap_skeleton"]
            else "NOT_ESTABLISHED"
        ),
        "gap_cap_control": summary["gap_cap_control"],
        "micro_island_structural_model": summary[
            "micro_island_structural_model"
        ],
        "fixed_stride_record_model": summary[
            "fixed_stride_record_model"
        ],
        "repeated_run_record_model": summary[
            "repeated_run_record_model"
        ],
        "semantic_owner": "OPEN",
        "exact_section_boundary": "OPEN",
        "runtime_loader_transform": "NOT_OBSERVED",
        "runtime_execution_observed": False,
    }
    return {
        "schema": "phoenix-mmi.run-gap-topology-comparison/v1",
        "analysis_mode": (
            "read-only-static-bounded-2k-exact-run-gap-topology"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session037_schema": prior["schema"],
        "search_contract": {
            **validated,
            "primary_gap_cap": _PRIMARY_GAP_CAP,
            "relaxed_gap_cap": _RELAXED_GAP_CAP,
            "minimum_component_span": _MINIMUM_COMPONENT_SPAN,
            "minimum_component_runs": _MINIMUM_COMPONENT_RUNS,
            "minimum_component_equal_bytes": (
                _MINIMUM_COMPONENT_EQUAL_BYTES
            ),
            "minimum_component_coverage": _MINIMUM_COMPONENT_COVERAGE,
            "minimum_period_share": _MINIMUM_PERIOD_SHARE,
            "period_minimum": 4,
            "period_maximum": 64,
            "new_delta_search_performed": False,
            "whole_image_search_performed": False,
            "adaptive_threshold_used": False,
        },
        "rz012": rz012,
        "rz013_negative_control": rz013,
        "summary": summary,
        "classification": classification,
        "interpretation": (
            "The fixed run-gap model tests whether exact equality inside "
            "the prior RZ-012 micro-island forms one control-distinguished "
            "component bridged only by singleton differences. Period and "
            "repeated-run gates remain separate; no result establishes "
            "record semantics, section ownership, loader behavior or an "
            "exact boundary."
        ),
        "limits": [
            "Only the exact Session 037 2 KiB overlap is read from CD1.",
            "Only the prior RZ-012 and RZ-013 mappings are read from CD3.",
            "Only gap caps one and two are tested.",
            "Run lengths and gaps are structural counts, not field semantics.",
            "A periodicity match cannot establish a record grammar by itself.",
            "No section, loader, runtime or semantic boundary is inferred.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_overlap_bytes_included": False,
            "unequal_byte_values_included": False,
            "word_values_included": False,
            "instruction_bytes_included": False,
            "mnemonic_names_included": False,
            "raw_strings_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def correlate_run_gap_topology(
    prior_correlation: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.run-gap-topology-correlation/v1",
        "analysis_mode": report["analysis_mode"],
        "firmware": copy.deepcopy(report["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_run_gap_edge": "NOT_ASSERTED",
        "interpretation": report["interpretation"],
        "operational_graph": update_operational_graph_v31(
            prior_correlation["operational_graph"], report
        ),
        "publication_safety": copy.deepcopy(
            report["publication_safety"]
        ),
    }


def build_public_run_gap_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

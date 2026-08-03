"""Session 032 relocation anchors, plateaus and breakpoint brackets.

The analyzer combines only evidence classes already validated by earlier
sessions: direct-link bounded-code pairs, byte-identical data regions and
constant-delta marker bands.  It reports exact anchors and bounded change
brackets; it never interpolates an unobserved runtime/file mapping.
"""

from __future__ import annotations

from collections import Counter
import copy
import hashlib
from typing import Protocol

from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import summarize_bounded_entry


_CODE_WINDOW_BYTES = 0x180
_CODE_PLATEAU_MAX_GAP = 0x10000
_CROSS_CLASS_MAX_GAP = 0x20000


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def sha256(self) -> str: ...


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _distance_to_interval(
    point: int, start: int, end: int
) -> int:
    if start <= point <= end:
        return 0
    return min(abs(point - start), abs(point - end))


def _exact_region(
    left_reader: _Reader,
    right_reader: _Reader,
    *,
    region_id: str,
    source_session: int,
    left_offset: int,
    right_offset: int,
    length: int,
    expected_sha256: str,
) -> dict[str, object]:
    if length <= 0:
        raise ValueError("exact region length must be positive")
    left = left_reader.read(left_offset, length)
    right = right_reader.read(right_offset, length)
    if len(left) != length or len(right) != length:
        raise ValueError(f"truncated exact region {region_id}")
    left_hash = _sha256(left)
    right_hash = _sha256(right)
    verified = bool(
        left == right
        and left_hash == right_hash
        and left_hash == expected_sha256
    )
    return {
        "region_id": region_id,
        "source_session": source_session,
        "evidence_class": "BYTE_IDENTICAL_DATA_REGION",
        "left_start": left_offset,
        "left_end": left_offset + length,
        "right_start": right_offset,
        "right_end": right_offset + length,
        "length": length,
        "relocation_delta": right_offset - left_offset,
        "sha256": left_hash,
        "byte_identity_verified": verified,
        "continuous_interval_mapping_confirmed": verified,
        "firmware_bytes_included": False,
    }


def _collect_exact_regions(
    left_reader: _Reader,
    right_reader: _Reader,
    session005_left: dict[str, object],
    session005_right: dict[str, object],
    session008: dict[str, object],
) -> list[dict[str, object]]:
    left_core = session005_left["core_bundle"]
    right_core = session005_right["core_bundle"]
    if (
        int(left_core["length"]) != int(right_core["length"])
        or left_core["sha256"] != right_core["sha256"]
    ):
        raise ValueError("Session 005 core bundles do not agree")
    bitmap = session008["bitmap_atlas"]["equal_region"]
    regions = [
        _exact_region(
            left_reader,
            right_reader,
            region_id="DR-001",
            source_session=5,
            left_offset=int(left_core["offset"]),
            right_offset=int(right_core["offset"]),
            length=int(left_core["length"]),
            expected_sha256=str(left_core["sha256"]),
        ),
        _exact_region(
            left_reader,
            right_reader,
            region_id="DR-002",
            source_session=8,
            left_offset=int(bitmap["left_offset"]),
            right_offset=int(bitmap["right_offset"]),
            length=int(bitmap["length"]),
            expected_sha256=str(bitmap["sha256"]),
        ),
    ]
    if not all(
        region["byte_identity_verified"] for region in regions
    ):
        raise ValueError("an exact data region failed raw verification")
    return regions


def _collect_marker_bands(
    session009: dict[str, object],
) -> list[dict[str, object]]:
    bands = []
    for source_index, band in enumerate(
        session009["relocation_bands"]
    ):
        if not (
            band["constant_relocation_delta"]
            and str(band["structural_status"]).startswith(
                "CONFIRMED"
            )
        ):
            continue
        delta = int(band["minimum_relocation_delta"])
        if delta != int(band["maximum_relocation_delta"]):
            raise ValueError("constant marker band has unequal deltas")
        left_start = int(band["left_start"])
        right_start = int(band["right_start"])
        if right_start - left_start != delta:
            raise ValueError("marker band start delta differs")
        bands.append(
            {
                "band_id": f"MB-{len(bands) + 1:03d}",
                "source_session": 9,
                "source_band_ordinal": source_index,
                "evidence_class": (
                    "CONSTANT_DELTA_ORDERED_MARKER_BAND"
                ),
                "left_start": left_start,
                "left_end": int(band["left_end"]),
                "right_start": right_start,
                "right_end": int(band["right_end"]),
                "relocation_delta": delta,
                "marker_pair_count": int(band["pair_count"]),
                "dominant_domain": band["dominant_domain"],
                "code_referenced_pair_count": int(
                    band[
                        "dual_release_code_referenced_pair_count"
                    ]
                ),
                "continuous_byte_mapping_asserted": False,
                "raw_strings_included": False,
            }
        )
    return bands


def _direct_pair_sources(
    session015: dict[str, object],
) -> list[dict[str, object]]:
    rows = []
    seen: dict[tuple[int, int], str] = {}
    for source_kind, source_rows in (
        (
            "SESSION010_CALL_TARGET",
            session015["navigation_seed_pairs"],
        ),
        (
            "RECORD_POINTER_BOUNDED_CODE",
            session015["optical_seed_pairs"],
        ),
    ):
        for source in source_rows:
            left = int(source["left_entry_file_offset"])
            right = int(source["right_entry_file_offset"])
            key = (left, right)
            anchor_id = seen.get(key)
            if anchor_id is None:
                anchor_id = f"CA-{len(seen) + 1:03d}"
                seen[key] = anchor_id
                rows.append(
                    {
                        "anchor_id": anchor_id,
                        "left_file_offset": left,
                        "right_file_offset": right,
                        "relocation_delta": right - left,
                        "source_kinds": [source_kind],
                        "source_classifications": [
                            source["classification"]
                        ],
                        "occurrence_count": int(
                            source["occurrence_count"]
                        ),
                    }
                )
                continue
            target = next(
                row
                for row in rows
                if row["anchor_id"] == anchor_id
            )
            if source_kind not in target["source_kinds"]:
                target["source_kinds"].append(source_kind)
            target["source_classifications"].append(
                source["classification"]
            )
            target["occurrence_count"] += int(
                source["occurrence_count"]
            )
    return rows


def _collect_direct_code_anchors(
    left_reader: _Reader,
    right_reader: _Reader,
    session015: dict[str, object],
) -> list[dict[str, object]]:
    anchors = []
    for source in _direct_pair_sources(session015):
        left_offset = int(source["left_file_offset"])
        right_offset = int(source["right_file_offset"])
        left_code = summarize_bounded_entry(
            left_reader,
            left_offset,
            source="session032-prior-direct-link-anchor",
            maximum_bytes=_CODE_WINDOW_BYTES,
        )
        right_code = summarize_bounded_entry(
            right_reader,
            right_offset,
            source="session032-prior-direct-link-anchor",
            maximum_bytes=_CODE_WINDOW_BYTES,
        )
        gate = bool(
            left_code["bounded_code_gate_passed"]
            and right_code["bounded_code_gate_passed"]
        )
        if not gate:
            raise ValueError(
                f"prior code anchor {source['anchor_id']} "
                "failed revalidation"
            )
        anchors.append(
            {
                **source,
                "source_session": 15,
                "evidence_class": (
                    "DIRECT_LINK_BILATERAL_BOUNDED_CODE"
                ),
                "left_code_gate_passed": True,
                "right_code_gate_passed": True,
                "left_known_ratio": left_code["known_ratio"],
                "right_known_ratio": right_code["known_ratio"],
                "normalized_shape_equal": (
                    left_code["normalized_shape_sha256"]
                    == right_code["normalized_shape_sha256"]
                ),
                "left_direct_link_file_correction": 0,
                "right_direct_link_file_correction": 0,
                "runtime_equivalence_asserted": False,
                "instruction_bytes_included": False,
                "raw_pointer_values_included": False,
                "absolute_runtime_addresses_included": False,
            }
        )
    return anchors


def _code_plateaus(
    anchors: list[dict[str, object]],
) -> list[dict[str, object]]:
    ordered = sorted(
        anchors, key=lambda row: int(row["left_file_offset"])
    )
    runs: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    for anchor in ordered:
        if not current:
            current = [anchor]
            continue
        previous = current[-1]
        same_delta = (
            int(anchor["relocation_delta"])
            == int(previous["relocation_delta"])
        )
        bounded_gap = (
            int(anchor["left_file_offset"])
            - int(previous["left_file_offset"])
            <= _CODE_PLATEAU_MAX_GAP
        )
        if same_delta and bounded_gap:
            current.append(anchor)
        else:
            runs.append(current)
            current = [anchor]
    if current:
        runs.append(current)

    plateaus = []
    for run in runs:
        if len(run) < 2:
            continue
        delta = int(run[0]["relocation_delta"])
        plateaus.append(
            {
                "plateau_id": f"CP-{len(plateaus) + 1:03d}",
                "evidence_class": (
                    "DIRECT_CODE_EQUAL_DELTA_ANCHOR_PLATEAU"
                ),
                "left_start": int(run[0]["left_file_offset"]),
                "left_end": int(run[-1]["left_file_offset"]),
                "right_start": int(run[0]["right_file_offset"]),
                "right_end": int(run[-1]["right_file_offset"]),
                "relocation_delta": delta,
                "anchor_count": len(run),
                "anchor_ids": [
                    str(anchor["anchor_id"]) for anchor in run
                ],
                "maximum_left_anchor_gap": max(
                    int(right["left_file_offset"])
                    - int(left["left_file_offset"])
                    for left, right in zip(run, run[1:])
                ),
                "mapping_confirmed_at_anchor_points": True,
                "continuous_interval_mapping_asserted": False,
            }
        )
    return plateaus


def _cross_class_support(
    marker_bands: list[dict[str, object]],
    code_anchors: list[dict[str, object]],
) -> list[dict[str, object]]:
    rows = []
    for band in marker_bands:
        matches = [
            anchor
            for anchor in code_anchors
            if int(anchor["relocation_delta"])
            == int(band["relocation_delta"])
            and _distance_to_interval(
                int(anchor["left_file_offset"]),
                int(band["left_start"]),
                int(band["left_end"]),
            )
            <= _CROSS_CLASS_MAX_GAP
        ]
        if not matches:
            continue
        rows.append(
            {
                "support_id": f"XC-{len(rows) + 1:03d}",
                "evidence_class": (
                    "CROSS_CLASS_MARKER_AND_DIRECT_CODE_DELTA"
                ),
                "marker_band_id": band["band_id"],
                "code_anchor_ids": [
                    anchor["anchor_id"] for anchor in matches
                ],
                "relocation_delta": band["relocation_delta"],
                "marker_pair_count": band["marker_pair_count"],
                "direct_code_anchor_count": len(matches),
                "minimum_left_gap": min(
                    _distance_to_interval(
                        int(anchor["left_file_offset"]),
                        int(band["left_start"]),
                        int(band["left_end"]),
                    )
                    for anchor in matches
                ),
                "continuous_mapping_between_classes_asserted": False,
            }
        )
    return rows


def _support_zones(
    exact_regions: list[dict[str, object]],
    marker_bands: list[dict[str, object]],
    code_plateaus: list[dict[str, object]],
) -> list[dict[str, object]]:
    zones = []
    for region in exact_regions:
        zones.append(
            {
                "zone_id": f"RZ-{len(zones) + 1:03d}",
                "source_id": region["region_id"],
                "evidence_class": region["evidence_class"],
                "left_start": region["left_start"],
                "left_end": region["left_end"],
                "right_start": region["right_start"],
                "right_end": region["right_end"],
                "relocation_delta": region[
                    "relocation_delta"
                ],
                "continuous_interval_mapping_confirmed": True,
            }
        )
    for band in marker_bands:
        zones.append(
            {
                "zone_id": f"RZ-{len(zones) + 1:03d}",
                "source_id": band["band_id"],
                "evidence_class": band["evidence_class"],
                "left_start": band["left_start"],
                "left_end": band["left_end"],
                "right_start": band["right_start"],
                "right_end": band["right_end"],
                "relocation_delta": band[
                    "relocation_delta"
                ],
                "continuous_interval_mapping_confirmed": False,
            }
        )
    for plateau in code_plateaus:
        zones.append(
            {
                "zone_id": f"RZ-{len(zones) + 1:03d}",
                "source_id": plateau["plateau_id"],
                "evidence_class": plateau["evidence_class"],
                "left_start": plateau["left_start"],
                "left_end": plateau["left_end"],
                "right_start": plateau["right_start"],
                "right_end": plateau["right_end"],
                "relocation_delta": plateau[
                    "relocation_delta"
                ],
                "continuous_interval_mapping_confirmed": False,
            }
        )
    return sorted(
        zones, key=lambda row: (int(row["left_start"]), row["zone_id"])
    )


def _breakpoint_brackets(
    zones: list[dict[str, object]],
) -> list[dict[str, object]]:
    brackets = []
    for left_zone, right_zone in zip(zones, zones[1:]):
        left_end = int(left_zone["left_end"])
        next_start = int(right_zone["left_start"])
        if next_start < left_end:
            continue
        left_delta = int(left_zone["relocation_delta"])
        right_delta = int(right_zone["relocation_delta"])
        if left_delta == right_delta:
            continue
        right_monotonic = (
            int(right_zone["right_start"])
            >= int(left_zone["right_end"])
        )
        brackets.append(
            {
                "bracket_id": f"RB-{len(brackets) + 1:03d}",
                "left_zone_id": left_zone["zone_id"],
                "right_zone_id": right_zone["zone_id"],
                "left_file_lower_bound": left_end,
                "left_file_upper_bound": next_start,
                "left_bracket_width": next_start - left_end,
                "left_delta": left_delta,
                "right_delta": right_delta,
                "delta_change": right_delta - left_delta,
                "right_order_monotonic": right_monotonic,
                "classification": (
                    "MONOTONIC_DELTA_CHANGE_BRACKET"
                    if right_monotonic
                    else "SECTION_REORDER_BRACKET"
                ),
                "exact_breakpoint_asserted": False,
            }
        )
    return brackets


def _pool_pairs(
    left_reader: _Reader,
    right_reader: _Reader,
    session030: dict[str, object],
) -> list[dict[str, object]]:
    pair_ids: dict[tuple[int, int], str] = {}
    rows: dict[str, dict[str, object]] = {}
    for target in session030["target_pairs"]:
        flow = int(target["flow_ordinal"])
        left_pool = target["left"]["pool"]
        right_pool = target["right"]["pool"]
        count = int(left_pool["pool_word_count"])
        if count != int(right_pool["pool_word_count"]):
            raise ValueError("pool word counts differ")
        left_raw = left_reader.read(
            int(left_pool["pool_start_file_offset"]), count * 4
        )
        right_raw = right_reader.read(
            int(right_pool["pool_start_file_offset"]), count * 4
        )
        left_entries = target["left"]["pool_references"][
            "entries"
        ]
        right_entries = target["right"]["pool_references"][
            "entries"
        ]
        for index in range(count):
            left_value = (
                int.from_bytes(
                    left_raw[index * 4 : index * 4 + 4], "big"
                )
                - RUNTIME_BASE
            )
            right_value = (
                int.from_bytes(
                    right_raw[index * 4 : index * 4 + 4], "big"
                )
                - RUNTIME_BASE
            )
            key = (left_value, right_value)
            pair_id = pair_ids.get(key)
            if pair_id is None:
                pair_id = f"LP-{len(pair_ids) + 1:03d}"
                pair_ids[key] = pair_id
                left_uses = left_entries[index]["uses"]
                right_uses = right_entries[index]["uses"]
                if len(left_uses) != 1 or len(right_uses) != 1:
                    role = "AMBIGUOUS"
                else:
                    role = str(
                        left_uses[0]["classification"]
                    )
                    if role != str(
                        right_uses[0]["classification"]
                    ):
                        raise ValueError("pool entry roles differ")
                rows[pair_id] = {
                    "pair_id": pair_id,
                    "left_link_offset": left_value,
                    "right_link_offset": right_value,
                    "link_relocation_delta": (
                        right_value - left_value
                    ),
                    "use_classification": role,
                    "occurrences": [],
                }
            rows[pair_id]["occurrences"].append(
                {"flow_ordinal": flow, "word_index": index}
            )
    return list(rows.values())


def _reconcile_pool_pairs(
    pool_pairs: list[dict[str, object]],
    direct_anchors: list[dict[str, object]],
    exact_regions: list[dict[str, object]],
    marker_bands: list[dict[str, object]],
    code_plateaus: list[dict[str, object]],
) -> list[dict[str, object]]:
    direct_by_pair = {
        (
            int(anchor["left_file_offset"]),
            int(anchor["right_file_offset"]),
        ): anchor
        for anchor in direct_anchors
    }
    direct_by_delta: dict[int, list[dict[str, object]]] = {}
    for anchor in direct_anchors:
        direct_by_delta.setdefault(
            int(anchor["relocation_delta"]), []
        ).append(anchor)
    rows = []
    for pair in pool_pairs:
        left = int(pair["left_link_offset"])
        right = int(pair["right_link_offset"])
        exact_anchor = direct_by_pair.get((left, right))
        same_delta_anchors = direct_by_delta.get(
            int(pair["link_relocation_delta"]), []
        )
        exact_regions_covering = [
            region["region_id"]
            for region in exact_regions
            if int(region["left_start"])
            <= left
            < int(region["left_end"])
            and int(region["right_start"])
            <= right
            < int(region["right_end"])
            and (
                left - int(region["left_start"])
                == right - int(region["right_start"])
            )
        ]
        marker_bands_covering = [
            band["band_id"]
            for band in marker_bands
            if int(band["left_start"])
            <= left
            <= int(band["left_end"])
            and int(band["right_start"])
            <= right
            <= int(band["right_end"])
            and int(pair["link_relocation_delta"])
            == int(band["relocation_delta"])
        ]
        plateau_candidates = [
            plateau["plateau_id"]
            for plateau in code_plateaus
            if int(plateau["left_start"])
            <= left
            <= int(plateau["left_end"])
            and int(plateau["right_start"])
            <= right
            <= int(plateau["right_end"])
            and int(pair["link_relocation_delta"])
            == int(plateau["relocation_delta"])
        ]
        if exact_anchor is not None:
            status = "CONFIRMED_EXACT_PRIOR_DIRECT_CODE_ANCHOR"
        elif exact_regions_covering:
            status = "CONFIRMED_EXACT_DATA_INTERVAL_MAPPING"
        elif marker_bands_covering:
            status = "CONFIRMED_MARKER_BAND_ANCHOR_COVERAGE"
        elif plateau_candidates:
            status = "INTERPOLATION_CANDIDATE_NOT_PROMOTED"
        elif same_delta_anchors:
            status = "DELTA_FAMILY_ONLY_NOT_IDENTITY"
        else:
            status = "NO_PRIOR_ANCHOR_COVERAGE"
        rows.append(
            {
                "pair_id": pair["pair_id"],
                "link_relocation_delta": pair[
                    "link_relocation_delta"
                ],
                "use_classification": pair[
                    "use_classification"
                ],
                "occurrences": copy.deepcopy(
                    pair["occurrences"]
                ),
                "exact_direct_code_anchor_id": (
                    None
                    if exact_anchor is None
                    else exact_anchor["anchor_id"]
                ),
                "same_delta_direct_code_anchor_ids": [
                    anchor["anchor_id"]
                    for anchor in same_delta_anchors
                ],
                "exact_data_region_ids": exact_regions_covering,
                "marker_band_ids": marker_bands_covering,
                "code_plateau_candidate_ids": plateau_candidates,
                "status": status,
                "original_handoff_callee_asserted": False,
                "raw_pointer_values_included": False,
                "absolute_runtime_addresses_included": False,
            }
        )
    return rows


def analyze_relocation_breakpoints(
    left_reader: _Reader,
    right_reader: _Reader,
    *,
    session005_left: dict[str, object],
    session005_right: dict[str, object],
    session008: dict[str, object],
    session009: dict[str, object],
    session015: dict[str, object],
    session030: dict[str, object],
    session031: dict[str, object],
) -> dict[str, object]:
    """Build a conservative whole-image relocation support model."""

    exact_regions = _collect_exact_regions(
        left_reader,
        right_reader,
        session005_left,
        session005_right,
        session008,
    )
    marker_bands = _collect_marker_bands(session009)
    direct_anchors = _collect_direct_code_anchors(
        left_reader, right_reader, session015
    )
    code_plateaus = _code_plateaus(direct_anchors)
    cross_class = _cross_class_support(
        marker_bands, direct_anchors
    )
    zones = _support_zones(
        exact_regions, marker_bands, code_plateaus
    )
    brackets = _breakpoint_brackets(zones)
    pool_pairs = _pool_pairs(
        left_reader, right_reader, session030
    )
    if len(pool_pairs) != int(
        session031["classification"]["unique_link_pair_count"]
    ):
        raise ValueError("Session 031 unique pool-pair count differs")
    prior_pairs = {
        str(row["pair_id"]): row
        for row in session031["unique_pairs"]
    }
    for pair in pool_pairs:
        prior = prior_pairs.get(str(pair["pair_id"]))
        if (
            prior is None
            or int(prior["link_relocation_delta"])
            != int(pair["link_relocation_delta"])
            or str(prior["use_classification"])
            != str(pair["use_classification"])
            or prior["occurrences"] != pair["occurrences"]
        ):
            raise ValueError(
                "Session 031 pool-pair identity differs"
            )
    pool_reconciliation = _reconcile_pool_pairs(
        pool_pairs,
        direct_anchors,
        exact_regions,
        marker_bands,
        code_plateaus,
    )

    exact_code_matches = sum(
        row["status"]
        == "CONFIRMED_EXACT_PRIOR_DIRECT_CODE_ANCHOR"
        for row in pool_reconciliation
    )
    exact_data_matches = sum(
        row["status"]
        == "CONFIRMED_EXACT_DATA_INTERVAL_MAPPING"
        for row in pool_reconciliation
    )
    delta_only_matches = sum(
        row["status"] == "DELTA_FAMILY_ONLY_NOT_IDENTITY"
        for row in pool_reconciliation
    )
    interpolation_candidates = sum(
        row["status"]
        == "INTERPOLATION_CANDIDATE_NOT_PROMOTED"
        for row in pool_reconciliation
    )
    classifications = Counter(
        str(row["classification"]) for row in brackets
    )
    delta_counts = Counter(
        int(anchor["relocation_delta"])
        for anchor in direct_anchors
    )
    classification = {
        "direct_link_code_anchor_count": len(direct_anchors),
        "direct_link_code_delta_family_count": len(delta_counts),
        "direct_link_code_equal_shape_count": sum(
            anchor["normalized_shape_equal"]
            for anchor in direct_anchors
        ),
        "exact_data_region_count": len(exact_regions),
        "exact_data_byte_count": sum(
            int(region["length"]) for region in exact_regions
        ),
        "constant_marker_band_count": len(marker_bands),
        "constant_marker_pair_count": sum(
            int(band["marker_pair_count"])
            for band in marker_bands
        ),
        "direct_code_plateau_count": len(code_plateaus),
        "cross_class_delta_support_count": len(cross_class),
        "support_zone_count": len(zones),
        "breakpoint_bracket_count": len(brackets),
        "breakpoint_classification_counts": dict(
            sorted(classifications.items())
        ),
        "pool_unique_pair_count": len(pool_pairs),
        "pool_exact_direct_code_anchor_match_count": (
            exact_code_matches
        ),
        "pool_exact_data_interval_match_count": (
            exact_data_matches
        ),
        "pool_delta_family_only_match_count": (
            delta_only_matches
        ),
        "pool_interpolation_candidate_count": (
            interpolation_candidates
        ),
        "pool_no_prior_anchor_coverage_count": sum(
            row["status"] == "NO_PRIOR_ANCHOR_COVERAGE"
            for row in pool_reconciliation
        ),
        "whole_image_relocation_support_model": (
            "CONFIRMED_AT_DECLARED_ANCHORS_AND_REGIONS"
        ),
        "continuous_universal_file_map": "NOT_ESTABLISHED",
        "loader_or_section_transform": "OPEN",
        "original_handoff_callee": "OPEN",
    }
    return {
        "schema": (
            "phoenix-mmi.relocation-breakpoint-comparison/v1"
        ),
        "analysis_mode": (
            "read-only-static-prior-anchor-relocation-breakpoints"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "classification": classification,
        "direct_link_code_anchors": direct_anchors,
        "direct_link_delta_families": [
            {
                "relocation_delta": delta,
                "anchor_count": count,
            }
            for delta, count in sorted(delta_counts.items())
        ],
        "exact_data_regions": exact_regions,
        "constant_marker_bands": marker_bands,
        "direct_code_plateaus": code_plateaus,
        "cross_class_delta_support": cross_class,
        "support_zones": zones,
        "breakpoint_brackets": brackets,
        "pool_pair_reconciliation": pool_reconciliation,
        "limits": {
            "prior_confirmed_evidence_only": True,
            "source_sessions": [5, 8, 9, 15, 30, 31],
            "code_window_bytes": _CODE_WINDOW_BYTES,
            "code_plateau_maximum_anchor_gap": (
                _CODE_PLATEAU_MAX_GAP
            ),
            "cross_class_maximum_gap": (
                _CROSS_CLASS_MAX_GAP
            ),
            "global_arbitrary_code_search_performed": False,
            "unobserved_interval_interpolation_performed": False,
            "runtime_execution_observed": False,
            "loader_metadata_decoded": False,
        },
        "interpretation": (
            "Prior evidence confirms a sparse whole-image relocation "
            "support model: direct-link code targets, byte-identical data "
            "intervals and constant marker bands occupy multiple relocation "
            "families, including reordered sections. Exact anchors and "
            "bounded change brackets are reproducible, but gaps are not "
            "interpolated. Pool-entry identity may be reconciled with a "
            "prior direct code anchor without making that entry the original "
            "handoff callee."
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


def update_operational_graph_v25(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v25"
    classification = comparison["classification"]
    graph["nodes"].extend(
        [
            {
                "id": "direct-link-code-anchor-registry",
                "label": "Revalidated direct-link code anchors",
                "status": "CONFIRMED_BOUNDED_STRUCTURAL",
                "anchor_count": classification[
                    "direct_link_code_anchor_count"
                ],
                "evidence": ["S032-01", "RQ-104"],
            },
            {
                "id": "relocation-support-zones",
                "label": "Relocation support zones and brackets",
                "status": "CONFIRMED_AT_DECLARED_ANCHORS",
                "zone_count": classification[
                    "support_zone_count"
                ],
                "bracket_count": classification[
                    "breakpoint_bracket_count"
                ],
                "evidence": ["S032-02", "RQ-105", "RQ-106"],
            },
            {
                "id": "pool-entry-anchor-reconciliation",
                "label": "Literal-pool entry anchor reconciliation",
                "status": (
                    "CONFIRMED_PARTIAL"
                    if classification[
                        "pool_exact_direct_code_anchor_match_count"
                    ]
                    else "OPEN"
                ),
                "exact_code_match_count": classification[
                    "pool_exact_direct_code_anchor_match_count"
                ],
                "evidence": ["S032-03", "RQ-107"],
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "literal-pool-link-delta-atlas",
                "target": "direct-link-code-anchor-registry",
                "relation": (
                    "pool value pairs are reconciled by exact identity "
                    "against prior direct-link code anchors"
                ),
                "status": "CONFIRMED_PARTIAL",
            },
            {
                "source": "direct-link-code-anchor-registry",
                "target": "relocation-support-zones",
                "relation": (
                    "equal-delta anchors bound local plateaus without "
                    "interpolating gaps"
                ),
                "status": "CONFIRMED_STRUCTURAL",
            },
            {
                "source": "relocation-support-zones",
                "target": "piecewise-link-file-map",
                "relation": (
                    "support zones constrain file layout but do not form "
                    "a continuous universal map"
                ),
                "status": "OPEN",
            },
            {
                "source": "pool-entry-anchor-reconciliation",
                "target": "runtime-linkage-owner-ingress",
                "relation": (
                    "resolved pool-entry code identity does not establish "
                    "the original handoff registration path"
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
        "BOUNDED_NEGATIVE" in edge["status"]
        for edge in graph["edges"]
    )
    graph["disproved_edge_count"] = sum(
        "DISPROVED" in edge["status"] for edge in graph["edges"]
    )
    graph["interpretation"] = comparison["interpretation"]
    return graph


def correlate_relocation_breakpoints(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": (
            "phoenix-mmi.relocation-breakpoint-correlation/v1"
        ),
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
        "operational_graph": update_operational_graph_v25(
            prior_correlation["operational_graph"],
            comparison,
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_relocation_breakpoint_report(
    report: dict[str, object],
) -> dict[str, object]:
    """Return a detached already-publication-safe report."""

    return copy.deepcopy(report)

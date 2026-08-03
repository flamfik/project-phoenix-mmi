"""Bounded reference-graph and owner-evidence analysis.

This module performs read-only static correlation.  It deliberately separates
structural references from semantic ownership: a relocated pointer graph can
be confirmed while the subsystem that owns it remains only probable.
"""

from __future__ import annotations

from collections import Counter
import copy
from typing import Iterable

from .binary import BinaryReader
from .superh import find_pc_relative_referrers


RUNTIME_BASE = 0x0C000000
BROWSER_MARKERS = (b"html", b"http", b"mime", b"url", b"browser", b"gif", b"jpeg")


def _region_name(offset: int, boundaries: dict[str, int], size: int) -> str:
    if not 0 <= offset < size:
        return "out-of-image"
    if boundaries["browser_core_start"] <= offset < boundaries["browser_core_end"]:
        return "browser-resource-core"
    if boundaries["browser_core_end"] <= offset < boundaries["browser_island_end"]:
        return "browser-post-cluster"
    if offset < boundaries["browser_core_start"]:
        return "pre-browser-unresolved"
    return "post-browser-unresolved"


def build_reference_anchors(
    bundle_report: dict[str, object],
    *,
    record_block_offset: int,
    record_block_length: int,
) -> list[dict[str, object]]:
    """Build explicit anchors from already-published Session 005/006 evidence."""

    island = bundle_report["island"]
    core = bundle_report["core_bundle"]
    post_cluster = bundle_report["post_cluster"]
    island_start = int(island["offset"])
    anchors: list[dict[str, object]] = [
        {"label": "browser-core-start", "file_offset": int(core["offset"])},
        {"label": "browser-core-end", "file_offset": int(core["end"])},
        {"label": "browser-island-end", "file_offset": int(island["end"])},
    ]
    for index, run in enumerate(post_cluster["pointer_runs"]):
        start = island_start + int(run["island_offset"])
        end = start + int(run["count"]) * 4
        anchors.extend(
            (
                {"label": f"source-run-{index}-start", "file_offset": start},
                {"label": f"source-run-{index}-end", "file_offset": end},
            )
        )
    anchors.extend(
        (
            {"label": "record-block-start", "file_offset": record_block_offset},
            {
                "label": "record-block-end",
                "file_offset": record_block_offset + record_block_length,
            },
        )
    )
    return anchors


def scan_runtime_anchor(
    reader: BinaryReader,
    anchor: dict[str, object],
    *,
    boundaries: dict[str, int],
    runtime_base: int = RUNTIME_BASE,
) -> dict[str, object]:
    """Find exact big-endian runtime-address words and their SH MOV.L users."""

    file_offset = int(anchor["file_offset"])
    runtime_address = runtime_base + file_offset
    occurrences = reader.find_all(runtime_address.to_bytes(4, "big"))
    occurrence_reports = []
    referrer_count = 0
    for occurrence in occurrences:
        referrers = find_pc_relative_referrers(reader, occurrence)
        referrer_count += len(referrers)
        occurrence_reports.append(
            {
                "file_offset": occurrence,
                "region": _region_name(occurrence, boundaries, reader.size),
                "pc_relative_mov_l_referrer_offsets": [item.offset for item in referrers],
            }
        )
    return {
        "label": str(anchor["label"]),
        "target_file_offset": file_offset,
        "exact_runtime_word_occurrence_count": len(occurrences),
        "exact_runtime_word_occurrences": occurrence_reports,
        "pc_relative_mov_l_referrer_count": referrer_count,
        "runtime_address_included": False,
    }


def find_descriptor_candidates(
    reader: BinaryReader,
    *,
    record_block_offset: int,
    record_block_length: int,
    runtime_base: int = RUNTIME_BASE,
    window_before: int = 0x40,
    window_after: int = 0x44,
) -> list[dict[str, object]]:
    """Find structures containing the block-end pointer and normalize fields.

    A candidate is anchored by an exact runtime pointer to the first byte after
    the confirmed record block.  Other in-image pointer fields in a small,
    aligned window are represented only by their relative field location and
    target delta from the block start.
    """

    block_end_address = runtime_base + record_block_offset + record_block_length
    candidates = []
    for anchor_offset in reader.find_all(block_end_address.to_bytes(4, "big")):
        fields = []
        for relative in range(-window_before, window_after + 1, 4):
            field_offset = anchor_offset + relative
            if field_offset < 0 or field_offset + 4 > reader.size:
                continue
            value = int.from_bytes(reader.read(field_offset, 4), "big")
            target_offset = value - runtime_base
            if not 0 <= target_offset < reader.size:
                continue
            fields.append(
                {
                    "field_relative_offset": relative,
                    "target_delta_from_block": target_offset - record_block_offset,
                }
            )
        referrers = find_pc_relative_referrers(reader, anchor_offset)
        candidates.append(
            {
                "anchor_file_offset": anchor_offset,
                "anchor_delta_from_block": anchor_offset - record_block_offset,
                "mapped_field_count": len(fields),
                "pc_relative_mov_l_referrer_offsets": [item.offset for item in referrers],
                "_internal_normalized_fields": fields,
            }
        )
    return candidates


def scan_marker_profile(
    reader: BinaryReader,
    *,
    center_offset: int,
    radius: int = 0x10000,
    markers: Iterable[bytes] = BROWSER_MARKERS,
) -> dict[str, object]:
    """Scan a bounded window for a fixed, non-payload marker vocabulary."""

    start = max(0, center_offset - radius)
    end = min(reader.size, center_offset + radius)
    lowered = reader.read(start, end - start).lower()
    occurrences: list[dict[str, object]] = []
    for marker in markers:
        search_from = 0
        while True:
            index = lowered.find(marker, search_from)
            if index < 0:
                break
            occurrences.append(
                {
                    "marker": marker.decode("ascii"),
                    "relative_offset": start + index - center_offset,
                }
            )
            search_from = index + 1
    occurrences.sort(key=lambda item: (int(item["relative_offset"]), str(item["marker"])))
    counts = Counter(str(item["marker"]) for item in occurrences)
    relatives = [int(item["relative_offset"]) for item in occurrences]
    return {
        "radius": radius,
        "marker_vocabulary": [marker.decode("ascii") for marker in markers],
        "occurrence_count": len(occurrences),
        "counts": dict(sorted(counts.items())),
        "minimum_relative_offset": min(relatives) if relatives else None,
        "maximum_relative_offset": max(relatives) if relatives else None,
        "raw_strings_included": False,
        "_internal_occurrences": occurrences,
    }


def analyze_reference_graph(
    reader: BinaryReader,
    bundle_report: dict[str, object],
    *,
    record_block_offset: int,
    record_block_length: int,
    runtime_base: int = RUNTIME_BASE,
) -> dict[str, object]:
    """Build one release's static reference graph without executing firmware."""

    boundaries = {
        "browser_core_start": int(bundle_report["core_bundle"]["offset"]),
        "browser_core_end": int(bundle_report["core_bundle"]["end"]),
        "browser_island_end": int(bundle_report["island"]["end"]),
    }
    anchors = build_reference_anchors(
        bundle_report,
        record_block_offset=record_block_offset,
        record_block_length=record_block_length,
    )
    anchor_reports = [
        scan_runtime_anchor(
            reader,
            anchor,
            boundaries=boundaries,
            runtime_base=runtime_base,
        )
        for anchor in anchors
    ]
    source_ranges = []
    island_start = int(bundle_report["island"]["offset"])
    for index, run in enumerate(bundle_report["post_cluster"]["pointer_runs"]):
        start = island_start + int(run["island_offset"])
        source_ranges.append((index, start, start + int(run["count"]) * 4))

    block_start = next(item for item in anchor_reports if item["label"] == "record-block-start")
    source_edges = []
    for occurrence in block_start["exact_runtime_word_occurrences"]:
        offset = int(occurrence["file_offset"])
        for run_index, start, end in source_ranges:
            if start <= offset < end:
                source_edges.append(
                    {
                        "source_run_index": run_index,
                        "source_entry_index": (offset - start) // 4,
                        "target": "record-block-start",
                    }
                )

    descriptors = find_descriptor_candidates(
        reader,
        record_block_offset=record_block_offset,
        record_block_length=record_block_length,
        runtime_base=runtime_base,
    )
    marker_profile = scan_marker_profile(reader, center_offset=record_block_offset)
    direct_referrers = sum(
        int(item["pc_relative_mov_l_referrer_count"]) for item in anchor_reports
    ) + sum(len(item["pc_relative_mov_l_referrer_offsets"]) for item in descriptors)
    return {
        "schema": "phoenix-mmi.reference-graph/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "filename": reader.path.name,
            "sha256": reader.sha256(),
            "size_bytes": reader.size,
        },
        "runtime_model": {
            "base": runtime_base,
            "status": "REUSED_CONFIRMED_SESSION006_MODEL",
        },
        "boundaries": boundaries,
        "record_block": {
            "file_offset": record_block_offset,
            "length": record_block_length,
        },
        "anchors": anchor_reports,
        "source_to_target_edges": source_edges,
        "descriptor_candidates": descriptors,
        "browser_marker_profile": marker_profile,
        "direct_pc_relative_referrer_count": direct_referrers,
        "publication_safety": {
            "firmware_bytes_included": False,
            "target_window_bytes_included": False,
            "raw_strings_included": False,
            "raw_runtime_addresses_included": False,
            "raw_pointer_run_values_included": False,
        },
    }


def _descriptor_match(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    left_candidates = left["descriptor_candidates"]
    right_candidates = right["descriptor_candidates"]
    best: dict[str, object] | None = None
    for left_candidate in left_candidates:
        left_fields = {
            (int(item["field_relative_offset"]), int(item["target_delta_from_block"]))
            for item in left_candidate["_internal_normalized_fields"]
        }
        for right_candidate in right_candidates:
            right_fields = {
                (int(item["field_relative_offset"]), int(item["target_delta_from_block"]))
                for item in right_candidate["_internal_normalized_fields"]
            }
            common = sorted(left_fields & right_fields)
            candidate = {
                "left_anchor_file_offset": int(left_candidate["anchor_file_offset"]),
                "right_anchor_file_offset": int(right_candidate["anchor_file_offset"]),
                "left_anchor_delta_from_block": int(left_candidate["anchor_delta_from_block"]),
                "right_anchor_delta_from_block": int(right_candidate["anchor_delta_from_block"]),
                "common_normalized_field_count": len(common),
                "common_normalized_fields": [
                    {
                        "field_relative_offset": field,
                        "target_delta_from_block": target,
                    }
                    for field, target in common
                ],
            }
            if (
                best is None
                or candidate["common_normalized_field_count"]
                > best["common_normalized_field_count"]
            ):
                best = candidate
    return best or {
        "common_normalized_field_count": 0,
        "common_normalized_fields": [],
    }


def _compare_marker_profiles(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    left_occurrences = left["browser_marker_profile"]["_internal_occurrences"]
    right_occurrences = right["browser_marker_profile"]["_internal_occurrences"]
    left_order = [str(item["marker"]) for item in left_occurrences]
    right_order = [str(item["marker"]) for item in right_occurrences]
    exact = Counter(
        (str(item["marker"]), int(item["relative_offset"])) for item in left_occurrences
    ) & Counter(
        (str(item["marker"]), int(item["relative_offset"])) for item in right_occurrences
    )
    ordinal_deltas: Counter[int] = Counter()
    vocabulary = left["browser_marker_profile"]["marker_vocabulary"]
    for marker in vocabulary:
        left_offsets = sorted(
            int(item["relative_offset"])
            for item in left_occurrences
            if item["marker"] == marker
        )
        right_offsets = sorted(
            int(item["relative_offset"])
            for item in right_occurrences
            if item["marker"] == marker
        )
        for left_offset, right_offset in zip(left_offsets, right_offsets):
            ordinal_deltas[right_offset - left_offset] += 1
    return {
        "left_occurrence_count": len(left_occurrences),
        "right_occurrence_count": len(right_occurrences),
        "counts_equal": left["browser_marker_profile"]["counts"]
        == right["browser_marker_profile"]["counts"],
        "ordered_marker_sequence_equal": left_order == right_order,
        "exact_relative_position_match_count": sum(exact.values()),
        "ordinal_relative_offset_delta_histogram": {
            str(delta): count for delta, count in sorted(ordinal_deltas.items())
        },
        "raw_strings_included": False,
    }


def compare_reference_graphs(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    """Compare normalized graphs and apply a deliberately conservative owner policy."""

    descriptor = _descriptor_match(left, right)
    block_delta = int(right["record_block"]["file_offset"]) - int(
        left["record_block"]["file_offset"]
    )
    descriptor_delta = None
    if "left_anchor_file_offset" in descriptor:
        descriptor_delta = int(descriptor["right_anchor_file_offset"]) - int(
            descriptor["left_anchor_file_offset"]
        )
    descriptor["record_block_relocation_delta"] = block_delta
    descriptor["descriptor_relocation_delta"] = descriptor_delta
    descriptor["relocates_with_record_block"] = descriptor_delta == block_delta
    descriptor["status"] = (
        "CONFIRMED_RELOCATED_DESCRIPTOR_GRAPH"
        if descriptor["common_normalized_field_count"] >= 3
        and descriptor["relocates_with_record_block"]
        else "UNRESOLVED"
    )

    markers = _compare_marker_profiles(left, right)
    source_edges_match = left["source_to_target_edges"] == right["source_to_target_edges"]
    source_in_browser_island = bool(left["source_to_target_edges"]) and source_edges_match
    marker_signal = bool(markers["counts_equal"] and markers["ordered_marker_sequence_equal"])
    direct_referrer_count = int(left["direct_pc_relative_referrer_count"]) + int(
        right["direct_pc_relative_referrer_count"]
    )
    owner_status = (
        "PROBABLE_BROWSER_SUPPORT_REGION"
        if source_in_browser_island and marker_signal
        else "NOT_CONFIRMED"
    )
    return {
        "schema": "phoenix-mmi.reference-graph-comparison/v1",
        "analysis_mode": "read-only-static",
        "left": left["artifact"].get("label", left["artifact"]["filename"]),
        "right": right["artifact"].get("label", right["artifact"]["filename"]),
        "source_edge_comparison": {
            "same_source_edges": source_edges_match,
            "edge_count_per_release": len(left["source_to_target_edges"]),
            "all_edges_originate_in_browser_post_cluster": source_in_browser_island,
        },
        "descriptor_graph": descriptor,
        "browser_marker_profile_comparison": markers,
        "direct_reference_search": {
            "combined_pc_relative_mov_l_referrer_count": direct_referrer_count,
            "status": (
                "FOUND" if direct_referrer_count else "CONFIRMED_BOUNDED_NEGATIVE"
            ),
            "scope": "exact runtime-address words at declared anchors and descriptor anchors",
        },
        "owner_evidence": {
            "status": owner_status,
            "confirmed": False,
            "independent_positive_signal_count": sum(
                (source_in_browser_island, marker_signal)
            ),
            "signals": {
                "source_table_is_inside_confirmed_browser_post_cluster": source_in_browser_island,
                "browser_marker_counts_and_order_preserved_near_target": marker_signal,
                "normalized_descriptor_graph_relocated_with_target": descriptor["status"]
                == "CONFIRMED_RELOCATED_DESCRIPTOR_GRAPH",
                "direct_code_referrer_identifies_owner": direct_referrer_count > 0,
            },
            "policy": (
                "Two independent contextual signals can support PROBABLE ownership. "
                "CONFIRMED requires a direct code/dataflow referrer or equivalent semantic evidence."
            ),
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "target_window_bytes_included": False,
            "raw_strings_included": False,
            "raw_runtime_addresses_included": False,
            "raw_pointer_run_values_included": False,
        },
    }


def build_public_reference_graph(report: dict[str, object]) -> dict[str, object]:
    """Strip local-only occurrence sequences and normalized candidate details."""

    public = copy.deepcopy(report)
    public["browser_marker_profile"].pop("_internal_occurrences", None)
    for candidate in public["descriptor_candidates"]:
        candidate.pop("_internal_normalized_fields", None)
    return public

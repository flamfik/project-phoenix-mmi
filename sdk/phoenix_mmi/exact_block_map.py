"""Bounded exact-block mapping around the Session 032 reorder bracket.

Session 034 does not assume another descriptor grammar.  It hashes fixed,
aligned seeds only inside two declared per-zone windows, retains seeds unique
on both sides, verifies their bytes, and extends them to window-bounded maximal
byte-identical blocks.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import hashlib

from .binary import BinaryReader


_DEFAULT_MARGIN = 0x20000
_DEFAULT_SEED_SIZE = 64
_DEFAULT_STRIDE = 4
_EXTENSION_CHUNK = 4096


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _validate_prior(prior: dict[str, object]) -> dict[str, object]:
    if prior.get("schema") != (
        "phoenix-mmi.relocation-descriptor-comparison/v1"
    ):
        raise ValueError("unsupported Session 033 comparison schema")
    classification = prior.get("classification", {})
    if classification.get("section_reorder_anchor") != (
        "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL"
    ):
        raise ValueError("confirmed reorder anchor is required")
    if classification.get("coherent_reorder_descriptor_table") != (
        "CLOSED_BOUNDED_NEGATIVE"
    ):
        raise ValueError("Session 033 descriptor boundary is required")
    bracket = prior.get("reorder_bracket", {})
    if bracket.get("classification") != "SECTION_REORDER_BRACKET":
        raise ValueError("section-reorder bracket is required")
    left_zones = {
        str(row["zone_id"]): row
        for row in prior.get("left", {}).get("zones", [])
    }
    right_zones = {
        str(row["zone_id"]): row
        for row in prior.get("right", {}).get("zones", [])
    }
    zone_ids = (
        str(bracket["left_zone_id"]),
        str(bracket["right_zone_id"]),
    )
    if any(
        zone_id not in left_zones or zone_id not in right_zones
        for zone_id in zone_ids
    ):
        raise ValueError("both reorder zones are required on both sides")
    return {
        "bracket": bracket,
        "zone_ids": zone_ids,
        "left_zones": left_zones,
        "right_zones": right_zones,
    }


def _window(
    zone: dict[str, object],
    *,
    image_size: int,
    margin: int,
    seed_size: int,
) -> dict[str, int]:
    start = max(0, int(zone["start"]) - margin)
    end = min(image_size, int(zone["end"]) + margin)
    if end - start < seed_size:
        raise ValueError("zone window is smaller than one seed")
    return {"start": start, "end": end, "length": end - start}


def _seed_index(
    data: bytes,
    window: dict[str, int],
    *,
    seed_size: int,
    stride: int,
) -> dict[str, object]:
    offsets: dict[bytes, list[int]] = defaultdict(list)
    first = _align_up(int(window["start"]), stride)
    last = int(window["end"]) - seed_size
    for offset in range(first, last + 1, stride):
        digest = hashlib.blake2s(
            data[offset : offset + seed_size], digest_size=16
        ).digest()
        offsets[digest].append(offset)
    unique = {
        digest: rows[0]
        for digest, rows in offsets.items()
        if len(rows) == 1
    }
    return {
        "total_seed_count": sum(len(rows) for rows in offsets.values()),
        "distinct_digest_count": len(offsets),
        "unique_digest_count": len(unique),
        "_unique": unique,
    }


def _verified_seed_pairs(
    left_data: bytes,
    right_data: bytes,
    left_index: dict[str, object],
    right_index: dict[str, object],
    *,
    seed_size: int,
) -> list[dict[str, int]]:
    left_unique = left_index["_unique"]
    right_unique = right_index["_unique"]
    rows = []
    for digest in sorted(set(left_unique) & set(right_unique)):
        left = int(left_unique[digest])
        right = int(right_unique[digest])
        if (
            left_data[left : left + seed_size]
            != right_data[right : right + seed_size]
        ):
            continue
        rows.append(
            {
                "left": left,
                "right": right,
                "delta": right - left,
            }
        )
    return sorted(rows, key=lambda row: (row["delta"], row["left"]))


def _seed_groups(
    pairs: list[dict[str, int]], *, seed_size: int
) -> list[dict[str, int]]:
    groups = []
    by_delta: dict[int, list[dict[str, int]]] = defaultdict(list)
    for row in pairs:
        by_delta[int(row["delta"])].append(row)
    for delta, rows in sorted(by_delta.items()):
        rows.sort(key=lambda row: int(row["left"]))
        start = int(rows[0]["left"])
        end = start + seed_size
        seed_count = 1
        for row in rows[1:]:
            offset = int(row["left"])
            if offset <= end:
                end = max(end, offset + seed_size)
                seed_count += 1
                continue
            groups.append(
                {
                    "left_start": start,
                    "right_start": start + delta,
                    "seed_extent_end": end,
                    "delta": delta,
                    "unique_seed_count": seed_count,
                }
            )
            start = offset
            end = offset + seed_size
            seed_count = 1
        groups.append(
            {
                "left_start": start,
                "right_start": start + delta,
                "seed_extent_end": end,
                "delta": delta,
                "unique_seed_count": seed_count,
            }
        )
    return groups


def _extend_left(
    left_data: bytes,
    right_data: bytes,
    left: int,
    right: int,
    *,
    left_bound: int,
    right_bound: int,
) -> tuple[int, int]:
    while left > left_bound and right > right_bound:
        width = min(
            _EXTENSION_CHUNK,
            left - left_bound,
            right - right_bound,
        )
        left_chunk = left_data[left - width : left]
        right_chunk = right_data[right - width : right]
        if left_chunk == right_chunk:
            left -= width
            right -= width
            continue
        equal_suffix = 0
        for index in range(1, width + 1):
            if left_chunk[-index] != right_chunk[-index]:
                break
            equal_suffix += 1
        left -= equal_suffix
        right -= equal_suffix
        break
    return left, right


def _extend_right(
    left_data: bytes,
    right_data: bytes,
    left: int,
    right: int,
    *,
    left_bound: int,
    right_bound: int,
) -> tuple[int, int]:
    while left < left_bound and right < right_bound:
        width = min(
            _EXTENSION_CHUNK,
            left_bound - left,
            right_bound - right,
        )
        left_chunk = left_data[left : left + width]
        right_chunk = right_data[right : right + width]
        if left_chunk == right_chunk:
            left += width
            right += width
            continue
        equal_prefix = 0
        for index in range(width):
            if left_chunk[index] != right_chunk[index]:
                break
            equal_prefix += 1
        left += equal_prefix
        right += equal_prefix
        break
    return left, right


def _maximal_blocks(
    left_data: bytes,
    right_data: bytes,
    groups: list[dict[str, int]],
    *,
    left_window: dict[str, int],
    right_window: dict[str, int],
    seed_size: int,
) -> list[dict[str, object]]:
    blocks: dict[tuple[int, int, int], dict[str, object]] = {}
    for group in groups:
        left_start, right_start = _extend_left(
            left_data,
            right_data,
            int(group["left_start"]),
            int(group["right_start"]),
            left_bound=int(left_window["start"]),
            right_bound=int(right_window["start"]),
        )
        seed_length = (
            int(group["seed_extent_end"])
            - int(group["left_start"])
        )
        left_end, right_end = _extend_right(
            left_data,
            right_data,
            int(group["left_start"]) + seed_length,
            int(group["right_start"]) + seed_length,
            left_bound=int(left_window["end"]),
            right_bound=int(right_window["end"]),
        )
        length = left_end - left_start
        if length < seed_size or length != right_end - right_start:
            continue
        if (
            left_data[left_start:left_end]
            != right_data[right_start:right_end]
        ):
            continue
        key = (left_start, right_start, length)
        block = blocks.setdefault(
            key,
            {
                "left_start": left_start,
                "left_end": left_end,
                "right_start": right_start,
                "right_end": right_end,
                "length": length,
                "relocation_delta": right_start - left_start,
                "unique_seed_count": 0,
                "sha256": hashlib.sha256(
                    left_data[left_start:left_end]
                ).hexdigest(),
                "byte_identity_verified": True,
                "window_bounded_maximal": True,
            },
        )
        block["unique_seed_count"] = int(
            block["unique_seed_count"]
        ) + int(group["unique_seed_count"])
    return sorted(
        blocks.values(),
        key=lambda row: (
            int(row["left_start"]),
            -int(row["length"]),
            int(row["right_start"]),
        ),
    )


def _lane_analysis(
    left_data: bytes,
    right_data: bytes,
    *,
    zone_id: str,
    left_zone: dict[str, object],
    right_zone: dict[str, object],
    margin: int,
    seed_size: int,
    stride: int,
) -> dict[str, object]:
    left_window = _window(
        left_zone,
        image_size=len(left_data),
        margin=margin,
        seed_size=seed_size,
    )
    right_window = _window(
        right_zone,
        image_size=len(right_data),
        margin=margin,
        seed_size=seed_size,
    )
    left_index = _seed_index(
        left_data,
        left_window,
        seed_size=seed_size,
        stride=stride,
    )
    right_index = _seed_index(
        right_data,
        right_window,
        seed_size=seed_size,
        stride=stride,
    )
    pairs = _verified_seed_pairs(
        left_data,
        right_data,
        left_index,
        right_index,
        seed_size=seed_size,
    )
    groups = _seed_groups(pairs, seed_size=seed_size) if pairs else []
    blocks = _maximal_blocks(
        left_data,
        right_data,
        groups,
        left_window=left_window,
        right_window=right_window,
        seed_size=seed_size,
    )
    expected_delta = int(right_zone["start"]) - int(left_zone["start"])
    for ordinal, block in enumerate(blocks, start=1):
        block["block_id"] = f"{zone_id}-EB-{ordinal:03d}"
        block["expected_zone_delta_match"] = (
            int(block["relocation_delta"]) == expected_delta
        )
        block["overlaps_left_zone"] = (
            int(block["left_start"]) < int(left_zone["end"])
            and int(block["left_end"]) > int(left_zone["start"])
        )
        block["covers_left_zone"] = (
            int(block["left_start"]) <= int(left_zone["start"])
            and int(block["left_end"]) >= int(left_zone["end"])
        )
    expected = [
        row for row in blocks if row["expected_zone_delta_match"]
    ]
    delta_counts = Counter(
        int(row["relocation_delta"]) for row in blocks
    )
    return {
        "zone_id": zone_id,
        "left_zone": copy.deepcopy(left_zone),
        "right_zone": copy.deepcopy(right_zone),
        "expected_zone_delta": expected_delta,
        "left_window": left_window,
        "right_window": right_window,
        "seed_census": {
            "seed_size": seed_size,
            "stride": stride,
            "left_total_seed_count": left_index["total_seed_count"],
            "right_total_seed_count": right_index["total_seed_count"],
            "left_unique_digest_count": left_index[
                "unique_digest_count"
            ],
            "right_unique_digest_count": right_index[
                "unique_digest_count"
            ],
            "bilateral_unique_verified_seed_count": len(pairs),
            "seed_group_count": len(groups),
            "hash_collision_accepted_count": 0,
        },
        "exact_block_count": len(blocks),
        "non_expected_delta_exact_block_count": (
            len(blocks) - len(expected)
        ),
        "expected_delta_exact_blocks": expected,
        "expected_delta_exact_block_count": len(expected),
        "expected_delta_zone_overlap_block_count": sum(
            bool(row["overlaps_left_zone"]) for row in expected
        ),
        "expected_delta_zone_covering_block_count": sum(
            bool(row["covers_left_zone"]) for row in expected
        ),
        "expected_delta_exact_byte_count": sum(
            int(row["length"]) for row in expected
        ),
        "largest_expected_delta_exact_block": max(
            (int(row["length"]) for row in expected), default=0
        ),
        "relocation_delta_distribution": {
            str(key): value for key, value in sorted(delta_counts.items())
        },
        "raw_seed_digests_included": False,
        "firmware_bytes_included": False,
    }


def _overlap_length(
    left: dict[str, object], right: dict[str, object]
) -> int:
    return max(
        0,
        min(int(left["left_end"]), int(right["left_end"]))
        - max(int(left["left_start"]), int(right["left_start"])),
    )


def _transition_envelope(
    lanes: list[dict[str, object]],
    bracket: dict[str, object],
) -> dict[str, object]:
    first, second = lanes
    lower = int(bracket["left_file_lower_bound"])
    upper = int(bracket["left_file_upper_bound"])
    first_blocks = first["expected_delta_exact_blocks"]
    second_blocks = second["expected_delta_exact_blocks"]
    first_inside = [
        row
        for row in first_blocks
        if int(row["left_end"]) > lower
        and int(row["left_start"]) < upper
    ]
    second_inside = [
        row
        for row in second_blocks
        if int(row["left_end"]) > lower
        and int(row["left_start"]) < upper
    ]
    supported_lower = max(
        [lower]
        + [
            min(upper, int(row["left_end"]))
            for row in first_inside
        ]
    )
    supported_upper = min(
        [upper]
        + [
            max(lower, int(row["left_start"]))
            for row in second_inside
        ]
    )
    overlaps = [
        _overlap_length(left, right)
        for left in first_inside
        for right in second_inside
    ]
    overlap = max(overlaps, default=0)
    if supported_lower <= supported_upper and not overlap:
        width = supported_upper - supported_lower
        status = (
            "NARROWED_BY_EXACT_BLOCKS"
            if width < upper - lower
            else "UNCHANGED"
        )
        bounds_valid = True
    else:
        width = None
        status = "AMBIGUOUS_CROSS_LANE_OVERLAP"
        bounds_valid = False
    return {
        "prior_lower_bound": lower,
        "prior_upper_bound": upper,
        "prior_width": upper - lower,
        "first_lane_last_exact_end": supported_lower,
        "second_lane_first_exact_start": supported_upper,
        "cross_lane_maximum_left_overlap": overlap,
        "bounds_ordered_and_non_overlapping": bounds_valid,
        "classification": status,
        "narrowed_lower_bound": (
            supported_lower if bounds_valid else None
        ),
        "narrowed_upper_bound": (
            supported_upper if bounds_valid else None
        ),
        "narrowed_width": width,
        "exact_breakpoint_asserted": False,
    }


def update_operational_graph_v27(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v27"
    exact_support = comparison["classification"][
        "file_layout_reorder_exact_block_support"
    ]
    graph["nodes"].extend(
        [
            {
                "id": "reorder-exact-block-map",
                "status": exact_support,
                "evidence": comparison["interpretation"],
            },
            {
                "id": "reorder-transition-envelope",
                "status": comparison["transition_envelope"][
                    "classification"
                ],
                "evidence": (
                    "Exact blocks refine only the bounded file-layout "
                    "transition; no runtime boundary is asserted."
                ),
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-zone-descriptor-seeds",
                "target": "reorder-exact-block-map",
                "status": exact_support,
                "relation": "bounds-content-search",
            },
            {
                "source": "reorder-exact-block-map",
                "target": "reorder-transition-envelope",
                "status": comparison["transition_envelope"][
                    "classification"
                ],
                "relation": "bounds-file-layout-transition",
            },
        ]
    )
    return graph


def analyze_exact_block_map(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
    *,
    margin: int = _DEFAULT_MARGIN,
    seed_size: int = _DEFAULT_SEED_SIZE,
    stride: int = _DEFAULT_STRIDE,
) -> dict[str, object]:
    """Build a two-lane, window-bounded exact content map."""

    if margin < seed_size:
        raise ValueError("margin must be at least one seed")
    if seed_size < 16 or seed_size % 4:
        raise ValueError("seed size must be a multiple of four and >= 16")
    if stride <= 0 or stride > seed_size or seed_size % stride:
        raise ValueError("stride must divide the seed size")
    validated = _validate_prior(prior)
    if left_reader.sha256() != prior.get("left_artifact_sha256"):
        raise ValueError("left principal-image hash differs from Session 033")
    if right_reader.sha256() != prior.get("right_artifact_sha256"):
        raise ValueError(
            "right principal-image hash differs from Session 033"
        )
    left_data = left_reader.read(0, left_reader.size)
    right_data = right_reader.read(0, right_reader.size)
    lanes = []
    for zone_id in validated["zone_ids"]:
        lanes.append(
            _lane_analysis(
                left_data,
                right_data,
                zone_id=zone_id,
                left_zone=validated["left_zones"][zone_id],
                right_zone=validated["right_zones"][zone_id],
                margin=margin,
                seed_size=seed_size,
                stride=stride,
            )
        )
    transition = _transition_envelope(
        lanes, validated["bracket"]
    )
    bilateral_support = all(
        int(lane["expected_delta_exact_block_count"]) > 0
        for lane in lanes
    )
    classification = {
        "section_reorder_anchor": "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL",
        "simple_internal_descriptor_table": "CLOSED_BOUNDED_NEGATIVE",
        "file_layout_reorder_exact_block_support": (
            "CONFIRMED_AT_EXACT_BLOCKS"
            if bilateral_support
            else "NOT_ESTABLISHED"
        ),
        "transition_envelope": transition["classification"],
        "exact_section_boundary": "OPEN",
        "compile_link_layout_explanation": "CONSISTENT_NOT_PROVEN",
        "runtime_loader_transform": "NOT_OBSERVED",
        "runtime_execution_observed": False,
    }
    interpretation = (
        "Both reorder lanes contain byte-verified exact blocks at their "
        "independently known relocation deltas. This confirms file-layout "
        "content movement at bounded blocks, while compile/link placement "
        "versus a loader transform remains unresolved."
        if bilateral_support
        else (
            "The bounded unique-seed model does not produce exact blocks "
            "at both independently known relocation deltas. The prior "
            "marker-based reorder remains confirmed, but exact content "
            "support is incomplete."
        )
    )
    return {
        "schema": "phoenix-mmi.exact-block-map-comparison/v1",
        "analysis_mode": (
            "read-only-static-bounded-unique-seed-exact-block-map"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session033_schema": prior["schema"],
        "search_contract": {
            "margin": margin,
            "seed_size": seed_size,
            "stride": stride,
            "hash_algorithm": "BLAKE2s-128",
            "seed_unique_in_each_lane_window_required": True,
            "direct_seed_byte_verification_required": True,
            "maximal_extension_requires_direct_byte_equality": True,
            "whole_image_search_performed": False,
            "adaptive_threshold_used": False,
        },
        "reorder_bracket": copy.deepcopy(validated["bracket"]),
        "lanes": lanes,
        "transition_envelope": transition,
        "classification": classification,
        "interpretation": interpretation,
        "limits": [
            "Only two fixed per-zone windows are searched.",
            "Repeated 64-byte seeds are intentionally excluded.",
            "Exact blocks are maximal only inside their declared lane windows.",
            "Byte identity proves file-layout correspondence, not runtime execution or semantic ownership.",
            "Low-information bytes may extend a block only when contiguous with a bilateral unique seed.",
            "Changed or relocation-patched bytes between exact blocks remain unmapped.",
            "Compile/link placement and runtime loader transformation are not distinguished.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_seed_digests_included": False,
            "raw_strings_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def correlate_exact_block_map(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.exact-block-map-correlation/v1",
        "analysis_mode": comparison["analysis_mode"],
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_exact_block_edge": "NOT_ASSERTED",
        "interpretation": comparison["interpretation"],
        "operational_graph": update_operational_graph_v27(
            prior_correlation["operational_graph"], comparison
        ),
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def compare_exact_block_seed_control(
    primary: dict[str, object],
    strict: dict[str, object],
) -> dict[str, object]:
    """Compare a primary map with a stricter, larger-seed control."""

    schema = "phoenix-mmi.exact-block-map-comparison/v1"
    if primary.get("schema") != schema or strict.get("schema") != schema:
        raise ValueError("exact-block comparison schemas are required")
    if (
        primary["left_artifact_sha256"]
        != strict["left_artifact_sha256"]
        or primary["right_artifact_sha256"]
        != strict["right_artifact_sha256"]
    ):
        raise ValueError("seed-control artifacts differ")
    primary_contract = primary["search_contract"]
    strict_contract = strict["search_contract"]
    if (
        int(primary_contract["margin"]) != int(strict_contract["margin"])
        or int(primary_contract["stride"]) != int(strict_contract["stride"])
    ):
        raise ValueError("seed-control window or stride differs")
    if int(strict_contract["seed_size"]) <= int(
        primary_contract["seed_size"]
    ):
        raise ValueError("strict seed must be larger")
    primary_envelope = primary["transition_envelope"]
    strict_envelope = strict["transition_envelope"]
    envelope_equal = all(
        primary_envelope[key] == strict_envelope[key]
        for key in (
            "narrowed_lower_bound",
            "narrowed_upper_bound",
            "narrowed_width",
            "classification",
        )
    )
    support_equal = (
        primary["classification"][
            "file_layout_reorder_exact_block_support"
        ]
        == strict["classification"][
            "file_layout_reorder_exact_block_support"
        ]
        == "CONFIRMED_AT_EXACT_BLOCKS"
    )
    lane_rows = []
    for primary_lane, strict_lane in zip(
        primary["lanes"], strict["lanes"], strict=True
    ):
        if primary_lane["zone_id"] != strict_lane["zone_id"]:
            raise ValueError("seed-control lane order differs")
        lane_rows.append(
            {
                "zone_id": primary_lane["zone_id"],
                "primary_expected_block_count": primary_lane[
                    "expected_delta_exact_block_count"
                ],
                "strict_expected_block_count": strict_lane[
                    "expected_delta_exact_block_count"
                ],
                "primary_exact_byte_count": primary_lane[
                    "expected_delta_exact_byte_count"
                ],
                "strict_exact_byte_count": strict_lane[
                    "expected_delta_exact_byte_count"
                ],
                "largest_block_equal": (
                    primary_lane[
                        "largest_expected_delta_exact_block"
                    ]
                    == strict_lane[
                        "largest_expected_delta_exact_block"
                    ]
                ),
            }
        )
    return {
        "schema": "phoenix-mmi.exact-block-seed-control/v1",
        "primary_seed_size": primary_contract["seed_size"],
        "strict_seed_size": strict_contract["seed_size"],
        "same_margin": True,
        "same_stride": True,
        "file_layout_support_equal": support_equal,
        "transition_envelope_equal": envelope_equal,
        "lanes": lane_rows,
        "classification": (
            "CONFIRMED_STABLE"
            if support_equal and envelope_equal
            else "NOT_STABLE"
        ),
        "strict_full_report_published": False,
    }


def build_public_exact_block_map_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

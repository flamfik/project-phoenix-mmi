"""Session 031 bounded piecewise link-address/file-layout mapping.

The analyzer follows the values stored in the two complete literal pools
recovered by Session 030.  It compares link-address relocation families and
tests a one-dimensional, bounded file-layout correction.  It never treats a
raw pointer, a nearby prologue or a single matching pair as a universal map.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
from dataclasses import dataclass
from typing import Protocol

from .handoff_field60 import _strict_target_profile
from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import summarize_bounded_entry


_SEARCH_RADIUS = 0x800
_SEARCH_STEP = 2
_CODE_WINDOW_BYTES = 0x80


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def sha256(self) -> str: ...


@dataclass(frozen=True)
class _MemoryReader:
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset > self.size:
            raise ValueError("offset is beyond artifact")
        return self.data[offset : min(self.size, offset + length)]


def _whole_image(reader: _Reader) -> _MemoryReader:
    return _MemoryReader(reader.read(0, reader.size))


def _pool_values(
    reader: _Reader, pool: dict[str, object]
) -> list[int]:
    start = int(pool["pool_start_file_offset"])
    count = int(pool["pool_word_count"])
    raw = reader.read(start, count * 4)
    if len(raw) != count * 4:
        raise ValueError("truncated literal pool")
    return [
        int.from_bytes(raw[index : index + 4], "big")
        for index in range(0, len(raw), 4)
    ]


def _single_use_class(
    entry: dict[str, object],
) -> str:
    uses = entry.get("uses", [])
    if len(uses) != 1:
        return "AMBIGUOUS"
    return str(uses[0].get("classification", "UNKNOWN"))


def _candidate_profile(
    left: _MemoryReader,
    right: _MemoryReader,
    *,
    left_offset: int,
    right_offset: int,
) -> dict[str, object] | None:
    if (
        left_offset < 0
        or right_offset < 0
        or left_offset >= left.size
        or right_offset >= right.size
        or left_offset & 1
        or right_offset & 1
    ):
        return None
    left_strict = _strict_target_profile(left, left_offset)
    right_strict = _strict_target_profile(right, right_offset)
    if not (
        left_strict["strict_exact_entry_gate_passed"]
        and right_strict["strict_exact_entry_gate_passed"]
    ):
        return None
    left_code = summarize_bounded_entry(
        left,
        left_offset,
        source="session031-piecewise-candidate",
        maximum_bytes=_CODE_WINDOW_BYTES,
    )
    right_code = summarize_bounded_entry(
        right,
        right_offset,
        source="session031-piecewise-candidate",
        maximum_bytes=_CODE_WINDOW_BYTES,
    )
    shape_equal = (
        left_code["normalized_shape_sha256"]
        == right_code["normalized_shape_sha256"]
    )
    gate = bool(
        left_code["bounded_code_gate_passed"]
        and right_code["bounded_code_gate_passed"]
        and left_code["known_ratio"] == 1.0
        and right_code["known_ratio"] == 1.0
        and shape_equal
    )
    return {
        "left_file_offset": left_offset,
        "right_file_offset": right_offset,
        "left_known_ratio": left_code["known_ratio"],
        "right_known_ratio": right_code["known_ratio"],
        "normalized_shape_sha256": left_code[
            "normalized_shape_sha256"
        ],
        "normalized_shape_equal": shape_equal,
        "bilateral_code_anchor_gate_passed": gate,
        "instruction_bytes_included": False,
    }


def _bounded_matches(
    left: _MemoryReader,
    right: _MemoryReader,
    *,
    left_link_offset: int,
    right_link_offset: int,
    structural_delta: int,
    search_radius: int,
) -> dict[str, object]:
    link_delta = right_link_offset - left_link_offset
    relative_correction = structural_delta - link_delta
    strict_pair_count = 0
    matches = []
    tested = 0
    for common_correction in range(
        -search_radius, search_radius + 1, _SEARCH_STEP
    ):
        tested += 1
        left_file = left_link_offset + common_correction
        right_file = (
            right_link_offset
            + common_correction
            + relative_correction
        )
        candidate = _candidate_profile(
            left,
            right,
            left_offset=left_file,
            right_offset=right_file,
        )
        if candidate is None:
            continue
        strict_pair_count += 1
        if candidate["bilateral_code_anchor_gate_passed"]:
            matches.append(
                {
                    "common_correction": common_correction,
                    **candidate,
                }
            )
    return {
        "search_radius_bytes": search_radius,
        "search_step_bytes": _SEARCH_STEP,
        "candidate_correction_count": tested,
        "bilateral_strict_entry_count": strict_pair_count,
        "bilateral_code_anchor_count": len(matches),
        "matching_common_corrections": [
            int(match["common_correction"]) for match in matches
        ],
        "matches": matches,
    }


def _family_status(
    *,
    unique_pair_count: int,
    code_eligible_pair_count: int,
    eligible_pair_count: int,
    common_corrections: set[int],
) -> str:
    if code_eligible_pair_count == 0:
        return "NOT_APPLICABLE_NON_CONTROL_LITERAL"
    if (
        unique_pair_count >= 2
        and eligible_pair_count == unique_pair_count
        and len(common_corrections) == 1
    ):
        return "CONFIRMED_TWO_INDEPENDENT_CODE_ANCHORS"
    if eligible_pair_count and len(common_corrections) == 1:
        return "PROVISIONAL_SINGLE_PAIR_OR_INCOMPLETE_FAMILY"
    if eligible_pair_count:
        return "AMBIGUOUS_BOUNDED_CANDIDATES"
    return "BOUNDED_NEGATIVE_NO_CODE_ANCHOR"


def analyze_piecewise_link_map(
    left_reader: _Reader,
    right_reader: _Reader,
    session030: dict[str, object],
    *,
    search_radius: int = _SEARCH_RADIUS,
) -> dict[str, object]:
    """Build a bounded cross-release link-delta atlas.

    Pool entries are paired by structural word ordinal after Session 030 has
    proved equal pool geometry and use grammar.  Indirect-control entries are
    eligible for code-anchor probing; argument literals are retained in the
    delta atlas but are not treated as callees.
    """

    if search_radius < 0 or search_radius % _SEARCH_STEP:
        raise ValueError("search_radius must be a non-negative even value")
    target_pairs = session030.get("target_pairs", [])
    if not target_pairs:
        raise ValueError("Session 030 target pairs are required")
    structural_deltas = {
        int(pair["pool_start_file_offset_delta"])
        for pair in target_pairs
    }
    if len(structural_deltas) != 1:
        raise ValueError("one common structural pool delta is required")
    structural_delta = next(iter(structural_deltas))

    left = _whole_image(left_reader)
    right = _whole_image(right_reader)
    occurrences = []
    pair_first_seen: dict[tuple[int, int], str] = {}
    unique_pairs: dict[str, dict[str, object]] = {}

    for target_pair in target_pairs:
        flow = int(target_pair["flow_ordinal"])
        left_pool = target_pair["left"]["pool"]
        right_pool = target_pair["right"]["pool"]
        left_values = _pool_values(left, left_pool)
        right_values = _pool_values(right, right_pool)
        left_entries = target_pair["left"]["pool_references"][
            "entries"
        ]
        right_entries = target_pair["right"]["pool_references"][
            "entries"
        ]
        if not (
            len(left_values)
            == len(right_values)
            == len(left_entries)
            == len(right_entries)
        ):
            raise ValueError("bilateral pool cardinality differs")

        for word_index, (
            left_value,
            right_value,
            left_entry,
            right_entry,
        ) in enumerate(
            zip(
                left_values,
                right_values,
                left_entries,
                right_entries,
            )
        ):
            left_role = _single_use_class(left_entry)
            right_role = _single_use_class(right_entry)
            if left_role != right_role:
                raise ValueError("bilateral pool role differs")
            left_link = left_value - RUNTIME_BASE
            right_link = right_value - RUNTIME_BASE
            raw_pair = (left_link, right_link)
            pair_id = pair_first_seen.get(raw_pair)
            if pair_id is None:
                pair_id = f"LP-{len(pair_first_seen) + 1:03d}"
                pair_first_seen[raw_pair] = pair_id
                unique_pairs[pair_id] = {
                    "pair_id": pair_id,
                    "left_link_offset": left_link,
                    "right_link_offset": right_link,
                    "link_relocation_delta": right_link - left_link,
                    "link_offsets_in_image_both": bool(
                        0 <= left_link < left.size
                        and 0 <= right_link < right.size
                    ),
                    "use_classification": left_role,
                    "occurrences": [],
                }
            occurrence = {
                "flow_ordinal": flow,
                "word_index": word_index,
                "pair_id": pair_id,
                "use_classification": left_role,
                "link_relocation_delta": right_link - left_link,
                "raw_pointer_values_included": False,
                "absolute_runtime_addresses_included": False,
            }
            occurrences.append(occurrence)
            unique_pairs[pair_id]["occurrences"].append(
                {
                    "flow_ordinal": flow,
                    "word_index": word_index,
                }
            )

    for pair in unique_pairs.values():
        eligible = (
            pair["use_classification"] == "INDIRECT_CONTROL_TARGET"
        )
        pair["code_anchor_eligible"] = eligible
        if eligible:
            pair["bounded_search"] = _bounded_matches(
                left,
                right,
                left_link_offset=int(pair["left_link_offset"]),
                right_link_offset=int(pair["right_link_offset"]),
                structural_delta=structural_delta,
                search_radius=search_radius,
            )
        else:
            pair["bounded_search"] = {
                "performed": False,
                "reason": "NON_CONTROL_LITERAL",
                "bilateral_code_anchor_count": 0,
                "matching_common_corrections": [],
            }

    grouped: dict[int, list[dict[str, object]]] = defaultdict(list)
    for pair in unique_pairs.values():
        grouped[int(pair["link_relocation_delta"])].append(pair)

    families = []
    confirmed_corrections = []
    for family_index, (delta, pairs) in enumerate(
        sorted(grouped.items()), start=1
    ):
        correction_sets = [
            set(
                int(value)
                for value in pair["bounded_search"].get(
                    "matching_common_corrections", []
                )
            )
            for pair in pairs
            if pair["code_anchor_eligible"]
        ]
        eligible_with_matches = [
            values for values in correction_sets if values
        ]
        intersection = (
            set.intersection(*eligible_with_matches)
            if eligible_with_matches
            else set()
        )
        eligible_count = sum(
            bool(values) for values in correction_sets
        )
        status = _family_status(
            unique_pair_count=len(pairs),
            code_eligible_pair_count=len(correction_sets),
            eligible_pair_count=eligible_count,
            common_corrections=intersection,
        )
        correction = (
            next(iter(intersection))
            if len(intersection) == 1
            else None
        )
        if status.startswith("CONFIRMED") and correction is not None:
            confirmed_corrections.append(correction)
        occurrence_count = sum(
            len(pair["occurrences"]) for pair in pairs
        )
        families.append(
            {
                "family_id": f"LF-{family_index:03d}",
                "link_relocation_delta": delta,
                "relative_file_correction": (
                    structural_delta - delta
                ),
                "occurrence_count": occurrence_count,
                "unique_pair_count": len(pairs),
                "use_classification_counts": dict(
                    sorted(
                        Counter(
                            str(pair["use_classification"])
                            for pair in pairs
                            for _ in pair["occurrences"]
                        ).items()
                    )
                ),
                "code_anchor_eligible_pair_count": len(
                    correction_sets
                ),
                "eligible_pair_with_match_count": eligible_count,
                "common_matching_corrections": sorted(
                    intersection
                ),
                "selected_common_correction": correction,
                "status": status,
                "pair_ids": [str(pair["pair_id"]) for pair in pairs],
            }
        )

    public_pairs = []
    for pair in unique_pairs.values():
        public_search = copy.deepcopy(pair["bounded_search"])
        public_pairs.append(
            {
                "pair_id": pair["pair_id"],
                "link_relocation_delta": pair[
                    "link_relocation_delta"
                ],
                "use_classification": pair["use_classification"],
                "link_offsets_in_image_both": pair[
                    "link_offsets_in_image_both"
                ],
                "occurrences": copy.deepcopy(pair["occurrences"]),
                "code_anchor_eligible": pair[
                    "code_anchor_eligible"
                ],
                "bounded_search": public_search,
                "raw_pointer_values_included": False,
                "absolute_runtime_addresses_included": False,
            }
        )

    confirmed_family_count = sum(
        str(family["status"]).startswith("CONFIRMED")
        for family in families
    )
    classification = {
        "pool_entry_occurrence_count": len(occurrences),
        "unique_link_pair_count": len(unique_pairs),
        "link_relocation_family_count": len(families),
        "structural_pool_relocation_delta": structural_delta,
        "confirmed_piecewise_family_count": confirmed_family_count,
        "confirmed_common_corrections": sorted(
            set(confirmed_corrections)
        ),
        "all_link_offsets_in_image_both": all(
            bool(pair["link_offsets_in_image_both"])
            for pair in unique_pairs.values()
        ),
        "cross_release_link_delta_atlas": "CONFIRMED",
        "piecewise_link_to_file_map": (
            "CONFIRMED_FOR_GATED_FAMILIES"
            if confirmed_family_count
            else "NOT_ESTABLISHED"
        ),
        "single_cross_release_link_relocation_delta": "DISPROVED",
        "universal_runtime_to_file_mapping": "NOT_ESTABLISHED",
        "actual_runtime_callee": "OPEN",
    }
    return {
        "schema": "phoenix-mmi.piecewise-link-map-comparison/v1",
        "analysis_mode": (
            "read-only-static-bounded-piecewise-link-address-map"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "classification": classification,
        "occurrences": occurrences,
        "unique_pairs": public_pairs,
        "families": families,
        "limits": {
            "source_session": 30,
            "literal_pool_pairs_only": True,
            "pool_entries_paired_by_structural_word_ordinal": True,
            "search_radius_bytes": search_radius,
            "search_step_bytes": _SEARCH_STEP,
            "code_window_bytes": _CODE_WINDOW_BYTES,
            "one_dimensional_structural_delta_preserved": True,
            "non_control_literals_code_searched": False,
            "minimum_independent_pairs_for_family_confirmation": 2,
            "arbitrary_global_code_search_performed": False,
            "dynamic_or_loader_mapping_observed": False,
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "The paired literal pools contain multiple cross-release "
            "link-address relocation families, so one universal direct "
            "runtime-base subtraction cannot describe the tested entries. "
            "A family becomes a file-layout map piece only when at least "
            "two distinct link pairs share one bounded, bilateral strict "
            "code correction. Single-pair and unmatched families remain "
            "provisional or open; no result alone identifies a runtime "
            "callee."
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


def update_operational_graph_v24(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v24"
    classification = comparison["classification"]
    graph["nodes"].extend(
        [
            {
                "id": "literal-pool-link-delta-atlas",
                "label": "Literal-pool cross-release link-delta atlas",
                "status": "CONFIRMED_STRUCTURAL",
                "family_count": classification[
                    "link_relocation_family_count"
                ],
                "evidence": ["S031-01", "RQ-100"],
            },
            {
                "id": "piecewise-link-file-map",
                "label": "Gated piecewise link-address/file-layout map",
                "status": classification["piecewise_link_to_file_map"],
                "confirmed_family_count": classification[
                    "confirmed_piecewise_family_count"
                ],
                "evidence": ["S031-02", "S031-03", "RQ-101"],
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "handoff-target-literal-pools",
                "target": "literal-pool-link-delta-atlas",
                "relation": (
                    "pool entries split into cross-release relocation "
                    "families"
                ),
                "status": "CONFIRMED_STRUCTURAL",
            },
            {
                "source": "literal-pool-link-delta-atlas",
                "target": "piecewise-link-file-map",
                "relation": (
                    "bounded code anchors gate each candidate map piece"
                ),
                "status": classification[
                    "piecewise_link_to_file_map"
                ],
            },
            {
                "source": "piecewise-link-file-map",
                "target": "runtime-linkage-owner-ingress",
                "relation": (
                    "a map piece constrains offsets but does not identify "
                    "the selected runtime callee"
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


def correlate_piecewise_link_map(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.piecewise-link-map-correlation/v1",
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
        "operational_graph": update_operational_graph_v24(
            prior_correlation["operational_graph"],
            comparison,
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_piecewise_link_map_report(
    report: dict[str, object],
) -> dict[str, object]:
    """Return a detached report that already excludes raw link values."""

    return copy.deepcopy(report)

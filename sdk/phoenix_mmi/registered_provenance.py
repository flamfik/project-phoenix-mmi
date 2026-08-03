"""Registered external-provenance audit for the Session 038 micro-island.

The analyzer consumes only evidence already registered by earlier sessions.
It does not search firmware for new pointers, descriptors, strings or code.
File-relative intervals are used solely to test whether a prior evidence pair
touches the fixed 240-byte component in both releases.
"""

from __future__ import annotations

import copy
from collections import Counter
from typing import Protocol


_ADJACENT_DISTANCE = 64
_NEAR_DISTANCE = 4096

_SCHEMAS = {
    "reference_left": "phoenix-mmi.reference-graph/v1",
    "reference_right": "phoenix-mmi.reference-graph/v1",
    "descriptor_lineage": (
        "phoenix-mmi.descriptor-producer-lineage-comparison/v1"
    ),
    "literal_pool": "phoenix-mmi.literal-pool-boundary-comparison/v1",
    "breakpoints": "phoenix-mmi.relocation-breakpoint-comparison/v1",
    "descriptors": "phoenix-mmi.relocation-descriptor-comparison/v1",
}

_FAMILIES = (
    "REFERENCE_GRAPH_TARGET",
    "REFERENCE_GRAPH_WORD",
    "REFERENCE_GRAPH_DESCRIPTOR",
    "DESCRIPTOR_PRODUCER_LINEAGE",
    "LITERAL_POOL_STORAGE",
    "LITERAL_POOL_SUCCESSOR_CODE",
    "DIRECT_LINK_CODE_ANCHOR",
    "RELOCATION_SUPPORT_ZONE",
    "REORDER_DESCRIPTOR",
)


class _Reader(Protocol):
    def sha256(self) -> str: ...


def _interval(start: int, end: int | None = None) -> dict[str, int]:
    final = start + 1 if end is None else end
    if start < 0 or final <= start:
        raise ValueError("registered interval must be positive and non-empty")
    return {"start": start, "end": final}


def _add_pair(
    rows: list[dict[str, object]],
    *,
    evidence_id: str,
    family: str,
    source_session: int,
    left: dict[str, int],
    right: dict[str, int],
    evidence_role: str,
    explicit_owner_edge: bool = False,
) -> None:
    rows.append(
        {
            "evidence_id": evidence_id,
            "family": family,
            "source_session": source_session,
            "left": left,
            "right": right,
            "evidence_role": evidence_role,
            "explicit_owner_edge": explicit_owner_edge,
        }
    )


def _hash_from_reference(report: dict[str, object]) -> str:
    return str(report["artifact"]["sha256"])


def _validate_registry_schemas(registries: dict[str, dict[str, object]]) -> None:
    if set(registries) != set(_SCHEMAS):
        raise ValueError("registered evidence set differs from frozen contract")
    for key, schema in _SCHEMAS.items():
        if registries[key].get("schema") != schema:
            raise ValueError(f"unsupported {key} registry schema")


def _validate_hashes(
    left_hash: str,
    right_hash: str,
    registries: dict[str, dict[str, object]],
) -> None:
    left_sources = (
        _hash_from_reference(registries["reference_left"]),
        str(registries["descriptor_lineage"]["left_artifact_sha256"]),
        str(registries["literal_pool"]["left_artifact_sha256"]),
        str(registries["breakpoints"]["left_artifact_sha256"]),
        str(registries["descriptors"]["left_artifact_sha256"]),
    )
    right_sources = (
        _hash_from_reference(registries["reference_right"]),
        str(registries["descriptor_lineage"]["right_artifact_sha256"]),
        str(registries["literal_pool"]["right_artifact_sha256"]),
        str(registries["breakpoints"]["right_artifact_sha256"]),
        str(registries["descriptors"]["right_artifact_sha256"]),
    )
    if any(item != left_hash for item in left_sources):
        raise ValueError("left registered-evidence hash mismatch")
    if any(item != right_hash for item in right_sources):
        raise ValueError("right registered-evidence hash mismatch")


def _reference_pairs(
    left: dict[str, object], right: dict[str, object]
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    left_anchors = {str(row["label"]): row for row in left["anchors"]}
    right_anchors = {str(row["label"]): row for row in right["anchors"]}
    if left_anchors.keys() != right_anchors.keys():
        raise ValueError("reference-graph anchor labels differ")
    for label in sorted(left_anchors.keys() & right_anchors.keys()):
        left_anchor = left_anchors[label]
        right_anchor = right_anchors[label]
        _add_pair(
            rows,
            evidence_id=f"S007-TARGET-{label}",
            family="REFERENCE_GRAPH_TARGET",
            source_session=7,
            left=_interval(int(left_anchor["target_file_offset"])),
            right=_interval(int(right_anchor["target_file_offset"])),
            evidence_role="REGISTERED_RUNTIME_ADDRESS_TARGET",
        )
        left_words = left_anchor["exact_runtime_word_occurrences"]
        right_words = right_anchor["exact_runtime_word_occurrences"]
        if len(left_words) != len(right_words):
            raise ValueError(
                f"reference-word occurrence count differs for {label}"
            )
        for ordinal, (left_word, right_word) in enumerate(
            zip(left_words, right_words)
        ):
            _add_pair(
                rows,
                evidence_id=f"S007-WORD-{label}-{ordinal:02d}",
                family="REFERENCE_GRAPH_WORD",
                source_session=7,
                left=_interval(int(left_word["file_offset"])),
                right=_interval(int(right_word["file_offset"])),
                evidence_role="REGISTERED_REFERENCE_WORD_STORAGE",
                explicit_owner_edge=bool(
                    left_word["pc_relative_mov_l_referrer_offsets"]
                    and right_word["pc_relative_mov_l_referrer_offsets"]
                ),
            )
    if len(left["descriptor_candidates"]) != len(
        right["descriptor_candidates"]
    ):
        raise ValueError("reference-graph descriptor counts differ")
    for ordinal, (left_row, right_row) in enumerate(
        zip(left["descriptor_candidates"], right["descriptor_candidates"])
    ):
        _add_pair(
            rows,
            evidence_id=f"S007-DESCRIPTOR-{ordinal:02d}",
            family="REFERENCE_GRAPH_DESCRIPTOR",
            source_session=7,
            left=_interval(int(left_row["anchor_file_offset"])),
            right=_interval(int(right_row["anchor_file_offset"])),
            evidence_role="REGISTERED_RELOCATED_DESCRIPTOR_ANCHOR",
            explicit_owner_edge=bool(
                left_row["pc_relative_mov_l_referrer_offsets"]
                and right_row["pc_relative_mov_l_referrer_offsets"]
            ),
        )
    return rows


def _descriptor_lineage_pairs(
    report: dict[str, object],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    point_fields = (
        ("dispatch_call_site_offset", "DISPATCH_CALL_SITE"),
        ("producer_call_site_offset", "PRODUCER_CALL_SITE"),
        ("producer_target_file_offset", "PRODUCER_TARGET"),
        ("producer_child_target_file_offset", "PRODUCER_CHILD_TARGET"),
    )
    for pair_index, pair in enumerate(report["producer_pairs"]):
        for field, role in point_fields:
            left_value = pair["left"].get(field)
            right_value = pair["right"].get(field)
            if not isinstance(left_value, int) or not isinstance(right_value, int):
                continue
            _add_pair(
                rows,
                evidence_id=f"S017-{pair_index:02d}-{role}",
                family="DESCRIPTOR_PRODUCER_LINEAGE",
                source_session=17,
                left=_interval(left_value),
                right=_interval(right_value),
                evidence_role=role,
                explicit_owner_edge=bool(
                    pair["cross_version_producer_target_promoted"]
                    and role in {"PRODUCER_TARGET", "PRODUCER_CHILD_TARGET"}
                ),
            )
    return rows


def _literal_pool_pairs(
    report: dict[str, object],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for pair in report["target_pairs"]:
        flow = int(pair["flow_ordinal"])
        left = pair["left"]
        right = pair["right"]
        _add_pair(
            rows,
            evidence_id=f"S030-FLOW-{flow:02d}-TARGET-WORD",
            family="LITERAL_POOL_STORAGE",
            source_session=30,
            left=_interval(int(left["registered_target_file_offset"])),
            right=_interval(int(right["registered_target_file_offset"])),
            evidence_role="REGISTERED_TARGET_WORD_STORAGE",
        )
        _add_pair(
            rows,
            evidence_id=f"S030-FLOW-{flow:02d}-POOL",
            family="LITERAL_POOL_STORAGE",
            source_session=30,
            left=_interval(
                int(left["pool"]["pool_start_file_offset"]),
                int(left["pool"]["pool_end_file_offset"]),
            ),
            right=_interval(
                int(right["pool"]["pool_start_file_offset"]),
                int(right["pool"]["pool_end_file_offset"]),
            ),
            evidence_role="COMPLETE_PC_RELATIVE_LITERAL_POOL",
        )
        _add_pair(
            rows,
            evidence_id=f"S030-FLOW-{flow:02d}-SUCCESSOR",
            family="LITERAL_POOL_SUCCESSOR_CODE",
            source_session=30,
            left=_interval(
                int(left["pool_end_successor"]["entry_file_offset"])
            ),
            right=_interval(
                int(right["pool_end_successor"]["entry_file_offset"])
            ),
            evidence_role="STRICT_ADJACENT_CODE_ENTRY_NOT_RUNTIME_CALLEE",
        )
    return rows


def _breakpoint_pairs(
    report: dict[str, object],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for anchor in report["direct_link_code_anchors"]:
        _add_pair(
            rows,
            evidence_id=f"S032-{anchor['anchor_id']}",
            family="DIRECT_LINK_CODE_ANCHOR",
            source_session=32,
            left=_interval(int(anchor["left_file_offset"])),
            right=_interval(int(anchor["right_file_offset"])),
            evidence_role="BILATERAL_BOUNDED_CODE_ENTRY",
        )
    for zone in report["support_zones"]:
        _add_pair(
            rows,
            evidence_id=f"S032-{zone['zone_id']}",
            family="RELOCATION_SUPPORT_ZONE",
            source_session=32,
            left=_interval(int(zone["left_start"]), int(zone["left_end"])),
            right=_interval(int(zone["right_start"]), int(zone["right_end"])),
            evidence_role=str(zone["evidence_class"]),
        )
    return rows


def _reorder_descriptor_pairs(
    report: dict[str, object],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for ordinal, pair in enumerate(report["bilateral_descriptor_pairs"]):
        left = pair.get("left", {})
        right = pair.get("right", {})
        left_start = left.get("table_file_offset")
        right_start = right.get("table_file_offset")
        width = pair.get("record_width")
        count = pair.get("record_count")
        if not all(isinstance(value, int) for value in (
            left_start, right_start, width, count
        )):
            continue
        length = int(width) * int(count)
        _add_pair(
            rows,
            evidence_id=f"S033-DESCRIPTOR-{ordinal:02d}",
            family="REORDER_DESCRIPTOR",
            source_session=33,
            left=_interval(int(left_start), int(left_start) + length),
            right=_interval(int(right_start), int(right_start) + length),
            evidence_role="BILATERAL_REORDER_DESCRIPTOR_TABLE",
            explicit_owner_edge=bool(
                pair.get("both_tables_pc_relative_referenced", False)
            ),
        )
    return rows


def build_registered_evidence(
    registries: dict[str, dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Normalize the fixed earlier-session registries into bilateral pairs."""

    _validate_registry_schemas(registries)
    rows = [
        *_reference_pairs(
            registries["reference_left"], registries["reference_right"]
        ),
        *_descriptor_lineage_pairs(registries["descriptor_lineage"]),
        *_literal_pool_pairs(registries["literal_pool"]),
        *_breakpoint_pairs(registries["breakpoints"]),
        *_reorder_descriptor_pairs(registries["descriptors"]),
    ]
    counts = Counter(str(row["family"]) for row in rows)
    family_rows = [
        {
            "family": family,
            "registered_pair_count": counts[family],
            "source_sessions": sorted(
                {
                    int(row["source_session"])
                    for row in rows
                    if row["family"] == family
                }
            ),
        }
        for family in _FAMILIES
    ]
    return rows, family_rows


def _distance(
    target: dict[str, int], evidence: dict[str, int]
) -> int:
    if target["start"] < evidence["end"] and evidence["start"] < target["end"]:
        return 0
    if evidence["end"] <= target["start"]:
        return target["start"] - evidence["end"]
    return evidence["start"] - target["end"]


def _intersects(
    target: dict[str, int], evidence: dict[str, int]
) -> bool:
    return (
        target["start"] < evidence["end"]
        and evidence["start"] < target["end"]
    )


def evaluate_registered_pairs(
    target: dict[str, dict[str, int]],
    pairs: list[dict[str, object]],
) -> dict[str, object]:
    """Classify bilateral interval distance under the frozen bands."""

    evaluated = []
    for pair in pairs:
        left_distance = _distance(target["left"], pair["left"])
        right_distance = _distance(target["right"], pair["right"])
        bilateral = max(left_distance, right_distance)
        left_intersects = _intersects(target["left"], pair["left"])
        right_intersects = _intersects(target["right"], pair["right"])
        if left_intersects and right_intersects:
            relation = "BILATERAL_EXACT_INTERSECTION"
        elif bilateral <= _ADJACENT_DISTANCE:
            relation = "BILATERAL_ADJACENT"
        elif bilateral <= _NEAR_DISTANCE:
            relation = "BILATERAL_NEAR"
        else:
            relation = "OUTSIDE_FROZEN_NEIGHBORHOOD"
        evaluated.append(
            {
                "evidence_id": pair["evidence_id"],
                "family": pair["family"],
                "evidence_role": pair["evidence_role"],
                "left_distance": left_distance,
                "right_distance": right_distance,
                "bilateral_distance": bilateral,
                "left_intersects": left_intersects,
                "right_intersects": right_intersects,
                "relation": relation,
                "explicit_owner_edge": pair["explicit_owner_edge"],
            }
        )
    evaluated.sort(
        key=lambda row: (
            int(row["bilateral_distance"]),
            str(row["family"]),
            str(row["evidence_id"]),
        )
    )
    exact = [
        row for row in evaluated
        if row["relation"] == "BILATERAL_EXACT_INTERSECTION"
    ]
    adjacent = [
        row for row in evaluated
        if row["relation"] == "BILATERAL_ADJACENT"
    ]
    near = [
        row for row in evaluated
        if row["relation"] == "BILATERAL_NEAR"
    ]
    owner_edges = [row for row in exact if row["explicit_owner_edge"]]
    owner_families = {str(row["family"]) for row in owner_edges}
    return {
        "registered_pair_count": len(evaluated),
        "bilateral_exact_count": len(exact),
        "bilateral_adjacent_count": len(adjacent),
        "bilateral_near_count": len(near),
        "exact_owner_edge_count": len(owner_edges),
        "exact_owner_family_count": len(owner_families),
        "nearest": evaluated[:3],
        "bilateral_exact_matches": exact,
        "bilateral_adjacent_matches": adjacent,
        "bilateral_near_matches": near,
        "owner_gate_passed": len(owner_families) >= 2,
    }


def _validate_prior(
    prior: dict[str, object],
) -> tuple[dict[str, dict[str, int]], dict[str, dict[str, int]]]:
    if prior.get("schema") != "phoenix-mmi.run-gap-topology-comparison/v1":
        raise ValueError("unsupported Session 038 schema")
    classification = prior["classification"]
    if (
        classification.get("micro_island_structural_model")
        != "STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON"
    ):
        raise ValueError("Session 038 stable skeleton gate failed")
    if classification.get("exact_section_boundary") != "OPEN":
        raise ValueError("Session 038 exact-boundary status changed")
    component = prior["rz012"]["dominant_promoted_component"]
    if component is None or not component.get("promotion_gate_passed"):
        raise ValueError("Session 038 promoted component is absent")
    start = int(component["start"])
    end = int(component["end"])
    if end - start != int(component["span"]) or int(component["span"]) != 240:
        raise ValueError("Session 038 component geometry differs")
    contract = prior["search_contract"]
    rz012_delta = int(contract["left_delta"])
    rz013_delta = int(contract["right_delta"])
    source = _interval(start, end)
    rz012 = {
        "left": source,
        "right": _interval(start + rz012_delta, end + rz012_delta),
    }
    rz013 = {
        "left": source,
        "right": _interval(start + rz013_delta, end + rz013_delta),
    }
    return rz012, rz013


def _bracket_context(
    breakpoints: dict[str, object],
    target: dict[str, dict[str, int]],
) -> dict[str, object]:
    brackets = [
        row
        for row in breakpoints["breakpoint_brackets"]
        if row["classification"] == "SECTION_REORDER_BRACKET"
    ]
    if len(brackets) != 1:
        raise ValueError("expected exactly one registered reorder bracket")
    bracket = brackets[0]
    contained = bool(
        int(bracket["left_file_lower_bound"]) <= target["left"]["start"]
        and target["left"]["end"] <= int(bracket["left_file_upper_bound"])
    )
    return {
        "bracket_id": bracket["bracket_id"],
        "left_component_contained": contained,
        "classification": (
            "CONFIRMED_REORDER_BRACKET_CONTEXT_ONLY"
            if contained
            else "OUTSIDE_REGISTERED_REORDER_BRACKET"
        ),
        "exact_breakpoint_asserted": False,
        "continuous_mapping_asserted": False,
    }


def analyze_registered_provenance(
    left_reader: _Reader,
    right_reader: _Reader,
    prior: dict[str, object],
    registries: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Audit only frozen, previously registered evidence families."""

    left_hash = left_reader.sha256()
    right_hash = right_reader.sha256()
    if left_hash != prior.get("left_artifact_sha256"):
        raise ValueError("left principal-image hash differs from Session 038")
    if right_hash != prior.get("right_artifact_sha256"):
        raise ValueError("right principal-image hash differs from Session 038")
    _validate_registry_schemas(registries)
    _validate_hashes(left_hash, right_hash, registries)
    rz012_target, rz013_target = _validate_prior(prior)
    pairs, family_rows = build_registered_evidence(registries)
    rz012 = evaluate_registered_pairs(rz012_target, pairs)
    rz013 = evaluate_registered_pairs(rz013_target, pairs)
    context = _bracket_context(registries["breakpoints"], rz012_target)

    if rz012["owner_gate_passed"]:
        provenance = "SUPPORTED_BY_TWO_REGISTERED_OWNER_EDGE_FAMILIES"
        semantic_owner = "PROBABLE_REGISTERED_OWNER"
    elif rz012["bilateral_exact_count"]:
        provenance = "REGISTERED_STRUCTURAL_INTERSECTION_ONLY"
        semantic_owner = "OPEN"
    else:
        provenance = "NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES"
        semantic_owner = "OPEN"

    return {
        "schema": "phoenix-mmi.registered-provenance-comparison/v1",
        "analysis_mode": (
            "read-only-static-prior-registry-interval-audit"
        ),
        "left_artifact_sha256": left_hash,
        "right_artifact_sha256": right_hash,
        "source_session038_schema": prior["schema"],
        "target": {
            "component_id": prior["rz012"][
                "dominant_promoted_component"
            ]["component_id"],
            "left": rz012_target["left"],
            "rz012_right": rz012_target["right"],
            "rz013_negative_right": rz013_target["right"],
            "span": 240,
        },
        "search_contract": {
            "registered_source_sessions": [7, 17, 30, 32, 33],
            "registered_family_count": len(_FAMILIES),
            "adjacent_distance_bytes": _ADJACENT_DISTANCE,
            "near_distance_bytes": _NEAR_DISTANCE,
            "bilateral_intersection_required": True,
            "semantic_owner_requires_independent_owner_edge_families": 2,
            "whole_image_search_performed": False,
            "new_pointer_search_performed": False,
            "new_descriptor_search_performed": False,
            "new_string_or_code_scan_performed": False,
            "adaptive_distance_used": False,
        },
        "registered_families": family_rows,
        "registered_pair_count": len(pairs),
        "registered_explicit_owner_edge_pair_count": sum(
            bool(pair["explicit_owner_edge"]) for pair in pairs
        ),
        "reorder_context": context,
        "rz012": rz012,
        "rz013_negative_control": rz013,
        "classification": {
            "component_contract": "REPLAYED_SESSION038_STABLE_SKELETON",
            "reorder_bracket_context": context["classification"],
            "registered_external_provenance": provenance,
            "registered_owner_edge": (
                "FOUND"
                if rz012["exact_owner_edge_count"]
                else "NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES"
            ),
            "negative_control_owner_edge": (
                "FOUND"
                if rz013["exact_owner_edge_count"]
                else "NOT_FOUND"
            ),
            "semantic_owner": semantic_owner,
            "exact_section_boundary": "OPEN",
            "runtime_loader_transform": "NOT_OBSERVED",
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "The 240-byte skeleton lies inside the registered RB-015 "
            "reorder bracket, but no previously registered bilateral "
            "reference, descriptor, literal-pool, code-anchor or support-"
            "zone pair intersects it under the frozen owner gate. This is "
            "a bounded provenance negative, not proof that the component "
            "has no owner."
        ),
        "limits": [
            "Only reports from Sessions 007, 017, 030, 032 and 033 are normalized.",
            "No new firmware offset, pointer, descriptor, string or instruction search is performed.",
            "Distances describe file-layout proximity and do not imply dataflow.",
            "Support-zone or reorder-bracket containment is context, not ownership.",
            "Unregistered, encoded, computed, external or runtime-created references remain open.",
            "The exact section boundary and loader mechanism remain open.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_component_bytes_included": False,
            "instruction_bytes_included": False,
            "mnemonic_names_included": False,
            "raw_strings_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
            "map_payload_included": False,
        },
    }


def update_operational_graph_v32(
    prior_graph: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v32"
    graph["nodes"].extend(
        [
            {
                "id": "reorder-rz012-registered-provenance",
                "status": report["classification"][
                    "registered_external_provenance"
                ],
                "semantic_status": "BOUNDED_REGISTRY_AUDIT_ONLY",
                "evidence": report["interpretation"],
            },
            {
                "id": "reorder-rz012-semantic-owner",
                "status": report["classification"]["semantic_owner"],
                "semantic_status": "UNRESOLVED",
                "evidence": (
                    "No two independent exact registered owner-edge "
                    "families identify the component."
                ),
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-rz012-run-gap-skeleton",
                "target": "reorder-rz012-registered-provenance",
                "status": report["classification"][
                    "registered_external_provenance"
                ],
                "relation": "audits-frozen-registered-evidence-families",
            },
            {
                "source": "reorder-rz012-registered-provenance",
                "target": "reorder-rz012-semantic-owner",
                "status": "BOUNDED_NEGATIVE",
                "relation": "does-not-establish-owner-under-frozen-registry",
            },
        ]
    )
    return graph


def correlate_registered_provenance(
    prior_correlation: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.registered-provenance-correlation/v1",
        "analysis_mode": report["analysis_mode"],
        "firmware": copy.deepcopy(report["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_provenance_edge": "NOT_ASSERTED",
        "interpretation": report["interpretation"],
        "operational_graph": update_operational_graph_v32(
            prior_correlation["operational_graph"], report
        ),
        "publication_safety": copy.deepcopy(report["publication_safety"]),
    }


def build_public_registered_provenance_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

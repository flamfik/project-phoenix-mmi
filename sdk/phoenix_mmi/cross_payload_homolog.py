"""Fixed-signature cross-payload homolog search for Session 040.

The search uses only five exact 25-byte runs already registered by
Session 038.  Raw signature bytes remain internal.  Candidate payloads are
read statically from the update discs and are never executed or extracted
into publication output.
"""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
import hashlib
import math
from pathlib import PurePosixPath
from typing import Iterable, Protocol


_ELIGIBLE_EXTENSIONS = frozenset({".BIN", ".HEX", ".LOD", ".YIM", ".SW"})
_COMPONENT_SPAN = 240
_ANCHOR_LENGTH = 25
_ANCHOR_COUNT = 5
_ANCHOR_TOTAL_BYTES = _ANCHOR_LENGTH * _ANCHOR_COUNT
_MINIMUM_DISTINCT_ANCHOR_PATTERNS = 3
_MINIMUM_DISTINCT_BYTES = 8
_MINIMUM_ENTROPY = 2.5
_MINIMUM_STRONG_SIMILARITY = 0.75
_MAXIMUM_FIRST_ANCHOR_OCCURRENCES = 4096
_MAXIMUM_GEOMETRY_MATCHES = 256


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def sha256(self) -> str: ...


@dataclass(frozen=True)
class PayloadInput:
    disc: str
    path: str
    data: bytes


def payload_member_eligible(path: str, size: int) -> bool:
    """Return whether a member is in the frozen payload corpus."""

    extension = PurePosixPath(path).suffix.upper()
    return extension in _ELIGIBLE_EXTENSIONS and size >= _COMPONENT_SPAN


def _entropy(data: bytes) -> float:
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _validate_priors(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    session039: dict[str, object],
) -> dict[str, int]:
    if session038.get("schema") != (
        "phoenix-mmi.run-gap-topology-comparison/v1"
    ):
        raise ValueError("unsupported Session 038 schema")
    if session039.get("schema") != (
        "phoenix-mmi.registered-provenance-comparison/v1"
    ):
        raise ValueError("unsupported Session 039 schema")
    left_hash = left_reader.sha256()
    right_hash = right_reader.sha256()
    for report in (session038, session039):
        if report.get("left_artifact_sha256") != left_hash:
            raise ValueError("left principal-image hash differs")
        if report.get("right_artifact_sha256") != right_hash:
            raise ValueError("right principal-image hash differs")
    if session038["classification"].get(
        "micro_island_structural_model"
    ) != "STABLE_SPARSE_SINGLE_BYTE_DIFFERENCE_SKELETON":
        raise ValueError("Session 038 stable-skeleton gate failed")
    if session039["classification"].get(
        "registered_external_provenance"
    ) != "NOT_FOUND_UNDER_FROZEN_REGISTERED_FAMILIES":
        raise ValueError("Session 039 prior-registry result changed")
    if session039["classification"].get("semantic_owner") != "OPEN":
        raise ValueError("Session 039 semantic-owner status changed")

    component = session038["rz012"]["dominant_promoted_component"]
    left_start = int(component["start"])
    left_end = int(component["end"])
    target = session039["target"]
    right_start = int(target["rz012_right"]["start"])
    right_end = int(target["rz012_right"]["end"])
    if (
        left_end - left_start != _COMPONENT_SPAN
        or right_end - right_start != _COMPONENT_SPAN
        or int(target["left"]["start"]) != left_start
        or int(target["left"]["end"]) != left_end
    ):
        raise ValueError("component geometry differs across Sessions 038-039")
    control_start = int(session038["search_contract"]["overlap_start"])
    control_end = control_start + _COMPONENT_SPAN
    if not (
        0 <= control_start < control_end <= left_reader.size
        and control_end <= left_start
    ):
        raise ValueError("fixed control interval is invalid or overlaps target")
    return {
        "left_start": left_start,
        "left_end": left_end,
        "right_start": right_start,
        "right_end": right_end,
        "control_start": control_start,
        "control_end": control_end,
    }


def _anchor_rows(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    geometry: dict[str, int],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    run_by_id = {
        str(run["run_id"]): run for run in session038["rz012"]["runs"]
    }
    component = session038["rz012"]["dominant_promoted_component"]
    selected = [
        run_by_id[str(run_id)]
        for run_id in component["run_ids"]
        if int(run_by_id[str(run_id)]["length"]) == _ANCHOR_LENGTH
    ]
    if len(selected) != _ANCHOR_COUNT:
        raise ValueError("expected exactly five registered 25-byte runs")
    selected.sort(key=lambda row: int(row["start"]))

    anchors: list[dict[str, object]] = []
    controls: list[dict[str, object]] = []
    target_material: list[bytes] = []
    control_material: list[bytes] = []
    for ordinal, run in enumerate(selected):
        relative = int(run["start"]) - geometry["left_start"]
        if not 0 <= relative <= _COMPONENT_SPAN - _ANCHOR_LENGTH:
            raise ValueError("registered anchor falls outside component")
        left_data = left_reader.read(
            geometry["left_start"] + relative, _ANCHOR_LENGTH
        )
        right_data = right_reader.read(
            geometry["right_start"] + relative, _ANCHOR_LENGTH
        )
        control_data = left_reader.read(
            geometry["control_start"] + relative, _ANCHOR_LENGTH
        )
        if (
            len(left_data) != _ANCHOR_LENGTH
            or len(right_data) != _ANCHOR_LENGTH
            or len(control_data) != _ANCHOR_LENGTH
        ):
            raise ValueError("truncated signature anchor")
        if left_data != right_data:
            raise ValueError("Session 038 exact anchor no longer agrees")
        target_quality = {
            "distinct_byte_count": len(set(left_data)),
            "entropy": round(_entropy(left_data), 8),
        }
        control_quality = {
            "distinct_byte_count": len(set(control_data)),
            "entropy": round(_entropy(control_data), 8),
        }
        for label, quality in (
            ("target", target_quality),
            ("control", control_quality),
        ):
            if (
                int(quality["distinct_byte_count"])
                < _MINIMUM_DISTINCT_BYTES
                or float(quality["entropy"]) < _MINIMUM_ENTROPY
            ):
                raise ValueError(f"{label} anchor failed fixed quality gate")
        if left_data == control_data:
            raise ValueError("target and control anchors are not independent")
        anchor_id = f"SIG-{ordinal + 1:02d}"
        anchors.append(
            {
                "anchor_id": anchor_id,
                "relative_offset": relative,
                "length": _ANCHOR_LENGTH,
                **target_quality,
                "shared_exact_between_releases": True,
                "_internal_bytes": left_data,
            }
        )
        controls.append(
            {
                "anchor_id": f"CTL-{ordinal + 1:02d}",
                "relative_offset": relative,
                "length": _ANCHOR_LENGTH,
                **control_quality,
                "_internal_bytes": control_data,
            }
        )
        target_material.append(left_data)
        control_material.append(control_data)
    if len(set(target_material)) < _MINIMUM_DISTINCT_ANCHOR_PATTERNS:
        raise ValueError("target signature lacks three distinct patterns")
    if set(target_material) & set(control_material):
        raise ValueError("target and control signature sets overlap")
    return anchors, controls


def derive_cross_payload_signature(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    session039: dict[str, object],
) -> dict[str, object]:
    """Derive the frozen target and control signatures without scanning payloads."""

    geometry = _validate_priors(
        left_reader, right_reader, session038, session039
    )
    anchors, controls = _anchor_rows(
        left_reader, right_reader, session038, geometry
    )
    left_component = left_reader.read(
        geometry["left_start"], _COMPONENT_SPAN
    )
    right_component = right_reader.read(
        geometry["right_start"], _COMPONENT_SPAN
    )
    control_component = left_reader.read(
        geometry["control_start"], _COMPONENT_SPAN
    )
    if any(
        len(item) != _COMPONENT_SPAN
        for item in (left_component, right_component, control_component)
    ):
        raise ValueError("truncated component or control")
    return {
        "geometry": geometry,
        "anchors": anchors,
        "controls": controls,
        "_internal_left_component": left_component,
        "_internal_right_component": right_component,
        "_internal_control_component": control_component,
    }


def _signature_scan(
    data: bytes,
    anchors: list[dict[str, object]],
    references: tuple[bytes, ...],
) -> dict[str, object]:
    first = anchors[0]
    first_bytes = first["_internal_bytes"]
    first_relative = int(first["relative_offset"])
    occurrence = data.find(first_bytes)
    first_occurrences = 0
    matches = []
    seen_bases: set[int] = set()
    saturated = False
    while occurrence >= 0:
        first_occurrences += 1
        if first_occurrences > _MAXIMUM_FIRST_ANCHOR_OCCURRENCES:
            saturated = True
            break
        base = occurrence - first_relative
        if (
            base not in seen_bases
            and 0 <= base
            and base + _COMPONENT_SPAN <= len(data)
            and all(
                data[
                    base + int(anchor["relative_offset"]) :
                    base
                    + int(anchor["relative_offset"])
                    + int(anchor["length"])
                ]
                == anchor["_internal_bytes"]
                for anchor in anchors
            )
        ):
            seen_bases.add(base)
            window = data[base : base + _COMPONENT_SPAN]
            exact_counts = [
                sum(left == right for left, right in zip(window, reference))
                for reference in references
            ]
            best_exact = max(exact_counts)
            matches.append(
                {
                    "member_offset": base,
                    "anchor_count": len(anchors),
                    "anchor_exact_byte_count": sum(
                        int(anchor["length"]) for anchor in anchors
                    ),
                    "best_component_exact_byte_count": best_exact,
                    "best_component_similarity": round(
                        best_exact / _COMPONENT_SPAN, 8
                    ),
                    "strong_similarity_gate_passed": (
                        best_exact / _COMPONENT_SPAN
                        >= _MINIMUM_STRONG_SIMILARITY
                    ),
                }
            )
            if len(matches) >= _MAXIMUM_GEOMETRY_MATCHES:
                saturated = True
                break
        occurrence = data.find(first_bytes, occurrence + 1)
    return {
        "first_anchor_occurrence_count": first_occurrences,
        "geometry_match_count": len(matches),
        "strong_match_count": sum(
            row["strong_similarity_gate_passed"] for row in matches
        ),
        "scan_saturated": saturated,
        "matches": matches,
    }


def _public_anchor(anchor: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in anchor.items()
        if not key.startswith("_internal")
    }


def _disc_template() -> dict[str, object]:
    return {
        "eligible_member_count": 0,
        "eligible_member_bytes": 0,
        "scanned_member_count": 0,
        "scanned_member_bytes": 0,
        "principal_identity_exclusion_count": 0,
        "extension_counts": {},
        "target_geometry_hit_member_count": 0,
        "target_strong_hit_member_count": 0,
        "control_geometry_hit_member_count": 0,
        "control_strong_hit_member_count": 0,
    }


def analyze_cross_payload_homologs(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    session039: dict[str, object],
    payloads: Iterable[PayloadInput],
) -> dict[str, object]:
    """Scan the fixed eligible corpus using the predeclared signatures."""

    signature = derive_cross_payload_signature(
        left_reader, right_reader, session038, session039
    )
    anchors = signature["anchors"]
    controls = signature["controls"]
    target_references = (
        signature["_internal_left_component"],
        signature["_internal_right_component"],
    )
    control_references = (signature["_internal_control_component"],)
    principal_hashes = {
        left_reader.sha256(),
        right_reader.sha256(),
    }

    disc_rows: dict[str, dict[str, object]] = {}
    unique: dict[str, dict[str, object]] = {}
    eligible_members = 0
    eligible_bytes = 0
    for payload in payloads:
        if not payload_member_eligible(payload.path, len(payload.data)):
            continue
        disc = str(payload.disc)
        disc_row = disc_rows.setdefault(disc, _disc_template())
        extension = PurePosixPath(payload.path).suffix.upper()
        disc_row["eligible_member_count"] += 1
        disc_row["eligible_member_bytes"] += len(payload.data)
        extension_counts = disc_row["extension_counts"]
        extension_counts[extension] = extension_counts.get(extension, 0) + 1
        eligible_members += 1
        eligible_bytes += len(payload.data)

        digest = hashlib.sha256(payload.data).hexdigest()
        if digest in principal_hashes:
            disc_row["principal_identity_exclusion_count"] += 1
            continue
        disc_row["scanned_member_count"] += 1
        disc_row["scanned_member_bytes"] += len(payload.data)
        member = {
            "disc": disc,
            "path": payload.path,
            "size": len(payload.data),
            "extension": extension,
        }
        row = unique.get(digest)
        if row is None:
            target = _signature_scan(
                payload.data, anchors, target_references
            )
            control = _signature_scan(
                payload.data, controls, control_references
            )
            row = {
                "content_sha256": digest,
                "size": len(payload.data),
                "members": [],
                "target": target,
                "control": control,
            }
            unique[digest] = row
        row["members"].append(member)

    for row in unique.values():
        for member in row["members"]:
            disc_row = disc_rows[member["disc"]]
            if row["target"]["geometry_match_count"]:
                disc_row["target_geometry_hit_member_count"] += 1
            if row["target"]["strong_match_count"]:
                disc_row["target_strong_hit_member_count"] += 1
            if row["control"]["geometry_match_count"]:
                disc_row["control_geometry_hit_member_count"] += 1
            if row["control"]["strong_match_count"]:
                disc_row["control_strong_hit_member_count"] += 1

    target_hits = [
        row for row in unique.values()
        if row["target"]["geometry_match_count"]
    ]
    target_strong = [
        row for row in target_hits if row["target"]["strong_match_count"]
    ]
    control_hits = [
        row for row in unique.values()
        if row["control"]["geometry_match_count"]
    ]
    control_strong = [
        row for row in control_hits if row["control"]["strong_match_count"]
    ]
    saturated = [
        row for row in unique.values()
        if row["target"]["scan_saturated"]
        or row["control"]["scan_saturated"]
    ]
    if saturated:
        homolog = "INCONCLUSIVE_SCAN_SATURATED"
    elif control_strong:
        homolog = "MODEL_NOT_DISCRIMINATING_CONTROL_HIT"
    elif target_strong:
        homolog = "CROSS_PAYLOAD_HOMOLOG_SUPPORTED"
    elif target_hits:
        homolog = "ANCHOR_GEOMETRY_CANDIDATE_ONLY"
    else:
        homolog = "NOT_FOUND_UNDER_FIXED_SIGNATURE_MODEL"

    duplicate_groups = sum(
        len(row["members"]) > 1 for row in unique.values()
    )
    return {
        "schema": "phoenix-mmi.cross-payload-homolog-comparison/v1",
        "analysis_mode": (
            "read-only-static-fixed-five-anchor-cross-payload-search"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session038_schema": session038["schema"],
        "source_session039_schema": session039["schema"],
        "target": {
            "component_id": session039["target"]["component_id"],
            "left_interval": {
                "start": signature["geometry"]["left_start"],
                "end": signature["geometry"]["left_end"],
            },
            "right_interval": {
                "start": signature["geometry"]["right_start"],
                "end": signature["geometry"]["right_end"],
            },
            "span": _COMPONENT_SPAN,
        },
        "signature_contract": {
            "anchor_source": "SESSION038_EXACT_RUNS_LENGTH_25",
            "anchor_count": _ANCHOR_COUNT,
            "anchor_length": _ANCHOR_LENGTH,
            "anchor_total_exact_bytes": _ANCHOR_TOTAL_BYTES,
            "minimum_distinct_anchor_patterns": (
                _MINIMUM_DISTINCT_ANCHOR_PATTERNS
            ),
            "distinct_target_anchor_pattern_count": len(
                {row["_internal_bytes"] for row in anchors}
            ),
            "minimum_distinct_bytes": _MINIMUM_DISTINCT_BYTES,
            "minimum_entropy": _MINIMUM_ENTROPY,
            "minimum_strong_component_similarity": (
                _MINIMUM_STRONG_SIMILARITY
            ),
            "maximum_first_anchor_occurrences_per_payload": (
                _MAXIMUM_FIRST_ANCHOR_OCCURRENCES
            ),
            "maximum_geometry_matches_per_payload": (
                _MAXIMUM_GEOMETRY_MATCHES
            ),
            "target_anchors": [_public_anchor(row) for row in anchors],
            "control_source": (
                "SESSION038_OVERLAP_START_SAME_RELATIVE_GEOMETRY"
            ),
            "control_anchors": [_public_anchor(row) for row in controls],
            "target_control_anchor_overlap_count": 0,
            "raw_signature_bytes_included": False,
            "signature_hashes_included": False,
            "adaptive_anchor_selection_used": False,
        },
        "corpus_contract": {
            "disc_ids": sorted(disc_rows),
            "eligible_extensions": sorted(_ELIGIBLE_EXTENSIONS),
            "minimum_member_size": _COMPONENT_SPAN,
            "principal_images_excluded_by_content_sha256": True,
            "eligible_member_count": eligible_members,
            "eligible_member_bytes": eligible_bytes,
            "scanned_member_count": sum(
                int(row["scanned_member_count"])
                for row in disc_rows.values()
            ),
            "scanned_member_bytes": sum(
                int(row["scanned_member_bytes"])
                for row in disc_rows.values()
            ),
            "unique_payload_content_count": len(unique),
            "unique_payload_content_bytes": sum(
                int(row["size"]) for row in unique.values()
            ),
            "duplicate_content_group_count": duplicate_groups,
            "whole_payload_bytes_published": False,
        },
        "disc_summaries": {
            key: value for key, value in sorted(disc_rows.items())
        },
        "target_homologs": target_hits,
        "control_homologs": control_hits,
        "summary": {
            "target_geometry_hit_unique_count": len(target_hits),
            "target_first_anchor_occurrence_count": sum(
                int(row["target"]["first_anchor_occurrence_count"])
                for row in unique.values()
            ),
            "target_strong_hit_unique_count": len(target_strong),
            "target_geometry_hit_member_count": sum(
                len(row["members"]) for row in target_hits
            ),
            "target_strong_hit_member_count": sum(
                len(row["members"]) for row in target_strong
            ),
            "control_geometry_hit_unique_count": len(control_hits),
            "control_first_anchor_occurrence_count": sum(
                int(row["control"]["first_anchor_occurrence_count"])
                for row in unique.values()
            ),
            "control_strong_hit_unique_count": len(control_strong),
            "control_geometry_hit_member_count": sum(
                len(row["members"]) for row in control_hits
            ),
            "control_strong_hit_member_count": sum(
                len(row["members"]) for row in control_strong
            ),
            "saturated_unique_payload_count": len(saturated),
        },
        "classification": {
            "signature_contract": "CONFIRMED_FIXED_FIVE_ANCHOR_GEOMETRY",
            "control_contract": "CONFIRMED_INDEPENDENT_EQUAL_GEOMETRY",
            "cross_payload_homolog": homolog,
            "cross_payload_owner": "OPEN",
            "semantic_owner": "OPEN",
            "exact_section_boundary": "OPEN",
            "runtime_loader_transform": "NOT_OBSERVED",
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "Five high-quality exact runs from the stable Session 038 "
            "component are searched as one fixed relative geometry across "
            "deduplicated non-principal update payloads. The equal-geometry "
            "control prevents an isolated high-entropy signature hit from "
            "being promoted without discrimination. A hit can establish a "
            "cross-payload homolog, but not semantic ownership or runtime "
            "use by itself."
        ),
        "limits": [
            "Only BIN, HEX, LOD, YIM and SW members of at least 240 bytes are scanned.",
            "Principal-image copies are excluded by complete content SHA-256.",
            "Only the five registered 25-byte runs and their exact geometry are searched.",
            "Compressed, encoded, transformed or non-contiguous homologs remain open.",
            "A homolog cannot establish a subsystem owner without independent metadata or dataflow.",
            "No firmware, payload or signature bytes are published.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "raw_component_bytes_included": False,
            "raw_signature_bytes_included": False,
            "signature_hashes_included": False,
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


def update_operational_graph_v33(
    prior_graph: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v33"
    graph["nodes"].append(
        {
            "id": "reorder-rz012-cross-payload-homolog",
            "status": report["classification"]["cross_payload_homolog"],
            "semantic_status": "STRUCTURAL_PROVENANCE_NOT_OWNER_PROOF",
            "evidence": report["interpretation"],
        }
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-rz012-run-gap-skeleton",
                "target": "reorder-rz012-cross-payload-homolog",
                "status": report["classification"][
                    "cross_payload_homolog"
                ],
                "relation": "searches-fixed-signature-across-update-payloads",
            },
            {
                "source": "reorder-rz012-cross-payload-homolog",
                "target": "reorder-rz012-semantic-owner",
                "status": (
                    "OPEN"
                    if report["classification"]["cross_payload_homolog"]
                    == "CROSS_PAYLOAD_HOMOLOG_SUPPORTED"
                    else "BOUNDED_NEGATIVE"
                ),
                "relation": "does-not-assign-semantic-owner-by-itself",
            },
        ]
    )
    return graph


def correlate_cross_payload_homologs(
    prior_correlation: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.cross-payload-homolog-correlation/v1",
        "analysis_mode": report["analysis_mode"],
        "firmware": copy.deepcopy(report["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_homolog_edge": "NOT_ASSERTED",
        "interpretation": report["interpretation"],
        "operational_graph": update_operational_graph_v33(
            prior_correlation["operational_graph"], report
        ),
        "publication_safety": copy.deepcopy(report["publication_safety"]),
    }


def build_public_cross_payload_homolog_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

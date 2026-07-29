"""Frozen distributed near-homolog search for Session 042.

Ten non-overlapping 12-byte subanchors are derived from the five exact
Session 040 anchors before the payload corpus is searched. A candidate needs
fixed geometric support from multiple parent zones and independent
full-component similarity. Raw and validated record-normalized domains are
reported separately.
"""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
import hashlib
import math
from pathlib import PurePosixPath
from typing import Iterable, Protocol

from .cross_payload_homolog import (
    derive_cross_payload_signature,
    payload_member_eligible,
)
from .record_normalization import (
    normalize_record_payload,
    record_member_eligible,
)


_SUBANCHOR_LENGTH = 12
_SUBANCHOR_SLICES = ((0, 12), (13, 25))
_SUBANCHOR_COUNT = 10
_MINIMUM_DISTINCT_BYTES = 8
_MINIMUM_ENTROPY = 2.75
_MINIMUM_DISTINCT_TARGET_PATTERNS = 6
_MINIMUM_EXACT_SUBANCHORS = 4
_MINIMUM_PARENT_ZONES = 3
_MINIMUM_STRONG_SIMILARITY = 0.60
_MAXIMUM_OCCURRENCES_PER_ANCHOR_PER_UNIT = 4096
_MAXIMUM_CANDIDATES_PER_UNIT = 256
_COMPONENT_SPAN = 240


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def sha256(self) -> str: ...


@dataclass(frozen=True)
class NearHomologPayloadInput:
    disc: str
    path: str
    data: bytes


def _entropy(data: bytes) -> float:
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _subanchors(
    parent_anchors: list[dict[str, object]],
    *,
    prefix: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for parent_index, parent in enumerate(parent_anchors):
        material = bytes(parent["_internal_bytes"])
        if len(material) != 25:
            raise ValueError("parent anchor length differs")
        for slice_index, (start, end) in enumerate(_SUBANCHOR_SLICES):
            data = material[start:end]
            distinct = len(set(data))
            entropy = round(_entropy(data), 8)
            if (
                distinct < _MINIMUM_DISTINCT_BYTES
                or entropy < _MINIMUM_ENTROPY
            ):
                raise ValueError("subanchor failed fixed quality gate")
            rows.append(
                {
                    "anchor_id": (
                        f"{prefix}-{parent_index + 1:02d}-"
                        f"{slice_index + 1:02d}"
                    ),
                    "parent_zone_id": f"PARENT-{parent_index + 1:02d}",
                    "relative_offset": (
                        int(parent["relative_offset"]) + start
                    ),
                    "length": _SUBANCHOR_LENGTH,
                    "distinct_byte_count": distinct,
                    "entropy": entropy,
                    "_internal_bytes": data,
                }
            )
    if len(rows) != _SUBANCHOR_COUNT:
        raise ValueError("expected ten distributed subanchors")
    return rows


def derive_distributed_constellation(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    session039: dict[str, object],
    session040: dict[str, object],
) -> dict[str, object]:
    if session040.get("schema") != (
        "phoenix-mmi.cross-payload-homolog-comparison/v1"
    ):
        raise ValueError("unsupported Session 040 schema")
    if session040.get("left_artifact_sha256") != left_reader.sha256():
        raise ValueError("Session 040 left principal-image hash differs")
    if session040.get("right_artifact_sha256") != right_reader.sha256():
        raise ValueError("Session 040 right principal-image hash differs")
    if session040["classification"].get("cross_payload_homolog") != (
        "NOT_FOUND_UNDER_FIXED_SIGNATURE_MODEL"
    ):
        raise ValueError("Session 040 raw-payload result changed")

    signature = derive_cross_payload_signature(
        left_reader,
        right_reader,
        session038,
        session039,
    )
    target = _subanchors(signature["anchors"], prefix="DHA")
    control = _subanchors(signature["controls"], prefix="DHC")
    target_patterns = {
        row["_internal_bytes"] for row in target
    }
    control_patterns = {
        row["_internal_bytes"] for row in control
    }
    if len(target_patterns) < _MINIMUM_DISTINCT_TARGET_PATTERNS:
        raise ValueError("target constellation lacks six distinct patterns")
    if target_patterns & control_patterns:
        raise ValueError("target and control constellations overlap")
    return {
        "target_anchors": target,
        "control_anchors": control,
        "_internal_target_references": (
            signature["_internal_left_component"],
            signature["_internal_right_component"],
        ),
        "_internal_control_references": (
            signature["_internal_control_component"],
        ),
    }


def _scan_constellation(
    data: bytes,
    anchors: list[dict[str, object]],
    references: tuple[bytes, ...],
) -> dict[str, object]:
    votes: dict[int, set[int]] = {}
    occurrence_count = 0
    saturated = False
    for anchor_index, anchor in enumerate(anchors):
        pattern = bytes(anchor["_internal_bytes"])
        relative = int(anchor["relative_offset"])
        occurrence = data.find(pattern)
        anchor_occurrences = 0
        while occurrence >= 0:
            anchor_occurrences += 1
            occurrence_count += 1
            if (
                anchor_occurrences
                > _MAXIMUM_OCCURRENCES_PER_ANCHOR_PER_UNIT
            ):
                saturated = True
                break
            base = occurrence - relative
            if 0 <= base and base + _COMPONENT_SPAN <= len(data):
                votes.setdefault(base, set()).add(anchor_index)
            occurrence = data.find(pattern, occurrence + 1)
        if saturated:
            break

    candidates = []
    for base, anchor_indices in sorted(votes.items()):
        parents = {
            str(anchors[index]["parent_zone_id"])
            for index in anchor_indices
        }
        if (
            len(anchor_indices) < _MINIMUM_EXACT_SUBANCHORS
            or len(parents) < _MINIMUM_PARENT_ZONES
        ):
            continue
        window = data[base : base + _COMPONENT_SPAN]
        exact_counts = [
            sum(left == right for left, right in zip(window, reference))
            for reference in references
        ]
        best_exact = max(exact_counts)
        similarity = best_exact / _COMPONENT_SPAN
        candidates.append(
            {
                "unit_offset": base,
                "exact_subanchor_count": len(anchor_indices),
                "exact_parent_zone_count": len(parents),
                "exact_subanchor_byte_count": (
                    len(anchor_indices) * _SUBANCHOR_LENGTH
                ),
                "best_component_exact_byte_count": best_exact,
                "best_component_similarity": round(similarity, 8),
                "strong_similarity_gate_passed": (
                    similarity >= _MINIMUM_STRONG_SIMILARITY
                ),
            }
        )
        if len(candidates) >= _MAXIMUM_CANDIDATES_PER_UNIT:
            saturated = True
            break
    return {
        "anchor_occurrence_count": occurrence_count,
        "constellation_candidate_count": len(candidates),
        "strong_candidate_count": sum(
            row["strong_similarity_gate_passed"] for row in candidates
        ),
        "scan_saturated": saturated,
        "candidates": candidates,
    }


def _public_anchor(anchor: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in anchor.items()
        if not key.startswith("_internal")
    }


def _unit_result(
    *,
    domain: str,
    size: int,
    sources: list[dict[str, object]],
    data: bytes,
    constellation: dict[str, object],
) -> dict[str, object]:
    target = _scan_constellation(
        data,
        constellation["target_anchors"],
        constellation["_internal_target_references"],
    )
    control = _scan_constellation(
        data,
        constellation["control_anchors"],
        constellation["_internal_control_references"],
    )
    return {
        "domain": domain,
        "size": size,
        "sources": sources,
        "target": target,
        "control": control,
    }


def _domain_summary(rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "unique_unit_count": len(rows),
        "unique_unit_bytes": sum(int(row["size"]) for row in rows),
        "scannable_unique_unit_count": sum(
            int(row["size"]) >= _COMPONENT_SPAN for row in rows
        ),
        "target_seeded_unit_count": sum(
            bool(row["target"]["anchor_occurrence_count"]) for row in rows
        ),
        "target_anchor_occurrence_count": sum(
            int(row["target"]["anchor_occurrence_count"]) for row in rows
        ),
        "target_candidate_unit_count": sum(
            bool(row["target"]["constellation_candidate_count"])
            for row in rows
        ),
        "target_strong_unit_count": sum(
            bool(row["target"]["strong_candidate_count"]) for row in rows
        ),
        "control_seeded_unit_count": sum(
            bool(row["control"]["anchor_occurrence_count"]) for row in rows
        ),
        "control_anchor_occurrence_count": sum(
            int(row["control"]["anchor_occurrence_count"]) for row in rows
        ),
        "control_candidate_unit_count": sum(
            bool(row["control"]["constellation_candidate_count"])
            for row in rows
        ),
        "control_strong_unit_count": sum(
            bool(row["control"]["strong_candidate_count"]) for row in rows
        ),
        "saturated_unique_unit_count": sum(
            bool(
                row["target"]["scan_saturated"]
                or row["control"]["scan_saturated"]
            )
            for row in rows
        ),
    }


def scan_distributed_unit(
    data: bytes,
    constellation: dict[str, object],
    *,
    domain: str,
    sources: list[dict[str, object]],
) -> dict[str, object]:
    """Apply the frozen Session 042 model to one private byte unit."""

    return _unit_result(
        domain=domain,
        size=len(data),
        sources=copy.deepcopy(sources),
        data=data,
        constellation=constellation,
    )


def summarize_distributed_units(
    rows: list[dict[str, object]],
) -> dict[str, object]:
    """Return the publication-safe aggregate used by Session 042."""

    return _domain_summary(rows)


def analyze_distributed_homologs(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    session039: dict[str, object],
    session040: dict[str, object],
    session041: dict[str, object],
    payloads: Iterable[NearHomologPayloadInput],
) -> dict[str, object]:
    """Search raw and validated decoded domains with one frozen constellation."""

    if session041.get("schema") != (
        "phoenix-mmi.record-normalized-homolog-comparison/v1"
    ):
        raise ValueError("unsupported Session 041 schema")
    if session041.get("left_artifact_sha256") != left_reader.sha256():
        raise ValueError("Session 041 left principal-image hash differs")
    if session041.get("right_artifact_sha256") != right_reader.sha256():
        raise ValueError("Session 041 right principal-image hash differs")
    if session041["classification"].get(
        "record_normalized_homolog"
    ) != "NOT_FOUND_IN_VALIDATED_DECODED_REGIONS":
        raise ValueError("Session 041 normalized result changed")

    constellation = derive_distributed_constellation(
        left_reader,
        right_reader,
        session038,
        session039,
        session040,
    )
    principal_hashes = {
        left_reader.sha256(),
        right_reader.sha256(),
    }
    raw_sources: dict[str, dict[str, object]] = {}
    record_sources: dict[str, dict[str, object]] = {}
    eligible_member_count = 0
    eligible_member_bytes = 0
    scanned_member_count = 0
    scanned_member_bytes = 0
    principal_exclusion_count = 0
    record_member_count = 0
    record_member_bytes = 0
    for payload in payloads:
        if payload_member_eligible(payload.path, len(payload.data)):
            eligible_member_count += 1
            eligible_member_bytes += len(payload.data)
            digest = hashlib.sha256(payload.data).hexdigest()
            if digest in principal_hashes:
                principal_exclusion_count += 1
            else:
                scanned_member_count += 1
                scanned_member_bytes += len(payload.data)
                row = raw_sources.get(digest)
                if row is None:
                    row = {
                        "data": payload.data,
                        "members": [],
                    }
                    raw_sources[digest] = row
                row["members"].append(
                    {
                        "disc": str(payload.disc),
                        "path": payload.path,
                        "extension": (
                            PurePosixPath(payload.path).suffix.upper()
                        ),
                    }
                )
        if record_member_eligible(payload.path, len(payload.data)):
            record_member_count += 1
            record_member_bytes += len(payload.data)
            digest = hashlib.sha256(payload.data).hexdigest()
            row = record_sources.get(digest)
            if row is None:
                row = {
                    "data": payload.data,
                    "path": payload.path,
                    "members": [],
                }
                record_sources[digest] = row
            row["members"].append(
                {
                    "disc": str(payload.disc),
                    "path": payload.path,
                    "extension": (
                        PurePosixPath(payload.path).suffix.upper()
                    ),
                }
            )

    expected_raw = session040["corpus_contract"]
    actual_raw = {
        "eligible_member_count": eligible_member_count,
        "eligible_member_bytes": eligible_member_bytes,
        "scanned_member_count": scanned_member_count,
        "scanned_member_bytes": scanned_member_bytes,
        "principal_identity_exclusion_count": principal_exclusion_count,
        "unique_payload_content_count": len(raw_sources),
        "unique_payload_content_bytes": sum(
            len(row["data"]) for row in raw_sources.values()
        ),
    }
    expected_raw_values = {
        "eligible_member_count": int(
            expected_raw["eligible_member_count"]
        ),
        "eligible_member_bytes": int(
            expected_raw["eligible_member_bytes"]
        ),
        "scanned_member_count": int(expected_raw["scanned_member_count"]),
        "scanned_member_bytes": int(expected_raw["scanned_member_bytes"]),
        "principal_identity_exclusion_count": sum(
            int(row["principal_identity_exclusion_count"])
            for row in session040["disc_summaries"].values()
        ),
        "unique_payload_content_count": int(
            expected_raw["unique_payload_content_count"]
        ),
        "unique_payload_content_bytes": int(
            expected_raw["unique_payload_content_bytes"]
        ),
    }
    if actual_raw != expected_raw_values:
        raise ValueError("raw corpus differs from Session 040")

    normalized_regions: dict[str, dict[str, object]] = {}
    normalized_unique_source_count = 0
    for source in record_sources.values():
        normalization = normalize_record_payload(
            str(source["path"]),
            bytes(source["data"]),
        )
        if normalization.decoded_regions:
            normalized_unique_source_count += 1
        for region_index, region in enumerate(
            normalization.decoded_regions
        ):
            digest = hashlib.sha256(region.data).hexdigest()
            row = normalized_regions.get(digest)
            sources = [
                {
                    "disc": member["disc"],
                    "path": member["path"],
                    "format_name": normalization.format_name,
                    "source_classification": normalization.classification,
                    "source_region_index": region_index,
                }
                for member in source["members"]
            ]
            if row is None:
                row = {
                    "data": region.data,
                    "sources": [],
                }
                normalized_regions[digest] = row
            row["sources"].extend(sources)

    expected_source = session041["source_corpus"]
    expected_decoded = session041["decoded_corpus"]
    actual_normalized = {
        "member_count": record_member_count,
        "member_bytes": record_member_bytes,
        "unique_source_content_count": len(record_sources),
        "normalized_unique_source_count": normalized_unique_source_count,
        "unique_region_content_count": len(normalized_regions),
        "unique_decoded_region_bytes": sum(
            len(row["data"]) for row in normalized_regions.values()
        ),
        "scannable_unique_region_count": sum(
            len(row["data"]) >= _COMPONENT_SPAN
            for row in normalized_regions.values()
        ),
    }
    expected_normalized = {
        "member_count": int(expected_source["member_count"]),
        "member_bytes": int(expected_source["member_bytes"]),
        "unique_source_content_count": int(
            expected_source["unique_source_content_count"]
        ),
        "normalized_unique_source_count": int(
            expected_source["normalized_unique_source_count"]
        ),
        "unique_region_content_count": int(
            expected_decoded["unique_region_content_count"]
        ),
        "unique_decoded_region_bytes": int(
            expected_decoded["unique_decoded_region_bytes"]
        ),
        "scannable_unique_region_count": int(
            expected_decoded["scannable_unique_region_count"]
        ),
    }
    if actual_normalized != expected_normalized:
        raise ValueError("normalized corpus differs from Session 041")

    raw_rows = [
        _unit_result(
            domain="RAW",
            size=len(source["data"]),
            sources=copy.deepcopy(source["members"]),
            data=bytes(source["data"]),
            constellation=constellation,
        )
        for source in raw_sources.values()
    ]
    normalized_rows = [
        _unit_result(
            domain="RECORD_NORMALIZED",
            size=len(source["data"]),
            sources=copy.deepcopy(source["sources"]),
            data=bytes(source["data"]),
            constellation=constellation,
        )
        for source in normalized_regions.values()
        if len(source["data"]) >= _COMPONENT_SPAN
    ]
    domain_rows = {
        "RAW": raw_rows,
        "RECORD_NORMALIZED": normalized_rows,
    }
    domain_summaries = {
        domain: _domain_summary(rows)
        for domain, rows in domain_rows.items()
    }
    all_rows = raw_rows + normalized_rows
    target_candidates = [
        {
            "domain": row["domain"],
            "size": row["size"],
            "sources": copy.deepcopy(row["sources"]),
            "candidates": copy.deepcopy(row["target"]["candidates"]),
        }
        for row in all_rows
        if row["target"]["constellation_candidate_count"]
    ]
    control_candidates = [
        {
            "domain": row["domain"],
            "size": row["size"],
            "sources": copy.deepcopy(row["sources"]),
            "candidates": copy.deepcopy(row["control"]["candidates"]),
        }
        for row in all_rows
        if row["control"]["constellation_candidate_count"]
    ]
    target_strong = sum(
        any(
            candidate["strong_similarity_gate_passed"]
            for candidate in row["candidates"]
        )
        for row in target_candidates
    )
    control_strong = sum(
        any(
            candidate["strong_similarity_gate_passed"]
            for candidate in row["candidates"]
        )
        for row in control_candidates
    )
    saturated = sum(
        int(summary["saturated_unique_unit_count"])
        for summary in domain_summaries.values()
    )
    if saturated:
        classification = "INCONCLUSIVE_DISTRIBUTED_SCAN_SATURATED"
    elif control_strong:
        classification = "DISTRIBUTED_MODEL_NOT_DISCRIMINATING"
    elif target_strong:
        classification = "DISTRIBUTED_NEAR_HOMOLOG_SUPPORTED"
    elif target_candidates:
        classification = "DISTRIBUTED_CONSTELLATION_CANDIDATE_ONLY"
    else:
        classification = "NOT_FOUND_UNDER_FIXED_DISTRIBUTED_MODEL"

    return {
        "schema": "phoenix-mmi.distributed-homolog-comparison/v1",
        "analysis_mode": (
            "read-only-fixed-distributed-near-homolog-raw-and-decoded-search"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session040_schema": session040["schema"],
        "source_session041_schema": session041["schema"],
        "constellation_contract": {
            "parent_anchor_count": 5,
            "subanchors_per_parent": 2,
            "subanchor_slices": [
                {"start": start, "end": end}
                for start, end in _SUBANCHOR_SLICES
            ],
            "subanchor_count": _SUBANCHOR_COUNT,
            "subanchor_length": _SUBANCHOR_LENGTH,
            "minimum_distinct_bytes": _MINIMUM_DISTINCT_BYTES,
            "minimum_entropy": _MINIMUM_ENTROPY,
            "minimum_distinct_target_patterns": (
                _MINIMUM_DISTINCT_TARGET_PATTERNS
            ),
            "distinct_target_pattern_count": len(
                {
                    row["_internal_bytes"]
                    for row in constellation["target_anchors"]
                }
            ),
            "distinct_control_pattern_count": len(
                {
                    row["_internal_bytes"]
                    for row in constellation["control_anchors"]
                }
            ),
            "target_control_pattern_overlap_count": 0,
            "minimum_exact_subanchors": _MINIMUM_EXACT_SUBANCHORS,
            "minimum_parent_zones": _MINIMUM_PARENT_ZONES,
            "minimum_strong_component_similarity": (
                _MINIMUM_STRONG_SIMILARITY
            ),
            "maximum_occurrences_per_anchor_per_unit": (
                _MAXIMUM_OCCURRENCES_PER_ANCHOR_PER_UNIT
            ),
            "maximum_candidates_per_unit": _MAXIMUM_CANDIDATES_PER_UNIT,
            "target_subanchors": [
                _public_anchor(row)
                for row in constellation["target_anchors"]
            ],
            "control_subanchors": [
                _public_anchor(row)
                for row in constellation["control_anchors"]
            ],
            "raw_signature_bytes_included": False,
            "signature_hashes_included": False,
            "adaptive_threshold_used": False,
        },
        "corpus_reproduction": {
            "raw": actual_raw,
            "record_normalized": actual_normalized,
            "prior_counts_reproduced": True,
        },
        "domain_summaries": domain_summaries,
        "target_candidates": target_candidates,
        "control_candidates": control_candidates,
        "summary": {
            "target_candidate_unique_unit_count": len(target_candidates),
            "target_strong_unique_unit_count": target_strong,
            "control_candidate_unique_unit_count": len(control_candidates),
            "control_strong_unique_unit_count": control_strong,
            "saturated_unique_unit_count": saturated,
        },
        "classification": {
            "distributed_near_homolog": classification,
            "cross_payload_owner": "OPEN",
            "semantic_owner": "OPEN",
            "exact_section_boundary": "OPEN",
            "runtime_loader_transform": "NOT_OBSERVED",
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "Ten fixed quality-gated subanchors test whether a variant retains "
            "distributed geometry after no complete 25-byte anchor survived. "
            "Four exact subanchors from three parent zones and independent "
            "60-percent full-component similarity are required. Raw and "
            "validated record-normalized domains are evaluated separately "
            "against an equal-geometry control."
        ),
        "limits": [
            "The model detects only exact 12-byte subanchors at fixed relative geometry.",
            "At least four subanchors from at least three parent zones are required before similarity is evaluated.",
            "A strong candidate must reach 60 percent similarity to either registered release component.",
            "Raw and validated record-normalized domains are searched; unsupported decoded forms remain open.",
            "Compression, encryption, relocation-normalized instructions and runtime-created data remain open.",
            "A structural near-homolog cannot assign semantic ownership by itself.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "decoded_region_bytes_included": False,
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


def update_operational_graph_v35(
    prior_graph: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v35"
    graph["nodes"].append(
        {
            "id": "distributed-near-homolog",
            "status": report["classification"]["distributed_near_homolog"],
            "semantic_status": "STRUCTURAL_PROVENANCE_NOT_OWNER_PROOF",
            "evidence": report["interpretation"],
        }
    )
    graph["edges"].extend(
        [
            {
                "source": "record-normalized-cross-payload-homolog",
                "target": "distributed-near-homolog",
                "status": report["classification"][
                    "distributed_near_homolog"
                ],
                "relation": "tests-fixed-shorter-distributed-geometry",
            },
            {
                "source": "distributed-near-homolog",
                "target": "reorder-rz012-semantic-owner",
                "status": (
                    "OPEN"
                    if report["classification"][
                        "distributed_near_homolog"
                    ]
                    == "DISTRIBUTED_NEAR_HOMOLOG_SUPPORTED"
                    else "BOUNDED_NEGATIVE"
                ),
                "relation": "does-not-assign-semantic-owner-by-itself",
            },
        ]
    )
    return graph


def correlate_distributed_homologs(
    prior_correlation: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.distributed-homolog-correlation/v1",
        "analysis_mode": report["analysis_mode"],
        "firmware": copy.deepcopy(report["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_homolog_edge": "NOT_ASSERTED",
        "interpretation": report["interpretation"],
        "operational_graph": update_operational_graph_v35(
            prior_correlation["operational_graph"],
            report,
        ),
        "publication_safety": copy.deepcopy(report["publication_safety"]),
    }


def build_public_distributed_homolog_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

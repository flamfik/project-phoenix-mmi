"""High-level composition of the Phoenix MMI static-analysis pipeline."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path

from .binary import BinaryReader
from .checksum import (
    candidate_regions,
    detect_sequential_crc32_layouts,
    map_crc32_expectations,
    parse_metainfo_checksums,
)
from .entropy import entropy_profile, entropy_transitions, summarize_entropy
from .fingerprint import scan_fingerprints
from .segments import build_candidate_segments, find_filler_runs
from .strings import extract_strings, summarize_strings


@dataclass(frozen=True)
class AnalysisConfig:
    entropy_window: int = 64 * 1024
    entropy_step: int = 64 * 1024
    entropy_delta: float = 1.25
    string_min_length: int = 5
    max_fingerprint_hits: int = 256


def analyze_file(
    path: str | Path,
    *,
    label: str | None = None,
    metainfo: str | Path | None = None,
    metainfo_section: str | None = None,
    config: AnalysisConfig | None = None,
) -> dict[str, object]:
    """Analyze one file without executing it or exporting embedded payloads."""

    config = config or AnalysisConfig()
    reader = BinaryReader(path)
    fingerprints = scan_fingerprints(
        reader, max_hits_per_signature=config.max_fingerprint_hits
    )
    entropy_windows = entropy_profile(
        reader,
        window_size=config.entropy_window,
        step=config.entropy_step,
    )
    filler_runs = find_filler_runs(reader)
    segments = build_candidate_segments(
        reader.size,
        fingerprints,
        entropy_windows,
        filler_runs,
        entropy_delta=config.entropy_delta,
    )
    string_summary = summarize_strings(
        extract_strings(reader, min_length=config.string_min_length)
    )

    checksum_report: dict[str, object] = {
        "status": "NOT_REQUESTED",
        "algorithm_tested": "CRC32/IEEE",
        "matches": [],
    }
    if metainfo is not None:
        metadata = parse_metainfo_checksums(
            metainfo,
            None if metainfo_section else reader.path.name,
            section_name=metainfo_section,
        )
        regions = candidate_regions(reader.size, segments)
        matches = map_crc32_expectations(reader, metadata.expectations, regions)
        sequential_layouts = detect_sequential_crc32_layouts(reader, metadata.expectations)
        matched_indices = sorted({match.index for match in matches})
        checksum_report = {
            "status": "TESTED",
            "metainfo_section": metadata.section,
            "flash_start_address": metadata.flash_start_address,
            "algorithm_tested": "CRC32/IEEE",
            "expected": [
                {"index": item.index, "field": item.field, "value": item.hex_value}
                for item in metadata.expectations
            ],
            "candidate_region_count": len(regions),
            "matched_indices": matched_indices,
            "unmatched_indices": sorted(
                item.index for item in metadata.expectations if item.index not in matched_indices
            ),
            "matches": [match.to_dict() for match in matches],
            "sequential_layouts": sequential_layouts,
            "interpretation": (
                "A match proves only that one tested region has the expected CRC32. "
                "No match does not disprove CRC32 because the true boundaries may be unknown."
            ),
        }

    fingerprint_counts = Counter(hit.name for hit in fingerprints)
    validated_fingerprint_counts = Counter(
        hit.name for hit in fingerprints if hit.details and hit.details.get("validated") is True
    )
    header = reader.head(64)
    return {
        "schema": "phoenix-mmi.analysis/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "label": label or reader.path.name,
            "filename": reader.path.name,
            "size_bytes": reader.size,
            "sha256": reader.sha256(),
            "header_length": len(header),
            "header_sha256": hashlib.sha256(header).hexdigest(),
        },
        "fingerprints": {
            "hit_count": len(fingerprints),
            "counts": dict(sorted(fingerprint_counts.items())),
            "validated_hit_count": sum(validated_fingerprint_counts.values()),
            "validated_counts": dict(sorted(validated_fingerprint_counts.items())),
            "hits": [hit.to_dict() for hit in fingerprints],
            "interpretation": "Magic-byte hits are candidates until surrounding structure validates them.",
        },
        "entropy": {
            "window_size": config.entropy_window,
            "step": config.entropy_step,
            "summary": summarize_entropy(entropy_windows),
            "transitions": entropy_transitions(
                entropy_windows, minimum_delta=config.entropy_delta
            ),
            "windows": [window.to_dict() for window in entropy_windows],
        },
        "strings": string_summary,
        "candidate_segments": {
            "status": "HYPOTHESIS",
            "count": len(segments),
            "segments": [segment.to_dict() for segment in segments],
        },
        "filler_runs": [run.to_dict() for run in filler_runs],
        "checksums": checksum_report,
        "publication_safety": {
            "payload_bytes_included": False,
            "embedded_resources_exported": False,
            "raw_strings_included": False,
        },
    }


def compare_reports(left: dict[str, object], right: dict[str, object]) -> dict[str, object]:
    """Compare sanitized reports rather than redistributing artifact bytes."""

    left_artifact = left["artifact"]
    right_artifact = right["artifact"]
    left_counts = left["fingerprints"]["counts"]
    right_counts = right["fingerprints"]["counts"]
    names = sorted(set(left_counts) | set(right_counts))
    left_resources = {
        hit["details"]["sha256"]
        for hit in left["fingerprints"]["hits"]
        if hit["category"] == "resource"
        and hit.get("details")
        and hit["details"].get("validated") is True
        and hit["details"].get("sha256")
    }
    right_resources = {
        hit["details"]["sha256"]
        for hit in right["fingerprints"]["hits"]
        if hit["category"] == "resource"
        and hit.get("details")
        and hit["details"].get("validated") is True
        and hit["details"].get("sha256")
    }
    return {
        "schema": "phoenix-mmi.comparison/v1",
        "left": left_artifact["label"],
        "right": right_artifact["label"],
        "same_sha256": left_artifact["sha256"] == right_artifact["sha256"],
        "size_delta_bytes": right_artifact["size_bytes"] - left_artifact["size_bytes"],
        "header64_sha256_equal": (
            left_artifact["header_sha256"] == right_artifact["header_sha256"]
        ),
        "fingerprint_count_delta": {
            name: right_counts.get(name, 0) - left_counts.get(name, 0)
            for name in names
            if right_counts.get(name, 0) != left_counts.get(name, 0)
        },
        "entropy_mean_delta": round(
            right["entropy"]["summary"].get("mean", 0.0)
            - left["entropy"]["summary"].get("mean", 0.0),
            6,
        ),
        "technical_markers_added": sorted(
            set(right["strings"]["technical_markers"])
            - set(left["strings"]["technical_markers"])
        ),
        "technical_markers_removed": sorted(
            set(left["strings"]["technical_markers"])
            - set(right["strings"]["technical_markers"])
        ),
        "validated_resource_hashes": {
            "left_count": len(left_resources),
            "right_count": len(right_resources),
            "shared_count": len(left_resources & right_resources),
            "added": sorted(right_resources - left_resources),
            "removed": sorted(left_resources - right_resources),
        },
        "publication_safety": {"artifact_bytes_included": False},
    }

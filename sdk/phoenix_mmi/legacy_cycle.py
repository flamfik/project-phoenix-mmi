"""Publication-safe analysis for the Sessions 044-050 legacy-format cycle."""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
import hashlib
import itertools
import math
from pathlib import PurePosixPath
from typing import Iterable, Protocol

from .distributed_homolog import (
    derive_distributed_constellation,
    scan_distributed_unit,
    summarize_distributed_units,
)
from .yim import (
    YimDecodeResult,
    decode_yim_rle,
    parse_yim_envelope,
    public_yim_envelope,
    public_yim_rle,
    yim_integrity_candidates,
)


_LEGACY_EXTENSIONS = frozenset({".LOD", ".YIM"})
_LOD_BLOCK_SIZE = 256


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def sha256(self) -> str: ...


@dataclass(frozen=True)
class LegacyPayloadInput:
    disc: str
    path: str
    data: bytes


def legacy_member_eligible(path: str, size: int) -> bool:
    return (
        PurePosixPath(path).suffix.upper() in _LEGACY_EXTENSIONS
        and size >= 60
    )


def _entropy(data: bytes) -> float:
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _longest_run(data: bytes, value: int) -> int:
    best = current = 0
    for item in data:
        if item == value:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _group_sources(
    payloads: Iterable[LegacyPayloadInput],
) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for payload in payloads:
        if not legacy_member_eligible(payload.path, len(payload.data)):
            continue
        extension = PurePosixPath(payload.path).suffix.upper()
        digest = hashlib.sha256(payload.data).hexdigest()
        row = grouped.setdefault(
            digest,
            {
                "extension": extension,
                "data": payload.data,
                "members": [],
                "_digest": digest,
            },
        )
        if row["extension"] != extension:
            raise ValueError("legacy content appears under mixed extensions")
        row["members"].append(
            {
                "disc": payload.disc,
                "path": payload.path,
                "size": len(payload.data),
            }
        )
    counters: Counter[str] = Counter()
    rows = []
    for row in sorted(
        grouped.values(),
        key=lambda item: (
            str(item["extension"]),
            len(bytes(item["data"])),
            str(item["_digest"]),
        ),
    ):
        extension = str(row["extension"])
        counters[extension] += 1
        row["source_id"] = (
            f"{extension[1:]}-U{counters[extension]:02d}"
        )
        row["members"] = sorted(
            row["members"],
            key=lambda member: (
                str(member["disc"]),
                str(member["path"]),
            ),
        )
        rows.append(row)
    return rows


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "decoded_raster_bytes_included": False,
        "decoded_raster_hashes_included": False,
        "source_content_hashes_included": False,
        "raw_header_values_included": False,
        "raw_strings_included": False,
        "local_paths_included": False,
        "extracted_resources_included": False,
        "runtime_execution_observed": False,
    }


def analyze_legacy_corpus(
    payloads: Iterable[LegacyPayloadInput],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    sources = _group_sources(payloads)
    extensions: dict[str, dict[str, object]] = {}
    public_sources = []
    for source in sources:
        extension = str(source["extension"])
        data = bytes(source["data"])
        row = extensions.setdefault(
            extension,
            {
                "member_count": 0,
                "member_bytes": 0,
                "unique_source_count": 0,
                "unique_source_bytes": 0,
            },
        )
        row["member_count"] += len(source["members"])
        row["member_bytes"] += sum(
            int(member["size"]) for member in source["members"]
        )
        row["unique_source_count"] += 1
        row["unique_source_bytes"] += len(data)
        if extension == ".YIM":
            parse_yim_envelope(data)
            format_evidence = "VALIDATED_XIM2_ENVELOPE"
        else:
            format_evidence = "OPAQUE_BINARY_NO_OUTER_MAGIC"
        public_sources.append(
            {
                "source_id": source["source_id"],
                "extension": extension,
                "size": len(data),
                "member_count": len(source["members"]),
                "disc_count": len(
                    {member["disc"] for member in source["members"]}
                ),
                "members": copy.deepcopy(source["members"]),
                "format_evidence": format_evidence,
                "entropy": round(_entropy(data), 8),
                "zero_ratio": round(data.count(0) / len(data), 8),
                "ff_ratio": round(data.count(0xFF) / len(data), 8),
            }
        )
    report = {
        "schema": "phoenix-mmi.legacy-container-census/v1",
        "analysis_mode": "read-only-content-deduplicated-legacy-census",
        "session": "044",
        "member_count": sum(
            int(row["member_count"]) for row in extensions.values()
        ),
        "member_bytes": sum(
            int(row["member_bytes"]) for row in extensions.values()
        ),
        "unique_source_count": len(sources),
        "unique_source_bytes": sum(
            len(bytes(source["data"])) for source in sources
        ),
        "extension_summaries": extensions,
        "sources": public_sources,
        "classification": {
            "legacy_family_census": "TWO_DISTINCT_FAMILIES_CONFIRMED",
            "yim_family": "XIM2_ENVELOPE_IDENTIFIED",
            "lod_family": "OPAQUE_BINARY_STRUCTURE_ONLY",
        },
        "operational_graph_version": "v36",
        "publication_safety": _publication_safety(),
    }
    return report, sources


def _yim_results(
    sources: list[dict[str, object]],
) -> list[tuple[dict[str, object], YimDecodeResult]]:
    return [
        (source, decode_yim_rle(bytes(source["data"])))
        for source in sources
        if source["extension"] == ".YIM"
    ]


def analyze_yim_envelopes(
    sources: list[dict[str, object]],
) -> dict[str, object]:
    results = _yim_results(sources)
    rows = []
    for source, result in results:
        row = public_yim_envelope(result)
        row.update(
            {
                "source_id": source["source_id"],
                "member_count": len(source["members"]),
                "disc_count": len(
                    {member["disc"] for member in source["members"]}
                ),
            }
        )
        rows.append(row)
    geometries = {
        (int(row["width"]), int(row["height"])) for row in rows
    }
    report = {
        "schema": "phoenix-mmi.yim-envelope/v1",
        "analysis_mode": "read-only-strict-yim-xim2-envelope-validation",
        "session": "045",
        "unique_source_count": len(rows),
        "validated_source_count": len(rows),
        "all_length_contracts_validated": all(
            row["length_contract_validated"] for row in rows
        ),
        "all_reserved_header_areas_zero": all(
            row["reserved_header_zero_validated"] for row in rows
        ),
        "distinct_geometry_count": len(geometries),
        "geometries": [
            {"width": width, "height": height}
            for width, height in sorted(geometries)
        ],
        "sources": rows,
        "classification": {
            "yim_envelope": "VALIDATED_XIM2_FIXED_GEOMETRY_ENVELOPE",
            "integrity_fields": "OPAQUE_PENDING_SESSION_047",
        },
        "operational_graph_version": "v37",
        "publication_safety": _publication_safety(),
    }
    return report


def analyze_yim_rle(
    sources: list[dict[str, object]],
) -> tuple[dict[str, object], list[tuple[dict[str, object], YimDecodeResult]]]:
    results = _yim_results(sources)
    rows = []
    for source, result in results:
        row = public_yim_rle(result)
        row["source_id"] = source["source_id"]
        rows.append(row)
    report = {
        "schema": "phoenix-mmi.yim-rle/v1",
        "analysis_mode": "read-only-bounded-two-byte-unit-rle-decoding",
        "session": "046",
        "unique_source_count": len(rows),
        "decoded_source_count": len(rows),
        "encoded_payload_bytes": sum(
            int(row["encoded_payload_size"]) for row in rows
        ),
        "decoded_raster_bytes": sum(
            int(row["decoded_raster_size"]) for row in rows
        ),
        "decoded_unit_count": sum(
            int(row["decoded_unit_count"]) for row in rows
        ),
        "literal_command_count": sum(
            int(row["literal_command_count"]) for row in rows
        ),
        "repeat_command_count": sum(
            int(row["repeat_command_count"]) for row in rows
        ),
        "all_streams_fully_consumed": all(
            row["stream_fully_consumed"] for row in rows
        ),
        "all_declared_raster_sizes_validated": all(
            row["declared_raster_size_validated"] for row in rows
        ),
        "sources": rows,
        "classification": {
            "yim_payload_codec": "VALIDATED_BOUNDED_RLE_16BIT_UNITS",
            "pixel_semantics": "NOT_ASSIGNED",
        },
        "operational_graph_version": "v38",
        "publication_safety": _publication_safety(),
    }
    return report, results


def analyze_yim_integrity(
    results: list[tuple[dict[str, object], YimDecodeResult]],
) -> dict[str, object]:
    rows = []
    for source, result in results:
        candidates = yim_integrity_candidates(
            bytes(source["data"]), result
        )
        rows.append(
            {
                "source_id": source["source_id"],
                **candidates,
            }
        )
    report = {
        "schema": "phoenix-mmi.yim-integrity/v1",
        "analysis_mode": "read-only-common-integrity-candidate-census",
        "session": "047",
        "unique_source_count": len(rows),
        "candidate_32bit_algorithms_tested": (
            rows[0]["candidate_32bit_algorithms_tested"] if rows else 0
        ),
        "candidate_16bit_algorithms_tested": (
            rows[0]["candidate_16bit_algorithms_tested"] if rows else 0
        ),
        "candidate_ranges_tested": (
            rows[0]["candidate_ranges_tested"] if rows else 0
        ),
        "integrity32_total_match_count": sum(
            int(row["integrity32_match_count"]) for row in rows
        ),
        "integrity16_total_match_count": sum(
            int(row["integrity16_match_count"]) for row in rows
        ),
        "sources": rows,
        "classification": {
            "yim_integrity_fields": (
                "UNRESOLVED_UNDER_TESTED_COMMON_ALGORITHMS"
            ),
            "safe_repack": "BLOCKED",
        },
        "operational_graph_version": "v39",
        "publication_safety": _publication_safety(),
    }
    return report


def _common_prefix_length(materials: list[bytes]) -> int:
    limit = min(map(len, materials), default=0)
    for index in range(limit):
        if len({material[index] for material in materials}) != 1:
            return index
    return limit


def _common_suffix_length(materials: list[bytes]) -> int:
    limit = min(map(len, materials), default=0)
    for length in range(1, limit + 1):
        if len({material[-length] for material in materials}) != 1:
            return length - 1
    return limit


def _block_hashes(data: bytes) -> set[str]:
    return {
        hashlib.sha256(data[offset : offset + _LOD_BLOCK_SIZE]).hexdigest()
        for offset in range(0, len(data) - _LOD_BLOCK_SIZE + 1, _LOD_BLOCK_SIZE)
    }


def _known_outer_magic(data: bytes) -> bool:
    return any(
        data.startswith(magic)
        for magic in (
            b"\x7fELF",
            b"\x1f\x8b",
            b"PK\x03\x04",
            b"XIM2",
            b"-rom1fs-",
            b"hsqs",
            b"sqsh",
        )
    )


def analyze_lod_topology(
    sources: list[dict[str, object]],
) -> dict[str, object]:
    lod_sources = [
        source for source in sources if source["extension"] == ".LOD"
    ]
    materials = [bytes(source["data"]) for source in lod_sources]
    if not materials:
        raise ValueError("LOD source family is absent")
    minimum_size = min(map(len, materials))
    aligned_equal = sum(
        len({material[index] for material in materials}) == 1
        for index in range(minimum_size)
    )
    block_sets = [_block_hashes(material) for material in materials]
    shared_all = set.intersection(*block_sets)
    pair_counts = [
        len(left & right)
        for left, right in itertools.combinations(block_sets, 2)
    ]
    rows = []
    for source, data, blocks in zip(lod_sources, materials, block_sets):
        rows.append(
            {
                "source_id": source["source_id"],
                "size": len(data),
                "member_count": len(source["members"]),
                "entropy": round(_entropy(data), 8),
                "zero_ratio": round(data.count(0) / len(data), 8),
                "ff_ratio": round(data.count(0xFF) / len(data), 8),
                "longest_zero_run": _longest_run(data, 0),
                "longest_ff_run": _longest_run(data, 0xFF),
                "full_block_count": len(data) // _LOD_BLOCK_SIZE,
                "unique_block_content_count": len(blocks),
                "known_outer_magic_at_offset_zero": _known_outer_magic(data),
            }
        )
    report = {
        "schema": "phoenix-mmi.lod-topology/v1",
        "analysis_mode": "read-only-cross-language-opaque-binary-topology",
        "session": "048",
        "unique_source_count": len(materials),
        "minimum_source_size": minimum_size,
        "maximum_source_size": max(map(len, materials)),
        "common_prefix_length": _common_prefix_length(materials),
        "common_suffix_length": _common_suffix_length(materials),
        "aligned_common_byte_count": aligned_equal,
        "aligned_common_byte_ratio_over_minimum_span": round(
            aligned_equal / minimum_size, 8
        ),
        "block_size": _LOD_BLOCK_SIZE,
        "shared_all_source_block_content_count": len(shared_all),
        "pairwise_shared_block_content_count": {
            "minimum": min(pair_counts, default=0),
            "maximum": max(pair_counts, default=0),
            "mean": round(
                sum(pair_counts) / len(pair_counts), 8
            )
            if pair_counts
            else 0,
        },
        "sources": rows,
        "classification": {
            "lod_structure": (
                "STRUCTURED_OPAQUE_BINARY_WITH_CROSS_LANGUAGE_REUSE"
            ),
            "lod_record_decoder": "NOT_ESTABLISHED",
            "lod_payload_reconstruction": "BLOCKED",
        },
        "operational_graph_version": "v40",
        "publication_safety": _publication_safety(),
    }
    return report


def analyze_yim_decoded_homolog(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    session039: dict[str, object],
    session040: dict[str, object],
    session042: dict[str, object],
    results: list[tuple[dict[str, object], YimDecodeResult]],
) -> dict[str, object]:
    if session042.get("schema") != (
        "phoenix-mmi.distributed-homolog-comparison/v1"
    ):
        raise ValueError("unsupported Session 042 schema")
    if session042["classification"].get("distributed_near_homolog") != (
        "NOT_FOUND_UNDER_FIXED_DISTRIBUTED_MODEL"
    ):
        raise ValueError("Session 042 distributed result changed")
    constellation = derive_distributed_constellation(
        left_reader,
        right_reader,
        session038,
        session039,
        session040,
    )
    unique_rasters: dict[str, dict[str, object]] = {}
    for source, result in results:
        digest = hashlib.sha256(result.raster).hexdigest()
        row = unique_rasters.setdefault(
            digest,
            {
                "raster": result.raster,
                "sources": [],
            },
        )
        row["sources"].append({"source_id": source["source_id"]})
    rows = [
        scan_distributed_unit(
            bytes(row["raster"]),
            constellation,
            domain="YIM_DECODED_RASTER",
            sources=copy.deepcopy(row["sources"]),
        )
        for row in unique_rasters.values()
    ]
    summary = summarize_distributed_units(rows)
    if summary["saturated_unique_unit_count"]:
        classification = "INCONCLUSIVE_YIM_RASTER_SCAN_SATURATED"
    elif summary["control_strong_unit_count"]:
        classification = "YIM_RASTER_MODEL_NOT_DISCRIMINATING"
    elif summary["target_strong_unit_count"]:
        classification = "YIM_RASTER_HOMOLOG_SUPPORTED"
    elif summary["target_candidate_unit_count"]:
        classification = "YIM_RASTER_CONSTELLATION_CANDIDATE_ONLY"
    else:
        classification = "NOT_FOUND_IN_VALIDATED_YIM_RASTERS"
    report = {
        "schema": "phoenix-mmi.yim-decoded-homolog/v1",
        "analysis_mode": "read-only-fixed-distributed-yim-raster-search",
        "session": "049",
        "source_unique_count": len(results),
        "decoded_raster_unique_content_count": len(unique_rasters),
        "decoded_raster_bytes": sum(
            len(bytes(row["raster"])) for row in unique_rasters.values()
        ),
        "session042_contract_reused": True,
        "domain_summary": summary,
        "classification": {
            "yim_decoded_homolog": classification,
            "semantic_owner": "OPEN",
            "runtime_loader_transform": "NOT_OBSERVED",
        },
        "operational_graph_version": "v41",
        "publication_safety": _publication_safety(),
    }
    return report


def build_firmware_evidence_map(
    prior_correlation: dict[str, object],
    reports: list[dict[str, object]],
) -> dict[str, object]:
    if prior_correlation.get("schema") != (
        "phoenix-mmi.distributed-homolog-correlation/v1"
    ):
        raise ValueError("unsupported Session 042 correlation schema")
    expected_sessions = [f"{number:03d}" for number in range(44, 50)]
    if [str(report.get("session")) for report in reports] != expected_sessions:
        raise ValueError("Sessions 044-049 report order differs")
    graph = copy.deepcopy(prior_correlation["operational_graph"])
    node_specs = [
        (
            "legacy-container-census",
            "legacy_family_census",
            "classifies-legacy-families",
        ),
        ("yim-envelope", "yim_envelope", "validates-envelope"),
        ("yim-rle", "yim_payload_codec", "validates-private-decoder"),
        (
            "yim-integrity",
            "yim_integrity_fields",
            "bounds-safe-repacking",
        ),
        ("lod-topology", "lod_structure", "profiles-opaque-family"),
        (
            "yim-decoded-homolog",
            "yim_decoded_homolog",
            "tests-decoded-display-assets",
        ),
    ]
    previous = "distributed-near-homolog"
    for report, (node_id, key, relation) in zip(reports, node_specs):
        status = str(report["classification"][key])
        graph["nodes"].append(
            {
                "id": node_id,
                "status": status,
                "evidence_session": report["session"],
            }
        )
        graph["edges"].append(
            {
                "source": previous,
                "target": node_id,
                "status": status,
                "relation": relation,
            }
        )
        previous = node_id
    graph["nodes"].append(
        {
            "id": "firmware-evidence-map",
            "status": "PARTIAL_EVIDENCE_LINKED_MODEL",
            "evidence_session": "050",
        }
    )
    graph["edges"].append(
        {
            "source": previous,
            "target": "firmware-evidence-map",
            "status": "SYNTHESIZED",
            "relation": "contributes-to-integrated-model",
        }
    )
    graph["schema"] = "phoenix-mmi.operational-graph/v42"
    return {
        "schema": "phoenix-mmi.firmware-evidence-map/v1",
        "analysis_mode": "evidence-only-cross-session-synthesis",
        "session": "050",
        "source_sessions": [
            "001-042",
            *expected_sessions,
        ],
        "layers": [
            {
                "id": "UPDATE_MEDIA",
                "status": "CONFIRMED",
                "role": "ISO9660 media and METAINFO-driven component selection",
            },
            {
                "id": "DISTRIBUTED_COMPONENT_PAYLOADS",
                "status": "CONFIRMED_PARTIAL_FORMAT_COVERAGE",
                "role": "MOST-device applications, bootloaders and data packages",
            },
            {
                "id": "MAIN_MMI_IMAGE",
                "status": "STRUCTURALLY_MAPPED_SEMANTIC_OWNER_OPEN",
                "role": "SuperH main-unit code, data and inferred runtime relationships",
            },
            {
                "id": "VALIDATED_RECORD_CONTAINERS",
                "status": "HEX_AND_SREC_VALIDATED",
                "role": "addressed peripheral update payloads",
            },
            {
                "id": "DISPLAY_ASSETS",
                "status": "YIM_XIM2_READ_ONLY_DECODER_VALIDATED",
                "role": "fixed-geometry RLE-compressed display rasters",
            },
            {
                "id": "SPEECH_LANGUAGE_PAYLOAD",
                "status": "LOD_STRUCTURED_BUT_OPAQUE",
                "role": "language-specific SDS payload family",
            },
            {
                "id": "NAVIGATION_MEDIA",
                "status": "PARTIALLY_MAPPED",
                "role": "optical navigation data and runtime consumers",
            },
        ],
        "closed_in_cycle": [
            "LOD/YIM family census",
            "YIM XIM2 envelope geometry",
            "YIM bounded RLE decoding",
            "decoded YIM fixed-homolog search",
        ],
        "open_after_cycle": [
            "YIM preamble integrity algorithm",
            "LOD record, address and integrity model",
            "safe YIM repacking",
            "exact main-image section boundary",
            "semantic owner of the reorder component",
            "external or runtime loader transformation",
        ],
        "classification": {
            "firmware_operational_model": (
                "PARTIAL_EVIDENCE_LINKED_MODEL"
            ),
            "milestone_m1": "PARTIAL_NOT_COMPLETE",
            "safe_mutation_ready": False,
        },
        "operational_graph": graph,
        "operational_graph_version": "v42",
        "publication_safety": _publication_safety(),
    }

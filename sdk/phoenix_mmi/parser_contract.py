"""Bounded firmware constant coupling for the navigation-media parser gap."""

from __future__ import annotations

from collections import Counter, defaultdict
import copy

from .binary import BinaryReader
from .navigation_dataflow import summarize_code_window
from .navigation_storage import discover_boundary_markers
from .strings import extract_strings


PARSER_CONSTANTS = {
    "fldb-directory-offset": 0x220,
    "fldb-record-size": 36,
    "logical-sector-size": 2048,
}


def _nearest_boundary(
    offset: int,
    boundary_hits: list[dict[str, object]],
    *,
    maximum_distance: int = 0x10000,
) -> dict[str, object] | None:
    if not boundary_hits:
        return None
    nearest = min(
        boundary_hits, key=lambda item: abs(int(item["offset"]) - offset)
    )
    distance = int(nearest["offset"]) - offset
    if abs(distance) > maximum_distance:
        return None
    return {
        "signed_distance": distance,
        "marker_ids": list(nearest["markers"]),
        "categories": list(nearest["categories"]),
        "maximum_distance": maximum_distance,
        "raw_string_included": False,
    }


def scan_parser_constants(reader: BinaryReader) -> dict[str, object]:
    """Scan one SH image once for exact PC-relative constant loads."""

    data = reader.read(0, reader.size)
    wanted = {value: constant_id for constant_id, value in PARSER_CONSTANTS.items()}
    boundary_hits = discover_boundary_markers(extract_strings(reader, min_length=4))
    mov_l_hits: dict[str, list[dict[str, object]]] = defaultdict(list)
    mov_w_counts: Counter[str] = Counter()
    immediate_counts: Counter[str] = Counter()
    for offset in range(0, len(data) - 1, 2):
        word = (data[offset] << 8) | data[offset + 1]
        if word & 0xF000 == 0xD000:
            literal_offset = (offset & ~3) + 4 + (word & 0xFF) * 4
            if literal_offset + 4 <= len(data):
                value = int.from_bytes(data[literal_offset : literal_offset + 4], "big")
                constant_id = wanted.get(value)
                if constant_id is not None:
                    window = summarize_code_window(
                        reader, offset, before=0x40, after=0x80
                    )
                    mov_l_hits[constant_id].append(
                        {
                            "load_offset": offset,
                            "literal_word_offset": literal_offset,
                            "known_ratio": window["known_ratio"],
                            "normalized_shape_sha256": window[
                                "normalized_shape_sha256"
                            ],
                            "mnemonic_counts": window["mnemonic_counts"],
                            "flow_counts": window["flow_counts"],
                            "nearest_fixed_boundary": _nearest_boundary(
                                offset, boundary_hits
                            ),
                            "instruction_bytes_included": False,
                        }
                    )
        elif word & 0xF000 == 0x9000:
            literal_offset = offset + 4 + (word & 0xFF) * 2
            if literal_offset + 2 <= len(data):
                value = int.from_bytes(
                    data[literal_offset : literal_offset + 2], "big", signed=True
                )
                constant_id = wanted.get(value)
                if constant_id is not None:
                    mov_w_counts[constant_id] += 1
        elif word & 0xF000 == 0xE000:
            immediate = word & 0xFF
            if immediate & 0x80:
                immediate -= 0x100
            constant_id = wanted.get(immediate)
            if constant_id is not None:
                immediate_counts[constant_id] += 1

    constants = []
    for constant_id, value in PARSER_CONSTANTS.items():
        hits = sorted(
            mov_l_hits.get(constant_id, []),
            key=lambda item: int(item["load_offset"]),
        )
        constants.append(
            {
                "constant_id": constant_id,
                "value": value,
                "mov_l_reference_count": len(hits),
                "mov_l_references": hits,
                "unique_literal_pool_word_count": len(
                    {int(hit["literal_word_offset"]) for hit in hits}
                ),
                "mov_w_reference_count": mov_w_counts[constant_id],
                "signed_immediate_reference_count": immediate_counts[constant_id],
            }
        )
    return {
        "schema": "phoenix-mmi.parser-constant-probes/v1",
        "analysis_mode": "read-only-static-single-pass",
        "artifact": {
            "sha256": reader.sha256(),
            "size_bytes": reader.size,
            "source_path_included": False,
        },
        "constants": constants,
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_strings_included": False,
            "raw_runtime_addresses_included": False,
            "local_paths_included": False,
        },
    }


def compare_parser_constants(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    """Pair constant-load windows only by ID and normalized instruction shape."""

    left_by_id = {item["constant_id"]: item for item in left["constants"]}
    right_by_id = {item["constant_id"]: item for item in right["constants"]}
    comparisons = []
    for constant_id in sorted(left_by_id.keys() & right_by_id.keys()):
        left_item = left_by_id[constant_id]
        right_item = right_by_id[constant_id]
        pairs = []
        used_right: set[int] = set()
        for left_hit in left_item["mov_l_references"]:
            for right_ordinal, right_hit in enumerate(right_item["mov_l_references"]):
                if right_ordinal in used_right:
                    continue
                if (
                    left_hit["normalized_shape_sha256"]
                    != right_hit["normalized_shape_sha256"]
                ):
                    continue
                used_right.add(right_ordinal)
                pairs.append(
                    {
                        "left_load_offset": left_hit["load_offset"],
                        "right_load_offset": right_hit["load_offset"],
                        "relocation_delta": int(right_hit["load_offset"])
                        - int(left_hit["load_offset"]),
                        "normalized_shape_sha256": left_hit[
                            "normalized_shape_sha256"
                        ],
                        "left_known_ratio": left_hit["known_ratio"],
                        "right_known_ratio": right_hit["known_ratio"],
                        "high_known_ratio_pair": (
                            float(left_hit["known_ratio"]) >= 0.5
                            and float(right_hit["known_ratio"]) >= 0.5
                        ),
                    }
                )
                break
        comparisons.append(
            {
                "constant_id": constant_id,
                "value": left_item["value"],
                "left_mov_l_reference_count": left_item["mov_l_reference_count"],
                "right_mov_l_reference_count": right_item["mov_l_reference_count"],
                "left_unique_literal_pool_word_count": left_item[
                    "unique_literal_pool_word_count"
                ],
                "right_unique_literal_pool_word_count": right_item[
                    "unique_literal_pool_word_count"
                ],
                "paired_window_count": len(pairs),
                "high_known_ratio_pair_count": sum(
                    bool(pair["high_known_ratio_pair"]) for pair in pairs
                ),
                "pairs": pairs,
            }
        )
    directory = next(
        item for item in comparisons if item["constant_id"] == "fldb-directory-offset"
    )
    directory_probable = bool(
        directory["paired_window_count"] >= 2
        and directory["high_known_ratio_pair_count"] >= 2
        and directory["left_unique_literal_pool_word_count"] == 1
        and directory["right_unique_literal_pool_word_count"] == 1
    )
    return {
        "schema": "phoenix-mmi.parser-constant-comparison/v1",
        "analysis_mode": "read-only-static-cross-version",
        "left_artifact_sha256": left["artifact"]["sha256"],
        "right_artifact_sha256": right["artifact"]["sha256"],
        "constants": comparisons,
        "classification": {
            "fldb_directory_offset_coupling": (
                "PROBABLE_CROSS_VERSION_CODE_COUPLED_CONSTANT"
                if directory_probable
                else "BOUNDED_AMBIGUOUS"
            ),
            "fldb_record_size_coupling": "BOUNDED_AMBIGUOUS",
            "logical_sector_size_coupling": "BOUNDED_AMBIGUOUS",
            "fldb_parser_edge": "NOT_CONFIRMED",
            "sector_read_abi": "OPEN",
        },
        "interpretation": (
            "Two relocation-paired, high-known-ratio SH windows load the exact "
            "FLDB directory offset from one literal-pool word in each release. "
            "This is probable static numeric coupling, not proof that the routine "
            "parses FLDB. Record-size and sector-size constants remain ambiguous."
        ),
        "publication_safety": copy.deepcopy(left["publication_safety"]),
    }


def correlate_payload_parser_contract(
    prior_contract: dict[str, object],
    payload_report: dict[str, object],
    constant_comparison: dict[str, object],
) -> dict[str, object]:
    result = {
        "schema": "phoenix-mmi.payload-parser-correlation/v1",
        "analysis_mode": "read-only-static",
        "media": {
            "inner_payload_schema": payload_report["classification"][
                "inner_payload_schema"
            ],
            "partition_model": payload_report["classification"]["partition_model"],
            "speech_payload_model": payload_report["classification"][
                "speech_payload_model"
            ],
        },
        "firmware": copy.deepcopy(constant_comparison["classification"]),
        "correlation": {
            "numeric_directory_offset_bridge": constant_comparison[
                "classification"
            ]["fldb_directory_offset_coupling"],
            "direct_fldb_parser": "NOT_CONFIRMED",
            "partition_consumer": "OPEN",
            "sector_read_abi": "OPEN",
            "dynamic_compatibility": "NOT_ESTABLISHED",
        },
        "interpretation": (
            "Session 012 confirms proprietary family headers, two fixed internal "
            "directory grammars, a speech index/data split and a 16-partition media "
            "topology. Firmware contains a strong cross-version code-coupled 0x220 "
            "constant candidate, but no direct parser, partition consumer or sector "
            "ABI is established."
        ),
        "publication_safety": copy.deepcopy(payload_report["publication_safety"]),
    }
    result["operational_graph"] = update_operational_graph_v5(
        prior_contract["operational_graph"], result
    )
    return result


def update_operational_graph_v5(
    prior_graph: dict[str, object], correlation: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v5"
    map_node = next(node for node in graph["nodes"] if node["id"] == "map-media-format")
    map_node.update(
        {
            "status": "PARTIAL_CONFIRMED_PARTITION_MODEL",
            "inner_payload_schema": "PARTIAL_PROPRIETARY_FAMILY_HEADERS_AND_DIRECTORIES",
            "partition_model": "CONFIRMED_CROSS_FAMILY_16_PARTITION_TOPOLOGY",
            "evidence": ["S012-01", "S012-02", "RQ-022", "RQ-029", "RQ-032"],
        }
    )
    graph["nodes"].extend(
        (
            {
                "id": "navigation-payload-partitions",
                "label": "Proprietary payload families and 16-partition topology",
                "status": "CONFIRMED_STRUCTURAL_PARTITION_GRAPH",
                "semantic_consumer": "OPEN",
                "evidence": ["S012-01", "S012-02"],
            },
            {
                "id": "speech-index-data-split",
                "label": "Declared speech text-index and binary-data split",
                "status": "CONFIRMED_MEDIA_STRUCTURE",
                "consumer": "OPEN",
                "evidence": ["S012-03"],
            },
            {
                "id": "fldb-directory-offset-candidate",
                "label": "Cross-version SH constant-load candidate for FLDB directory offset",
                "status": "PROBABLE_STATIC_CONSTANT_COUPLING",
                "parser_semantics": "OPEN",
                "evidence": ["S012-04", "RQ-033"],
            },
        )
    )
    graph["edges"].extend(
        (
            {
                "source": "fldb-container-set",
                "target": "navigation-payload-partitions",
                "relation": "contains validated family headers and partition sets",
                "status": "CONFIRMED_MEDIA_LAYOUT",
            },
            {
                "source": "navigation-payload-partitions",
                "target": "navigation-runtime",
                "relation": "partition consumer remains unresolved",
                "status": "HYPOTHESIS",
            },
            {
                "source": "fldb-directory-offset-candidate",
                "target": "fldb-container-set",
                "relation": "loads the exact fixed directory offset",
                "status": "PROBABLE_NUMERIC_COUPLING",
            },
            {
                "source": "optical-volume-reader",
                "target": "fldb-directory-offset-candidate",
                "relation": "runtime call/ABI edge remains unresolved",
                "status": "HYPOTHESIS",
            },
        )
    )
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED") for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE") for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(node["status"] == "OPEN" for node in graph["nodes"])
    graph["interpretation"] = (
        "Session 012 confirms media-side family directories and partition structure "
        "and adds a probable firmware numeric coupling. Parser semantics, partition "
        "consumer, sector ABI, backing volume and modified-map compatibility remain open."
    )
    return graph

"""Read-only navigation dataflow and optical-service contract analysis.

Session 010 deliberately limits itself to predeclared semantic anchors, bounded
SuperH instruction windows and relocation-normalized data neighborhoods.  It
does not infer function boundaries, execute firmware or publish arbitrary
strings, runtime addresses or binary payloads.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
from dataclasses import dataclass
import hashlib
import re

from .binary import BinaryReader
from .entropy import shannon_entropy
from .navigation_storage import (
    RUNTIME_BASE,
    discover_boundary_markers,
)
from .strings import StringRecord, extract_strings
from .superh import decode_instruction, find_pc_relative_referrers


@dataclass(frozen=True)
class ContractAnchor:
    """One fixed publication-safe anchor used by Session 010."""

    anchor_id: str
    category: str
    expression: str


ANCHORS = (
    ContractAnchor(
        "navigation-internal-data", "navigation-data", r"navigation internal data"
    ),
    ContractAnchor("routeact-dat", "route-data", r"routeact\.dat"),
    ContractAnchor("cdrom-manager", "optical-service", r"CDROMMgr"),
    ContractAnchor(
        "cdrom-access-event", "optical-service", r"CCDROMAccessEvent"
    ),
    ContractAnchor(
        "cdrom-access-thread-dispatcher",
        "optical-service",
        r"CDROMAccessThreadDispatcher",
    ),
    ContractAnchor(
        "cdrom-thread-dispatcher",
        "optical-service",
        r"(?<!Access)CDROMThreadDispatcher",
    ),
    ContractAnchor(
        "cdrom-manager-task", "optical-service", r"CRBCDROMManagerTask"
    ),
    ContractAnchor(
        "cdrom-command-event", "optical-service", r"CRBCDROMCommandEvent"
    ),
    ContractAnchor(
        "cdrom-filesystem-event",
        "optical-service",
        r"CRBCDROMFileSystemEvent",
    ),
    ContractAnchor("cdrom-event", "optical-service", r"CRBCDROMEvent"),
    ContractAnchor("map-position", "route-data", r"(?<!Store )Map position"),
    ContractAnchor("navi-stream", "route-data", r"Navi stream"),
    ContractAnchor("map-route-task", "route-data", r"Map route task"),
)

_COMPILED_ANCHORS = tuple(
    (anchor, re.compile(anchor.expression, re.IGNORECASE)) for anchor in ANCHORS
)
_ADDRESS_RE = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)


def _record_key(anchor_id: str, record: StringRecord, match_start: int) -> str:
    material = (
        f"{anchor_id}\0{record.encoding}\0{match_start}\0{record.text}"
    ).encode("utf-8", "surrogatepass")
    return hashlib.sha256(material).hexdigest()


def discover_contract_anchors(records: list[StringRecord]) -> list[dict[str, object]]:
    """Locate only predeclared anchors and omit their source text."""

    hits: list[dict[str, object]] = []
    for record in records:
        for anchor, pattern in _COMPILED_ANCHORS:
            for match in pattern.finditer(record.text):
                hits.append(
                    {
                        "anchor_id": anchor.anchor_id,
                        "category": anchor.category,
                        "offset": record.offset + match.start(),
                        "match_length": match.end() - match.start(),
                        "encoding": record.encoding,
                        "_internal_record_key": _record_key(
                            anchor.anchor_id, record, match.start()
                        ),
                    }
                )
    return sorted(hits, key=lambda hit: (int(hit["offset"]), str(hit["anchor_id"])))


def summarize_runtime_neighborhood(
    reader: BinaryReader,
    center: int,
    *,
    radius: int = 0x80,
    runtime_base: int = RUNTIME_BASE,
) -> dict[str, object]:
    if radius <= 0:
        raise ValueError("radius must be positive")
    start = max(0, center - radius)
    end = min(reader.size, center + radius)
    raw = reader.read(start, end - start)
    normalized = bytearray(raw)
    pointer_count = 0
    first_aligned = (-start) % 4
    for relative in range(first_aligned, len(normalized) - 3, 4):
        value = int.from_bytes(normalized[relative : relative + 4], "big")
        if runtime_base <= value < runtime_base + reader.size:
            normalized[relative : relative + 4] = b"PTR!"
            pointer_count += 1
    return {
        "start": start,
        "end": end,
        "length": end - start,
        "radius": radius,
        "aligned_runtime_pointer_count": pointer_count,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "normalized_sha256": hashlib.sha256(normalized).hexdigest(),
        "entropy": round(shannon_entropy(raw), 6),
        "raw_bytes_included": False,
        "raw_runtime_addresses_included": False,
    }


def _instruction_shape(instruction: object) -> str:
    operands = _ADDRESS_RE.sub("<address>", instruction.operands)
    return "|".join(
        (
            instruction.mnemonic,
            operands,
            instruction.flow,
            "delayed" if instruction.delayed else "plain",
        )
    )


def summarize_code_window(
    reader: BinaryReader,
    center: int,
    *,
    before: int = 0x40,
    after: int = 0x80,
) -> dict[str, object]:
    """Summarize an aligned window without asserting a function boundary."""

    if before < 0 or after <= 0:
        raise ValueError("before must be non-negative and after must be positive")
    start = max(0, center - before) & ~1
    end = min(reader.size, center + after) & ~1
    instructions = [decode_instruction(reader, offset) for offset in range(start, end, 2)]
    known = [instruction for instruction in instructions if instruction.mnemonic != "unknown"]
    shapes = [_instruction_shape(instruction) for instruction in instructions]
    resolved_calls = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic != "jsr" or index == 0:
            continue
        register_match = re.fullmatch(r"@r(\d+)", instruction.operands)
        previous = instructions[index - 1]
        previous_match = re.search(r",r(\d+)$", previous.operands)
        if (
            register_match is None
            or previous_match is None
            or previous.mnemonic != "mov.l"
            or previous.literal_address is None
            or previous.literal_value is None
            or register_match.group(1) != previous_match.group(1)
        ):
            continue
        target_offset = previous.literal_value - RUNTIME_BASE
        resolved_calls.append(
            {
                "load_offset": previous.offset,
                "call_site_offset": instruction.offset,
                "literal_word_offset": previous.literal_address,
                "target_file_offset": target_offset if 0 <= target_offset < reader.size else None,
                "target_in_image": 0 <= target_offset < reader.size,
                "resolution_status": "ADJACENT_PC_RELATIVE_MOV_L_TO_JSR",
                "raw_runtime_address_included": False,
            }
        )
    direct_calls = [
        {"call_site_offset": instruction.offset, "target_file_offset": instruction.target}
        for instruction in instructions
        if instruction.flow == "call" and instruction.target is not None
    ]
    return {
        "center": center,
        "start": start,
        "end": end,
        "instruction_count": len(instructions),
        "known_instruction_count": len(known),
        "known_ratio": round(len(known) / len(instructions), 6) if instructions else 0.0,
        "mnemonic_counts": dict(sorted(Counter(i.mnemonic for i in instructions).items())),
        "flow_counts": dict(sorted(Counter(i.flow for i in instructions).items())),
        "normalized_shape_sha256": hashlib.sha256(
            "\n".join(shapes).encode("utf-8")
        ).hexdigest(),
        "resolved_adjacent_indirect_calls": resolved_calls,
        "direct_relative_calls": direct_calls,
        "instruction_bytes_included": False,
        "function_boundary_asserted": False,
    }


def _nearest_boundary_marker(
    target_offset: int,
    boundary_hits: list[dict[str, object]],
    *,
    maximum_distance: int = 0x4000,
) -> dict[str, object] | None:
    if not boundary_hits:
        return None
    nearest = min(
        boundary_hits, key=lambda hit: abs(int(hit["offset"]) - target_offset)
    )
    signed_distance = int(nearest["offset"]) - target_offset
    if abs(signed_distance) > maximum_distance:
        return None
    return {
        "signed_distance": signed_distance,
        "markers": list(nearest["markers"]),
        "categories": list(nearest["categories"]),
        "maximum_distance": maximum_distance,
        "raw_string_included": False,
    }


def scan_contract_references(
    reader: BinaryReader,
    hits: list[dict[str, object]],
    *,
    boundary_hits: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Find exact linked words, bounded MOV.L users and adjacent JSR targets."""

    data = reader.read(0, reader.size)
    edges = []
    target_contexts: dict[int, dict[str, object]] = {}
    for hit in hits:
        linked_word = (RUNTIME_BASE + int(hit["offset"])).to_bytes(4, "big")
        search_from = 0
        while True:
            literal_word_offset = data.find(linked_word, search_from)
            if literal_word_offset < 0:
                break
            search_from = literal_word_offset + 1
            if literal_word_offset % 4:
                continue
            referrers = find_pc_relative_referrers(reader, literal_word_offset)
            windows = [summarize_code_window(reader, item.offset) for item in referrers]
            for window in windows:
                for call in window["resolved_adjacent_indirect_calls"]:
                    target = call["target_file_offset"]
                    if target is None or target in target_contexts:
                        continue
                    target_contexts[target] = {
                        "target_file_offset": target,
                        "code_window": summarize_code_window(
                            reader, target, before=0, after=0x40
                        ),
                        "nearest_fixed_boundary_marker": _nearest_boundary_marker(
                            target, boundary_hits or []
                        ),
                    }
            edges.append(
                {
                    "anchor_id": hit["anchor_id"],
                    "category": hit["category"],
                    "target_anchor_offset": hit["offset"],
                    "literal_word_offset": literal_word_offset,
                    "referrer_windows": windows,
                }
            )
    return {
        "exact_linked_word_count": len(edges),
        "pc_relative_referrer_count": sum(
            len(edge["referrer_windows"]) for edge in edges
        ),
        "referrer_counts_by_anchor": dict(
            sorted(
                Counter(
                    str(edge["anchor_id"])
                    for edge in edges
                    for _ in edge["referrer_windows"]
                ).items()
            )
        ),
        "edges": edges,
        "resolved_target_contexts": [
            target_contexts[offset] for offset in sorted(target_contexts)
        ],
        "raw_runtime_addresses_included": False,
        "raw_strings_included": False,
    }


def analyze_navigation_dataflow(
    reader: BinaryReader,
    *,
    min_string_length: int = 5,
    neighborhood_radius: int = 0x80,
) -> dict[str, object]:
    """Analyze one principal image without executing or modifying it."""

    records = extract_strings(reader, min_length=min_string_length)
    anchor_hits = discover_contract_anchors(records)
    boundary_hits = discover_boundary_markers(records)
    neighborhoods = [
        {
            "anchor_id": hit["anchor_id"],
            "category": hit["category"],
            "anchor_offset": hit["offset"],
            "neighborhood": summarize_runtime_neighborhood(
                reader, int(hit["offset"]), radius=neighborhood_radius
            ),
        }
        for hit in anchor_hits
    ]
    references = scan_contract_references(
        reader, anchor_hits, boundary_hits=boundary_hits
    )
    anchor_counts = Counter(str(hit["anchor_id"]) for hit in anchor_hits)
    category_counts = Counter(str(hit["category"]) for hit in anchor_hits)
    optical_anchor_ids = {
        anchor.anchor_id for anchor in ANCHORS if anchor.category == "optical-service"
    }
    present_optical = optical_anchor_ids & set(anchor_counts)
    nav_referrers = int(
        references["referrer_counts_by_anchor"].get("navigation-internal-data", 0)
    )
    return {
        "schema": "phoenix-mmi.navigation-dataflow/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "filename": reader.path.name,
            "size_bytes": reader.size,
            "sha256": reader.sha256(),
        },
        "anchor_vocabulary": [
            {"id": anchor.anchor_id, "category": anchor.category}
            for anchor in ANCHORS
        ],
        "anchor_inventory": {
            "matched_anchor_count": len(anchor_hits),
            "anchor_counts": dict(sorted(anchor_counts.items())),
            "category_counts": dict(sorted(category_counts.items())),
            "raw_strings_included": False,
        },
        "anchor_hits": anchor_hits,
        "normalized_neighborhoods": neighborhoods,
        "code_coupling": references,
        "classification": {
            "navigation_data_callsites": (
                "CONFIRMED_BOUNDED_CODE_COUPLING"
                if nav_referrers >= 2
                else "PARTIAL"
            ),
            "route_data_records": (
                "PRESENT_WITHOUT_DIRECT_CODE_REFERENCE"
                if anchor_counts.get("routeact-dat", 0)
                else "NOT_DETECTED"
            ),
            "optical_service_record_family": (
                "CONFIRMED_EMBEDDED_RECORD_FAMILY"
                if len(present_optical) >= 6
                else "PARTIAL"
            ),
            "navigation_to_optical_direct_edge": "NOT_CONFIRMED",
            "function_semantics": "OPEN",
            "map_media_schema": "OPEN",
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "instruction_bytes_included": False,
            "raw_strings_included": False,
            "raw_runtime_addresses_included": False,
            "map_payload_included": False,
            "route_payload_included": False,
        },
    }


def _group_by_anchor(items: list[dict[str, object]], offset_key: str) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in items:
        grouped[str(item["anchor_id"])].append(item)
    for values in grouped.values():
        values.sort(key=lambda item: int(item[offset_key]))
    return grouped


def _pair_referrer_windows(
    left: dict[str, object], right: dict[str, object]
) -> list[dict[str, object]]:
    left_windows: dict[str, list[dict[str, object]]] = defaultdict(list)
    right_windows: dict[str, list[dict[str, object]]] = defaultdict(list)
    for report, destination in ((left, left_windows), (right, right_windows)):
        for edge in report["code_coupling"]["edges"]:
            destination[str(edge["anchor_id"])].extend(edge["referrer_windows"])
        for values in destination.values():
            values.sort(key=lambda window: int(window["center"]))

    left_contexts = {
        int(context["target_file_offset"]): context
        for context in left["code_coupling"]["resolved_target_contexts"]
    }
    right_contexts = {
        int(context["target_file_offset"]): context
        for context in right["code_coupling"]["resolved_target_contexts"]
    }

    pairs = []
    for anchor_id in sorted(left_windows.keys() & right_windows.keys()):
        for ordinal, (left_window, right_window) in enumerate(
            zip(left_windows[anchor_id], right_windows[anchor_id])
        ):
            left_calls = left_window["resolved_adjacent_indirect_calls"]
            right_calls = right_window["resolved_adjacent_indirect_calls"]
            call_pairs = []
            for call_ordinal, (left_call, right_call) in enumerate(
                zip(left_calls, right_calls)
            ):
                left_target = left_call["target_file_offset"]
                right_target = right_call["target_file_offset"]
                left_context = left_contexts.get(left_target)
                right_context = right_contexts.get(right_target)
                target_shape_equal = None
                if left_context is not None and right_context is not None:
                    target_shape_equal = (
                        left_context["code_window"]["normalized_shape_sha256"]
                        == right_context["code_window"]["normalized_shape_sha256"]
                    )
                call_pairs.append(
                    {
                        "ordinal": call_ordinal,
                        "left_call_site_offset": left_call["call_site_offset"],
                        "right_call_site_offset": right_call["call_site_offset"],
                        "left_target_file_offset": left_target,
                        "right_target_file_offset": right_target,
                        "target_relocation_delta": (
                            right_target - left_target
                            if left_target is not None and right_target is not None
                            else None
                        ),
                        "target_window_shape_equal": target_shape_equal,
                        "left_nearest_fixed_boundary_marker": (
                            copy.deepcopy(
                                left_context["nearest_fixed_boundary_marker"]
                            )
                            if left_context is not None
                            else None
                        ),
                        "right_nearest_fixed_boundary_marker": (
                            copy.deepcopy(
                                right_context["nearest_fixed_boundary_marker"]
                            )
                            if right_context is not None
                            else None
                        ),
                        "resolution_status": "PAIRED_ADJACENT_PC_RELATIVE_MOV_L_TO_JSR",
                    }
                )
            pairs.append(
                {
                    "anchor_id": anchor_id,
                    "ordinal": ordinal,
                    "left_center": left_window["center"],
                    "right_center": right_window["center"],
                    "relocation_delta": right_window["center"] - left_window["center"],
                    "normalized_instruction_shape_equal": (
                        left_window["normalized_shape_sha256"]
                        == right_window["normalized_shape_sha256"]
                    ),
                    "left_known_ratio": left_window["known_ratio"],
                    "right_known_ratio": right_window["known_ratio"],
                    "resolved_call_pairs": call_pairs,
                    "function_boundary_asserted": False,
                }
            )
    return pairs


def compare_navigation_dataflow(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    """Compare anchor neighborhoods and bounded call-site windows."""

    left_groups = _group_by_anchor(left["normalized_neighborhoods"], "anchor_offset")
    right_groups = _group_by_anchor(right["normalized_neighborhoods"], "anchor_offset")
    neighborhood_pairs = []
    for anchor_id in sorted(left_groups.keys() & right_groups.keys()):
        for ordinal, (left_item, right_item) in enumerate(
            zip(left_groups[anchor_id], right_groups[anchor_id])
        ):
            left_neighborhood = left_item["neighborhood"]
            right_neighborhood = right_item["neighborhood"]
            neighborhood_pairs.append(
                {
                    "anchor_id": anchor_id,
                    "category": left_item["category"],
                    "ordinal": ordinal,
                    "left_anchor_offset": left_item["anchor_offset"],
                    "right_anchor_offset": right_item["anchor_offset"],
                    "relocation_delta": (
                        right_item["anchor_offset"] - left_item["anchor_offset"]
                    ),
                    "raw_window_equal": (
                        left_neighborhood["raw_sha256"]
                        == right_neighborhood["raw_sha256"]
                    ),
                    "runtime_pointer_normalized_window_equal": (
                        left_neighborhood["normalized_sha256"]
                        == right_neighborhood["normalized_sha256"]
                    ),
                    "left_runtime_pointer_count": left_neighborhood[
                        "aligned_runtime_pointer_count"
                    ],
                    "right_runtime_pointer_count": right_neighborhood[
                        "aligned_runtime_pointer_count"
                    ],
                    "window_length": left_neighborhood["length"],
                }
            )

    callsite_pairs = _pair_referrer_windows(left, right)
    optical_pairs = [
        pair for pair in neighborhood_pairs if pair["category"] == "optical-service"
    ]
    optical_equal = sum(
        bool(pair["runtime_pointer_normalized_window_equal"])
        for pair in optical_pairs
    )
    routeact_pairs = [
        pair for pair in neighborhood_pairs if pair["anchor_id"] == "routeact-dat"
    ]
    nav_callsite_pairs = [
        pair
        for pair in callsite_pairs
        if pair["anchor_id"] == "navigation-internal-data"
    ]
    nav_shapes_equal = sum(
        bool(pair["normalized_instruction_shape_equal"])
        for pair in nav_callsite_pairs
    )
    resolved_call_pairs = [
        call
        for pair in nav_callsite_pairs
        for call in pair["resolved_call_pairs"]
    ]
    storage_adjacent_call_pairs = sum(
        bool(call["left_nearest_fixed_boundary_marker"])
        and bool(call["right_nearest_fixed_boundary_marker"])
        and "storage"
        in call["left_nearest_fixed_boundary_marker"]["categories"]
        and "storage"
        in call["right_nearest_fixed_boundary_marker"]["categories"]
        for call in resolved_call_pairs
    )
    return {
        "schema": "phoenix-mmi.navigation-dataflow-comparison/v1",
        "analysis_mode": "read-only-static",
        "left": left["artifact"].get("label", left["artifact"]["filename"]),
        "right": right["artifact"].get("label", right["artifact"]["filename"]),
        "neighborhood_pairs": neighborhood_pairs,
        "paired_neighborhood_count": len(neighborhood_pairs),
        "runtime_pointer_normalized_equal_count": sum(
            bool(pair["runtime_pointer_normalized_window_equal"])
            for pair in neighborhood_pairs
        ),
        "callsite_window_pairs": callsite_pairs,
        "resolved_adjacent_call_pair_count": len(resolved_call_pairs),
        "storage_marker_adjacent_call_pair_count": storage_adjacent_call_pairs,
        "classification": {
            "navigation_data_lifecycle": (
                "CONFIRMED_CROSS_VERSION_CODE_COUPLED_ROUTINE_PAIR"
                if len(nav_callsite_pairs) >= 2 and nav_shapes_equal >= 2
                else "PARTIAL"
            ),
            "route_data_contract": (
                "CONFIRMED_CROSS_VERSION_RELOCATED_RECORDS_NO_DIRECT_CONSUMER"
                if routeact_pairs
                and all(
                    pair["runtime_pointer_normalized_window_equal"]
                    for pair in routeact_pairs
                )
                else "PARTIAL"
            ),
            "optical_service_contract": (
                "CONFIRMED_CROSS_VERSION_RELOCATED_RUNTIME_ADDRESS_NEIGHBORHOODS"
                if len(optical_pairs) >= 6 and optical_equal >= 5
                else "PARTIAL"
            ),
            "storage_adjacent_runtime_calls": (
                "CONFIRMED_PROXIMITY_WITH_OPEN_FUNCTION_SEMANTICS"
                if storage_adjacent_call_pairs
                else "NOT_DETECTED"
            ),
            "navigation_to_optical_direct_edge": "NOT_CONFIRMED",
            "map_media_schema": "OPEN",
            "sector_read_contract": "OPEN",
        },
        "interpretation": (
            "Two code-coupled navigation-data call-site windows and multiple relocated "
            "optical-service record neighborhoods are stable across releases. The "
            "evidence does not establish a direct call from navigation to the optical "
            "manager, a sector-read ABI or the map-media schema."
        ),
        "publication_safety": copy.deepcopy(left["publication_safety"]),
    }


def update_operational_graph_v3(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    """Add Session 010 evidence without closing the map-media gaps."""

    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v3"
    graph["nodes"].extend(
        (
            {
                "id": "navigation-data-lifecycle",
                "label": "Bounded navigation-data call-site routine pair",
                "status": "CONFIRMED_CROSS_VERSION_CODE_COUPLING",
                "function_semantics": "OPEN",
                "evidence": ["S010-01", "RQ-025"],
            },
            {
                "id": "route-data-records",
                "label": "Relocated route-data record neighborhoods",
                "status": "CONFIRMED_RELOCATED_STRUCTURE",
                "consumer_status": "OPEN",
                "evidence": ["S010-02", "RQ-027"],
            },
            {
                "id": "optical-service-events",
                "label": "Relocated CD-ROM event/task record family",
                "status": "CONFIRMED_RELOCATED_STRUCTURE",
                "dispatch_semantics": "OPEN",
                "evidence": ["S010-03", "RQ-026"],
            },
        )
    )
    graph["edges"].extend(
        (
            {
                "source": "navigation-runtime",
                "target": "navigation-data-lifecycle",
                "relation": "contains two bounded code-coupled call-site windows",
                "status": "CONFIRMED_CROSS_VERSION",
            },
            {
                "source": "startup-runtime",
                "target": "route-data-records",
                "relation": "embeds relocated route-data constants and address neighborhoods",
                "status": "CONFIRMED_IMAGE_INTEGRATION",
            },
            {
                "source": "startup-runtime",
                "target": "optical-service-events",
                "relation": "embeds relocated CD-ROM event and task record neighborhoods",
                "status": "CONFIRMED_IMAGE_INTEGRATION",
            },
            {
                "source": "optical-service-events",
                "target": "optical-volume-reader",
                "relation": "likely participates in optical service dispatch",
                "status": "PROBABLE",
            },
            {
                "source": "route-data-records",
                "target": "navigation-data-lifecycle",
                "relation": "consumer relationship is unresolved",
                "status": "HYPOTHESIS",
            },
        )
    )
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED") for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        node["status"] == "PROBABLE" for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(node["status"] == "OPEN" for node in graph["nodes"])
    graph["interpretation"] = (
        "Session 010 adds stable navigation-data call-site and optical-service record "
        "contracts. Indirect dispatch, route-data consumers, sector ABI and map schema "
        "remain explicit gaps."
    )
    return graph


def build_public_navigation_dataflow_report(
    report: dict[str, object]
) -> dict[str, object]:
    """Remove private correlation keys from the per-image report."""

    public = copy.deepcopy(report)
    public["artifact"].pop("source_member_path", None)
    public["anchor_hits"] = [
        {key: value for key, value in hit.items() if not key.startswith("_internal_")}
        for hit in report["anchor_hits"]
    ]
    return public

"""Navigation and persistent-storage boundary analysis.

The module performs static, read-only correlation of a fixed marker vocabulary,
validated filesystem signatures and bounded SuperH literal references.  It
never publishes arbitrary firmware strings and deliberately separates the
presence of runtime support code from the format of any external map medium.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
from dataclasses import dataclass
import hashlib
import re

from .binary import BinaryReader
from .strings import StringRecord, extract_strings
from .superh import find_pc_relative_referrers


RUNTIME_BASE = 0x0C000000


@dataclass(frozen=True)
class BoundaryMarker:
    """One predeclared marker used for publication-safe classification."""

    marker_id: str
    category: str
    expression: str


MARKERS = (
    BoundaryMarker("navigation", "navigation", r"navi(?:gation)?"),
    BoundaryMarker("gps", "navigation", r"(?<![a-z])gps(?![a-z])"),
    BoundaryMarker("route", "navigation", r"route"),
    BoundaryMarker("destination", "navigation", r"destination"),
    BoundaryMarker("guidance", "navigation", r"guidance"),
    BoundaryMarker("map", "navigation", r"(?<!bit)map"),
    BoundaryMarker("position", "navigation", r"position"),
    BoundaryMarker("waypoint", "navigation", r"waypoint"),
    BoundaryMarker("street", "navigation", r"street"),
    BoundaryMarker("poi", "navigation", r"(?<![a-z])poi(?![a-z])"),
    BoundaryMarker("navigation-internal-data", "navigation", r"navigation internal data"),
    BoundaryMarker("routeact-dat", "navigation", r"routeact\.dat"),
    BoundaryMarker("cdrom", "storage", r"cdrom"),
    BoundaryMarker("dvd", "storage", r"(?<![a-z])dvd(?![a-z])"),
    BoundaryMarker("dosfs", "storage", r"dosfs"),
    BoundaryMarker("filesystem", "storage", r"file\s*system"),
    BoundaryMarker("mount", "storage", r"mount"),
    BoundaryMarker("sector", "storage", r"sector"),
    BoundaryMarker("volume", "storage", r"volume"),
    BoundaryMarker("directory", "storage", r"directory"),
    BoundaryMarker("tffs", "storage", r"tffs"),
    BoundaryMarker("cbio", "storage", r"cbio"),
    BoundaryMarker("blk-dev", "storage", r"blk_dev"),
    BoundaryMarker("fat12", "storage", r"fat12"),
    BoundaryMarker("fat16", "storage", r"fat16"),
    BoundaryMarker("fat32", "storage", r"fat32"),
    BoundaryMarker("cd001", "storage", r"cd001"),
)

_COMPILED_MARKERS = tuple(
    (marker, re.compile(marker.expression, re.IGNORECASE)) for marker in MARKERS
)


def _record_key(record: StringRecord) -> str:
    material = f"{record.encoding}\0{record.text}".encode("utf-8", "surrogatepass")
    return hashlib.sha256(material).hexdigest()


def discover_boundary_markers(records: list[StringRecord]) -> list[dict[str, object]]:
    """Classify records using only the fixed marker vocabulary.

    Returned records intentionally contain marker identifiers and a private
    correlation key, not the source text.  The key is removed from public
    reports.
    """

    hits: list[dict[str, object]] = []
    for record in records:
        marker_ids = []
        categories = set()
        for marker, pattern in _COMPILED_MARKERS:
            if pattern.search(record.text):
                marker_ids.append(marker.marker_id)
                categories.add(marker.category)
        if not marker_ids:
            continue
        hits.append(
            {
                "offset": record.offset,
                "record_length": len(record.text),
                "encoding": record.encoding,
                "markers": sorted(marker_ids),
                "categories": sorted(categories),
                "_internal_record_key": _record_key(record),
            }
        )
    return hits


def _summarize_clusters(
    hits: list[dict[str, object]], *, maximum_gap: int = 0x4000
) -> list[dict[str, object]]:
    if maximum_gap <= 0:
        raise ValueError("maximum_gap must be positive")
    clusters: list[list[dict[str, object]]] = []
    for hit in sorted(hits, key=lambda item: int(item["offset"])):
        if (
            not clusters
            or int(hit["offset"]) - int(clusters[-1][-1]["offset"]) > maximum_gap
        ):
            clusters.append([hit])
        else:
            clusters[-1].append(hit)

    summaries = []
    for cluster in clusters:
        if len(cluster) < 3:
            continue
        marker_counts = Counter(
            str(marker) for hit in cluster for marker in hit["markers"]
        )
        category_counts = Counter(
            str(category) for hit in cluster for category in hit["categories"]
        )
        start = int(cluster[0]["offset"])
        end = max(
            int(hit["offset"]) + int(hit["record_length"]) for hit in cluster
        )
        summaries.append(
            {
                "start": start,
                "end": end,
                "span": end - start,
                "record_count": len(cluster),
                "marker_counts": dict(sorted(marker_counts.items())),
                "category_counts": dict(sorted(category_counts.items())),
                "raw_strings_included": False,
            }
        )
    return summaries


def scan_marker_references(
    reader: BinaryReader,
    hits: list[dict[str, object]],
    *,
    runtime_base: int = RUNTIME_BASE,
) -> dict[str, object]:
    """Find aligned runtime-address words and bounded SH MOV.L users."""

    data = reader.read(0, reader.size)
    targets = {int(hit["offset"]): hit for hit in hits}
    edges = []
    for source_offset in range(0, len(data) - 3, 4):
        value = int.from_bytes(data[source_offset : source_offset + 4], "big")
        target_offset = value - runtime_base
        hit = targets.get(target_offset)
        if hit is None:
            continue
        referrers = find_pc_relative_referrers(reader, source_offset)
        edges.append(
            {
                "literal_word_offset": source_offset,
                "target_record_offset": target_offset,
                "markers": list(hit["markers"]),
                "categories": list(hit["categories"]),
                "pc_relative_mov_l_referrer_offsets": [
                    instruction.offset for instruction in referrers
                ],
            }
        )

    marker_pointer_counts = Counter(
        str(marker) for edge in edges for marker in edge["markers"]
    )
    marker_referrer_counts = Counter()
    category_referrer_counts = Counter()
    for edge in edges:
        count = len(edge["pc_relative_mov_l_referrer_offsets"])
        for marker in edge["markers"]:
            marker_referrer_counts[str(marker)] += count
        for category in edge["categories"]:
            category_referrer_counts[str(category)] += count
    return {
        "runtime_model": {
            "base": runtime_base,
            "status": "REUSED_CONFIRMED_SESSION006_MODEL",
        },
        "exact_runtime_word_count": len(edges),
        "referenced_target_record_count": len(
            {int(edge["target_record_offset"]) for edge in edges}
        ),
        "pc_relative_mov_l_referrer_count": sum(
            len(edge["pc_relative_mov_l_referrer_offsets"]) for edge in edges
        ),
        "marker_pointer_counts": dict(sorted(marker_pointer_counts.items())),
        "marker_referrer_counts": dict(sorted(marker_referrer_counts.items())),
        "category_referrer_counts": dict(sorted(category_referrer_counts.items())),
        "edges": edges,
        "raw_runtime_addresses_included": False,
        "raw_strings_included": False,
    }


def _valid_fat_boot_sector(data: bytes, start: int, fat_type: str) -> bool:
    if start < 0 or start + 512 > len(data):
        return False
    sector = data[start : start + 512]
    valid_jump = (sector[0] == 0xEB and sector[2] == 0x90) or sector[0] == 0xE9
    bytes_per_sector = int.from_bytes(sector[11:13], "little")
    sectors_per_cluster = sector[13]
    reserved_sectors = int.from_bytes(sector[14:16], "little")
    fat_copies = sector[16]
    signature_offset = 82 if fat_type == "FAT32" else 54
    return bool(
        valid_jump
        and bytes_per_sector in {512, 1024, 2048, 4096}
        and sectors_per_cluster in {1, 2, 4, 8, 16, 32, 64, 128}
        and reserved_sectors > 0
        and 1 <= fat_copies <= 4
        and sector[signature_offset : signature_offset + len(fat_type)]
        == fat_type.encode("ascii")
        and sector[510:512] == b"\x55\xAA"
    )


def scan_storage_signatures(reader: BinaryReader) -> dict[str, object]:
    """Validate ISO-9660 and FAT structures, not just their marker bytes."""

    data = reader.read(0, reader.size)
    cd001_offsets = reader.find_all(b"CD001")
    valid_iso_descriptors = []
    for offset in cd001_offsets:
        if offset < 1 or offset + 5 >= len(data):
            continue
        descriptor_type = data[offset - 1]
        descriptor_version = data[offset + 5]
        if descriptor_type in {0, 1, 2, 3, 255} and descriptor_version == 1:
            valid_iso_descriptors.append(offset - 1)

    fat_marker_counts: dict[str, int] = {}
    valid_fat_starts = set()
    for fat_type, signature_offset in (("FAT12", 54), ("FAT16", 54), ("FAT32", 82)):
        occurrences = reader.find_all(fat_type.encode("ascii"))
        fat_marker_counts[fat_type.lower()] = len(occurrences)
        for occurrence in occurrences:
            start = occurrence - signature_offset
            if _valid_fat_boot_sector(data, start, fat_type):
                valid_fat_starts.add(start)

    udf_counts = {
        marker.decode("ascii").lower(): len(reader.find_all(marker))
        for marker in (b"BEA01", b"NSR02", b"NSR03", b"TEA01")
    }
    return {
        "iso9660": {
            "standard_identifier_occurrence_count": len(cd001_offsets),
            "standard_identifier_offsets": cd001_offsets,
            "validated_volume_descriptor_count": len(valid_iso_descriptors),
            "validated_volume_descriptor_offsets": valid_iso_descriptors,
            "status": (
                "VALIDATED_EMBEDDED_VOLUME_DESCRIPTOR"
                if valid_iso_descriptors
                else "IDENTIFIER_CONSTANT_ONLY"
            ),
        },
        "fat": {
            "type_marker_counts": fat_marker_counts,
            "validated_boot_sector_count": len(valid_fat_starts),
            "validated_boot_sector_offsets": sorted(valid_fat_starts),
            "status": (
                "VALIDATED_EMBEDDED_FAT_VOLUME"
                if valid_fat_starts
                else "RUNTIME_MARKERS_WITHOUT_EMBEDDED_VOLUME"
            ),
        },
        "udf": {
            "descriptor_marker_counts": udf_counts,
            "descriptor_marker_total": sum(udf_counts.values()),
            "status": "MARKERS_PRESENT" if any(udf_counts.values()) else "NOT_DETECTED",
        },
        "raw_filesystem_payload_included": False,
    }


def analyze_navigation_storage_boundary(
    reader: BinaryReader,
    *,
    min_string_length: int = 5,
    cluster_gap: int = 0x4000,
) -> dict[str, object]:
    """Analyze one principal image without executing or modifying it."""

    records = extract_strings(reader, min_length=min_string_length)
    hits = discover_boundary_markers(records)
    marker_counts = Counter(str(marker) for hit in hits for marker in hit["markers"])
    category_counts = Counter(
        str(category) for hit in hits for category in hit["categories"]
    )
    references = scan_marker_references(reader, hits)
    signatures = scan_storage_signatures(reader)
    required_storage_markers = {"dosfs", "tffs", "fat12", "fat16", "fat32"}
    storage_stack_confirmed = required_storage_markers.issubset(marker_counts)
    navigation_referrers = int(
        references["category_referrer_counts"].get("navigation", 0)
    )
    navigation_family_count = sum(
        marker_counts.get(marker, 0)
        for marker in ("navigation", "gps", "route", "destination", "guidance")
    )
    return {
        "schema": "phoenix-mmi.navigation-storage-boundary/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "filename": reader.path.name,
            "sha256": reader.sha256(),
            "size_bytes": reader.size,
        },
        "marker_vocabulary": [
            {"id": marker.marker_id, "category": marker.category} for marker in MARKERS
        ],
        "marker_inventory": {
            "printable_record_count": len(records),
            "matched_record_count": len(hits),
            "marker_counts": dict(sorted(marker_counts.items())),
            "category_counts": dict(sorted(category_counts.items())),
            "cluster_gap": cluster_gap,
            "candidate_clusters": _summarize_clusters(hits, maximum_gap=cluster_gap),
            "raw_strings_included": False,
        },
        "marker_hits": hits,
        "references": references,
        "storage_signature_validation": signatures,
        "classification": {
            "navigation_subsystem_presence": (
                "CONFIRMED_EMBEDDED_NAVIGATION_SUBSYSTEM_EVIDENCE"
                if navigation_family_count >= 20 and navigation_referrers > 0
                else "PARTIAL"
            ),
            "navigation_region_boundary": "PARTIAL_MULTIPLE_MARKER_CLUSTERS",
            "runtime_storage_stack": (
                "CONFIRMED_VXWORKS_DOSFS_FAT_TFFS_SUPPORT"
                if storage_stack_confirmed
                else "PARTIAL"
            ),
            "principal_image_embedded_filesystem": (
                "VALIDATED"
                if signatures["iso9660"]["validated_volume_descriptor_count"]
                or signatures["fat"]["validated_boot_sector_count"]
                else "NOT_FOUND_UNDER_TESTED_ISO9660_FAT_VALIDATORS"
            ),
            "map_media_format": "OPEN",
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_strings_included": False,
            "map_payload_included": False,
            "filesystem_payload_included": False,
            "raw_runtime_addresses_included": False,
        },
    }


def _reference_targets(report: dict[str, object]) -> set[int]:
    return {
        int(edge["target_record_offset"])
        for edge in report["references"]["edges"]
        if edge["pc_relative_mov_l_referrer_offsets"]
    }


def _build_relocation_bands(
    left: dict[str, object],
    right: dict[str, object],
    *,
    maximum_gap: int = 0x4000,
) -> list[dict[str, object]]:
    left_by_key: dict[str, list[dict[str, object]]] = defaultdict(list)
    right_by_key: dict[str, list[dict[str, object]]] = defaultdict(list)
    for hit in left["marker_hits"]:
        left_by_key[str(hit["_internal_record_key"])].append(hit)
    for hit in right["marker_hits"]:
        right_by_key[str(hit["_internal_record_key"])].append(hit)

    pairs = []
    for key in left_by_key.keys() & right_by_key.keys():
        if len(left_by_key[key]) != 1 or len(right_by_key[key]) != 1:
            continue
        pairs.append((left_by_key[key][0], right_by_key[key][0]))
    pairs.sort(key=lambda pair: int(pair[0]["offset"]))

    groups: list[list[tuple[dict[str, object], dict[str, object]]]] = []
    for pair in pairs:
        if not groups:
            groups.append([pair])
            continue
        previous_left, previous_right = groups[-1][-1]
        left_gap = int(pair[0]["offset"]) - int(previous_left["offset"])
        right_gap = int(pair[1]["offset"]) - int(previous_right["offset"])
        if 0 <= left_gap <= maximum_gap and 0 <= right_gap <= maximum_gap:
            groups[-1].append(pair)
        else:
            groups.append([pair])

    left_referenced = _reference_targets(left)
    right_referenced = _reference_targets(right)
    bands = []
    for group in groups:
        if len(group) < 3:
            continue
        marker_counts = Counter(
            str(marker) for pair in group for marker in pair[0]["markers"]
        )
        category_counts = Counter(
            str(category) for pair in group for category in pair[0]["categories"]
        )
        deltas = [
            int(right_hit["offset"]) - int(left_hit["offset"])
            for left_hit, right_hit in group
        ]
        left_start = int(group[0][0]["offset"])
        left_end = max(
            int(left_hit["offset"]) + int(left_hit["record_length"])
            for left_hit, _ in group
        )
        right_start = int(group[0][1]["offset"])
        right_end = max(
            int(right_hit["offset"]) + int(right_hit["record_length"])
            for _, right_hit in group
        )
        navigation = category_counts.get("navigation", 0)
        storage = category_counts.get("storage", 0)
        if navigation > storage * 2:
            domain = "navigation"
        elif storage > navigation * 2:
            domain = "storage"
        else:
            domain = "mixed-navigation-storage"
        bands.append(
            {
                "left_start": left_start,
                "left_end": left_end,
                "right_start": right_start,
                "right_end": right_end,
                "pair_count": len(group),
                "marker_counts": dict(sorted(marker_counts.items())),
                "category_counts": dict(sorted(category_counts.items())),
                "dominant_domain": domain,
                "minimum_relocation_delta": min(deltas),
                "maximum_relocation_delta": max(deltas),
                "constant_relocation_delta": len(set(deltas)) == 1,
                "dual_release_code_referenced_pair_count": sum(
                    int(left_hit["offset"]) in left_referenced
                    and int(right_hit["offset"]) in right_referenced
                    for left_hit, right_hit in group
                ),
                "structural_status": "CONFIRMED_ORDERED_CROSS_VERSION_MARKER_BAND",
                "semantic_status": f"PROBABLE_{domain.upper().replace('-', '_')}_REGION",
                "raw_strings_included": False,
            }
        )
    return bands


def compare_navigation_storage_boundaries(
    left: dict[str, object],
    right: dict[str, object],
    *,
    band_gap: int = 0x4000,
) -> dict[str, object]:
    """Compare two releases while retaining semantic uncertainty."""

    bands = _build_relocation_bands(left, right, maximum_gap=band_gap)
    navigation_bands = [
        band
        for band in bands
        if band["dominant_domain"] == "navigation" and int(band["pair_count"]) >= 4
    ]
    storage_bands = [
        band
        for band in bands
        if band["dominant_domain"] == "storage" and int(band["pair_count"]) >= 4
    ]
    left_navigation_refs = int(
        left["references"]["category_referrer_counts"].get("navigation", 0)
    )
    right_navigation_refs = int(
        right["references"]["category_referrer_counts"].get("navigation", 0)
    )
    left_storage_refs = int(
        left["references"]["category_referrer_counts"].get("storage", 0)
    )
    right_storage_refs = int(
        right["references"]["category_referrer_counts"].get("storage", 0)
    )
    navigation_confirmed = bool(
        navigation_bands
        and left_navigation_refs
        and right_navigation_refs
        and all(
            report["classification"]["navigation_subsystem_presence"].startswith(
                "CONFIRMED"
            )
            for report in (left, right)
        )
    )
    storage_confirmed = bool(
        storage_bands
        and left_storage_refs
        and right_storage_refs
        and all(
            report["classification"]["runtime_storage_stack"].startswith("CONFIRMED")
            for report in (left, right)
        )
    )
    no_embedded_volume = all(
        report["storage_signature_validation"]["iso9660"][
            "validated_volume_descriptor_count"
        ]
        == 0
        and report["storage_signature_validation"]["fat"][
            "validated_boot_sector_count"
        ]
        == 0
        for report in (left, right)
    )
    iso_reader_markers_both = all(
        report["storage_signature_validation"]["iso9660"][
            "standard_identifier_occurrence_count"
        ]
        > 0
        and report["marker_inventory"]["marker_counts"].get("cdrom", 0) > 0
        for report in (left, right)
    )
    return {
        "schema": "phoenix-mmi.navigation-storage-boundary-comparison/v1",
        "analysis_mode": "read-only-static",
        "left": left["artifact"].get("label", left["artifact"]["filename"]),
        "right": right["artifact"].get("label", right["artifact"]["filename"]),
        "band_gap": band_gap,
        "relocation_bands": bands,
        "relocation_band_count": len(bands),
        "constant_delta_band_count": sum(
            bool(band["constant_relocation_delta"]) for band in bands
        ),
        "navigation": {
            "cross_version_band_count": len(navigation_bands),
            "left_pc_relative_referrer_count": left_navigation_refs,
            "right_pc_relative_referrer_count": right_navigation_refs,
            "subsystem_presence": (
                "CONFIRMED_CROSS_VERSION_NAVIGATION_SUBSYSTEM_EVIDENCE"
                if navigation_confirmed
                else "PARTIAL"
            ),
            "region_boundary": "PARTIAL_MULTIPLE_RELOCATED_MARKER_BANDS",
            "map_format": "OPEN",
        },
        "storage": {
            "cross_version_band_count": len(storage_bands),
            "left_pc_relative_referrer_count": left_storage_refs,
            "right_pc_relative_referrer_count": right_storage_refs,
            "runtime_stack": (
                "CONFIRMED_CROSS_VERSION_STORAGE_RUNTIME_EVIDENCE"
                if storage_confirmed
                else "PARTIAL"
            ),
            "iso9660_reader_support": (
                "PROBABLE_IDENTIFIER_CONSTANT_AND_CDROM_RUNTIME_MARKERS"
                if iso_reader_markers_both
                else "NOT_CONFIRMED"
            ),
            "principal_image_embedded_volume": (
                "NOT_FOUND_UNDER_TESTED_ISO9660_FAT_VALIDATORS"
                if no_embedded_volume
                else "VALIDATED"
            ),
            "backing_device_and_volume_layout": "OPEN",
        },
        "interpretation": (
            "The principal image contains code-coupled navigation evidence and a VxWorks "
            "storage stack in both releases. Ordered marker bands are structural boundaries, "
            "not proof of one monolithic navigation module or of the map-disc data format."
        ),
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_strings_included": False,
            "map_payload_included": False,
            "filesystem_payload_included": False,
            "raw_runtime_addresses_included": False,
        },
    }


def update_operational_graph(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    """Refine Session 008 OPEN nodes without erasing remaining gaps."""

    graph = copy.deepcopy(prior_graph)
    nodes = graph["nodes"]
    navigation = next(node for node in nodes if node["id"] == "navigation-runtime")
    navigation.update(
        {
            "label": "Embedded navigation subsystem; multi-band boundary",
            "status": "CONFIRMED_SUBSYSTEM_PRESENCE",
            "boundary_status": comparison["navigation"]["region_boundary"],
            "map_format_status": comparison["navigation"]["map_format"],
            "evidence": ["RQ-009", "S009-01", "S009-02"],
        }
    )
    internal = next(node for node in nodes if node["id"] == "internal-filesystem")
    internal.update(
        {
            "label": "Internal backing volume and object layout",
            "status": "OPEN",
            "tested_embedded_volume_status": comparison["storage"][
                "principal_image_embedded_volume"
            ],
            "evidence": ["RQ-010", "S009-04"],
        }
    )
    nodes.extend(
        (
            {
                "id": "runtime-storage-stack",
                "label": "VxWorks dosFs/FAT/TFFS runtime support",
                "status": "CONFIRMED_BOUNDED",
                "evidence": ["S009-03", "S009-04"],
            },
            {
                "id": "optical-volume-reader",
                "label": "CD-ROM / ISO-9660 reader support",
                "status": "PROBABLE",
                "evidence": ["S009-03"],
            },
            {
                "id": "map-media-format",
                "label": "Navigation map-media schema and compatibility boundary",
                "status": "OPEN",
                "evidence": ["RQ-022"],
            },
        )
    )

    edges = graph["edges"]
    for edge in edges:
        if edge["source"] == "startup-runtime" and edge["target"] == "navigation-runtime":
            edge.update(
                {
                    "relation": "contains code-coupled navigation marker families",
                    "status": "CONFIRMED_IMAGE_INTEGRATION",
                }
            )
        if edge["source"] == "startup-runtime" and edge["target"] == "internal-filesystem":
            edge.update(
                {
                    "relation": "requires a backing volume whose layout remains unresolved",
                    "status": "HYPOTHESIS",
                }
            )
    edges.extend(
        (
            {
                "source": "startup-runtime",
                "target": "runtime-storage-stack",
                "relation": "embeds code-coupled dosFs/FAT/TFFS support",
                "status": "CONFIRMED_BOUNDED",
            },
            {
                "source": "runtime-storage-stack",
                "target": "internal-filesystem",
                "relation": "mounts an unresolved flash or block-device volume",
                "status": "PROBABLE",
            },
            {
                "source": "runtime-storage-stack",
                "target": "optical-volume-reader",
                "relation": "provides block and filesystem services",
                "status": "PROBABLE",
            },
            {
                "source": "optical-volume-reader",
                "target": "map-media-format",
                "relation": "may expose external navigation data",
                "status": "HYPOTHESIS",
            },
            {
                "source": "map-media-format",
                "target": "navigation-runtime",
                "relation": "supplies map and routing data",
                "status": "HYPOTHESIS",
            },
        )
    )
    graph["schema"] = "phoenix-mmi.operational-graph/v2"
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED") for node in nodes
    )
    graph["probable_node_count"] = sum(node["status"] == "PROBABLE" for node in nodes)
    graph["open_node_count"] = sum(node["status"] == "OPEN" for node in nodes)
    graph["interpretation"] = (
        "Session 009 confirms subsystem presence and the runtime storage stack, while "
        "keeping exact navigation boundaries, backing-volume layout and map format open."
    )
    return graph


def build_public_navigation_storage_report(report: dict[str, object]) -> dict[str, object]:
    """Return aggregate evidence without private record-correlation keys."""

    return {
        "schema": report["schema"],
        "analysis_mode": report["analysis_mode"],
        "artifact": copy.deepcopy(report["artifact"]),
        "marker_vocabulary": copy.deepcopy(report["marker_vocabulary"]),
        "marker_inventory": copy.deepcopy(report["marker_inventory"]),
        "references": copy.deepcopy(report["references"]),
        "storage_signature_validation": copy.deepcopy(
            report["storage_signature_validation"]
        ),
        "classification": copy.deepcopy(report["classification"]),
        "publication_safety": copy.deepcopy(report["publication_safety"]),
    }

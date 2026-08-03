"""Evidence-graded operational model for the MMI principal image.

The module combines prior confirmed observations with a bounded differential
analysis of a relocated sparse-row bitmap region.  Structural classification
and semantic interpretation are deliberately separate.
"""

from __future__ import annotations

from collections import Counter
import copy
import hashlib
from statistics import median

from .binary import BinaryReader


RUNTIME_BASE = 0x0C000000


def _flow_control_halfword(word: int) -> bool:
    return bool(
        word in (0x000B, 0x002B)
        or word & 0xF000 in (0xA000, 0xB000)
        or word & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00)
        or word & 0xF0FF in (0x400B, 0x402B)
    )


def _nonzero_row_runs(data: bytes) -> list[int]:
    runs: list[int] = []
    start: int | None = None
    for index, value in enumerate(data):
        if value and start is None:
            start = index
        elif not value and start is not None:
            runs.append(index - start)
            start = None
    if start is not None:
        runs.append(len(data) - start)
    return runs


def sparse_row_metrics(
    data: bytes,
    *,
    image_size: int,
    runtime_base: int = RUNTIME_BASE,
) -> dict[str, object]:
    """Measure whether bytes behave like one-byte-wide sparse bitmap rows."""

    if not data:
        raise ValueError("sparse-row metrics require at least one byte")
    runs = _nonzero_row_runs(data)
    pointer_count = sum(
        runtime_base
        <= int.from_bytes(data[offset : offset + 4], "big")
        < runtime_base + image_size
        for offset in range(0, len(data) - 3, 4)
    )
    flow_count = sum(
        _flow_control_halfword(int.from_bytes(data[offset : offset + 2], "big"))
        for offset in range(0, len(data) - 1, 2)
    )
    zero_ratio = data.count(0) / len(data)
    set_bit_density = sum(value.bit_count() for value in data) / (len(data) * 8)
    run_median = float(median(runs)) if runs else 0.0
    candidate = bool(
        zero_ratio >= 0.20
        and 0.05 <= set_bit_density <= 0.30
        and len(runs) >= 3
        and 2 <= run_median <= 12
        and flow_count == 0
        and pointer_count == 0
    )
    return {
        "length": len(data),
        "zero_byte_ratio": round(zero_ratio, 6),
        "set_bit_density": round(set_bit_density, 6),
        "nonzero_row_run_count": len(runs),
        "nonzero_row_run_height_median": run_median,
        "nonzero_row_run_height_histogram": {
            str(height): count for height, count in sorted(Counter(runs).items())
        },
        "aligned_runtime_pointer_count": pointer_count,
        "flow_control_halfword_count": flow_count,
        "sparse_row_bitmap_candidate": candidate,
        "raw_bytes_included": False,
    }


def scan_sparse_row_region(
    reader: BinaryReader,
    *,
    start: int,
    end: int,
    window_size: int = 64,
    runtime_base: int = RUNTIME_BASE,
) -> dict[str, object]:
    if not 0 <= start <= end <= reader.size:
        raise ValueError("region is outside the artifact")
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    data = reader.read(start, end - start)
    metrics = [
        sparse_row_metrics(
            data[offset : offset + window_size],
            image_size=reader.size,
            runtime_base=runtime_base,
        )
        for offset in range(0, len(data) - window_size + 1, window_size)
    ]
    candidate_count = sum(bool(item["sparse_row_bitmap_candidate"]) for item in metrics)
    return {
        "offset": start,
        "end": end,
        "length": end - start,
        "window_size": window_size,
        "complete_window_count": len(metrics),
        "candidate_window_count": candidate_count,
        "candidate_window_ratio": round(candidate_count / len(metrics), 6)
        if metrics
        else 0.0,
        "mean_zero_byte_ratio": round(
            sum(float(item["zero_byte_ratio"]) for item in metrics) / len(metrics), 6
        )
        if metrics
        else 0.0,
        "mean_set_bit_density": round(
            sum(float(item["set_bit_density"]) for item in metrics) / len(metrics), 6
        )
        if metrics
        else 0.0,
        "raw_bytes_included": False,
    }


def find_bounded_equal_relocated_region(
    left: BinaryReader,
    right: BinaryReader,
    *,
    left_anchor: int,
    right_anchor: int,
    max_backward: int = 0x20000,
    max_forward: int = 0x20000,
) -> dict[str, object]:
    """Find the maximal byte-equal extent around relocated anchors in a bound."""

    if not (0 <= left_anchor < left.size and 0 <= right_anchor < right.size):
        raise ValueError("anchor outside artifact")
    backward_limit = min(max_backward, left_anchor, right_anchor)
    forward_limit = min(
        max_forward, left.size - left_anchor, right.size - right_anchor
    )
    left_window = left.read(left_anchor - backward_limit, backward_limit + forward_limit)
    right_window = right.read(
        right_anchor - backward_limit, backward_limit + forward_limit
    )
    anchor_index = backward_limit
    backward = 0
    while (
        backward < backward_limit
        and left_window[anchor_index - backward - 1]
        == right_window[anchor_index - backward - 1]
    ):
        backward += 1
    forward = 0
    while (
        forward < forward_limit
        and left_window[anchor_index + forward]
        == right_window[anchor_index + forward]
    ):
        forward += 1
    left_start = left_anchor - backward
    right_start = right_anchor - backward
    region = left.read(left_start, backward + forward)
    return {
        "left_offset": left_start,
        "right_offset": right_start,
        "left_end": left_anchor + forward,
        "right_end": right_anchor + forward,
        "anchor_relative_start": -backward,
        "anchor_relative_end": forward,
        "length": backward + forward,
        "sha256": hashlib.sha256(region).hexdigest(),
        "byte_equal": region == right.read(right_start, backward + forward),
        "backward_bound_reached": backward == backward_limit,
        "forward_bound_reached": forward == forward_limit,
        "raw_bytes_included": False,
    }


def _control_regions(
    reader: BinaryReader, *, atlas_start: int, length: int
) -> list[dict[str, int | str]]:
    controls: list[dict[str, int | str]] = []
    if length <= reader.size:
        controls.append({"name": "image-start-control", "start": 0, "end": length})
    if atlas_start >= length:
        controls.append(
            {
                "name": "immediately-preceding-control",
                "start": atlas_start - length,
                "end": atlas_start,
            }
        )
    midpoint_start = max(0, min(reader.size - length, reader.size // 2 - length // 2))
    if midpoint_start + length <= reader.size:
        controls.append(
            {
                "name": "image-midpoint-control",
                "start": midpoint_start,
                "end": midpoint_start + length,
            }
        )
    return controls


def analyze_relocated_bitmap_atlas(
    left: BinaryReader,
    right: BinaryReader,
    *,
    left_block_offset: int,
    right_block_offset: int,
    descriptor_fields: list[dict[str, object]],
    target_window_size: int = 64,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Analyze a relocated equal region and descriptor-selected target windows."""

    extent = find_bounded_equal_relocated_region(
        left,
        right,
        left_anchor=left_block_offset,
        right_anchor=right_block_offset,
    )
    if not extent["byte_equal"]:
        raise ValueError("relocated extent is not byte-equal")
    reports = []
    for reader, block_offset, side in (
        (left, left_block_offset, "left"),
        (right, right_block_offset, "right"),
    ):
        start = int(extent[f"{side}_offset"])
        end = int(extent[f"{side}_end"])
        atlas_scan = scan_sparse_row_region(reader, start=start, end=end)
        controls = [
            {
                "name": control["name"],
                "scan": scan_sparse_row_region(
                    reader,
                    start=int(control["start"]),
                    end=int(control["end"]),
                ),
            }
            for control in _control_regions(reader, atlas_start=start, length=end - start)
        ]
        block_metrics = sparse_row_metrics(
            reader.read(block_offset, 256), image_size=reader.size
        )
        targets = []
        for field in descriptor_fields:
            delta = int(field["target_delta_from_block"])
            target = block_offset + delta
            if not start <= target < end or target + target_window_size > reader.size:
                targets.append(
                    {
                        "field_relative_offset": int(field["field_relative_offset"]),
                        "target_delta_from_block": delta,
                        "inside_equal_region": False,
                    }
                )
                continue
            targets.append(
                {
                    "field_relative_offset": int(field["field_relative_offset"]),
                    "target_delta_from_block": delta,
                    "inside_equal_region": True,
                    "metrics": sparse_row_metrics(
                        reader.read(target, target_window_size), image_size=reader.size
                    ),
                }
            )
        reports.append(
            {
                "artifact": {
                    "filename": reader.path.name,
                    "sha256": reader.sha256(),
                    "size_bytes": reader.size,
                },
                "equal_region": {
                    "offset": start,
                    "end": end,
                    "length": end - start,
                    "sha256": extent["sha256"],
                },
                "sparse_row_scan": atlas_scan,
                "control_scans": controls,
                "record_block_metrics": block_metrics,
                "descriptor_target_windows": targets,
            }
        )

    target_pairs = list(
        zip(
            reports[0]["descriptor_target_windows"],
            reports[1]["descriptor_target_windows"],
        )
    )
    exact_target_count = 0
    bitmap_target_count = 0
    for left_target, right_target in target_pairs:
        if not left_target.get("inside_equal_region") or not right_target.get(
            "inside_equal_region"
        ):
            continue
        left_target_offset = left_block_offset + int(left_target["target_delta_from_block"])
        right_target_offset = right_block_offset + int(
            right_target["target_delta_from_block"]
        )
        if left.read(left_target_offset, target_window_size) == right.read(
            right_target_offset, target_window_size
        ):
            exact_target_count += 1
        if left_target["metrics"]["sparse_row_bitmap_candidate"] and right_target[
            "metrics"
        ]["sparse_row_bitmap_candidate"]:
            bitmap_target_count += 1

    control_rates = [
        float(control["scan"]["candidate_window_ratio"])
        for report in reports
        for control in report["control_scans"]
    ]
    atlas_rates = [
        float(report["sparse_row_scan"]["candidate_window_ratio"])
        for report in reports
    ]
    structural_confirmed = bool(
        extent["byte_equal"]
        and int(extent["length"]) >= 0x1000
        and min(atlas_rates) >= 0.50
        and max(control_rates, default=1.0) <= 0.10
        and exact_target_count == len(descriptor_fields)
        and bitmap_target_count == len(descriptor_fields)
    )
    comparison = {
        "schema": "phoenix-mmi.relocated-bitmap-atlas-comparison/v1",
        "analysis_mode": "read-only-static",
        "equal_region": extent,
        "descriptor_target_count": len(descriptor_fields),
        "exact_equal_target_window_count": exact_target_count,
        "sparse_row_bitmap_target_window_count": bitmap_target_count,
        "atlas_candidate_window_ratios": atlas_rates,
        "maximum_control_candidate_window_ratio": max(control_rates, default=0.0),
        "structural_status": (
            "CONFIRMED_RELOCATED_SPARSE_ROW_BITMAP_REGION"
            if structural_confirmed
            else "UNRESOLVED"
        ),
        "semantic_status": (
            "PROBABLE_1BPP_GLYPH_ATLAS" if structural_confirmed else "UNRESOLVED"
        ),
        "semantic_confirmation": False,
        "interpretation": (
            "Sparse one-byte row morphology and descriptor targeting support a glyph-atlas "
            "interpretation, but no decoded font header or renderer consumer is known."
        ),
        "publication_safety": {
            "firmware_bytes_included": False,
            "rendered_glyphs_included": False,
            "raw_strings_included": False,
            "raw_pointer_runs_included": False,
        },
    }
    return reports[0], reports[1], comparison


def build_operational_graph(
    *, atlas_comparison: dict[str, object]
) -> dict[str, object]:
    """Compose a conservative end-to-end firmware model from session evidence."""

    nodes = [
        {
            "id": "update-media",
            "label": "Three-disc multi-device update set",
            "status": "CONFIRMED",
            "evidence": ["S001", "S002"],
        },
        {
            "id": "metainfo-selector",
            "label": "METAINFO target selection and integrity metadata",
            "status": "CONFIRMED_STRUCTURE",
            "evidence": ["S002-01", "S002-02", "S002-03"],
        },
        {
            "id": "most-inventory",
            "label": "Installed MOST component discovery",
            "status": "PROBABLE",
            "evidence": ["S002-06"],
        },
        {
            "id": "peripheral-firmware",
            "label": "Separate amplifier, tuner, telephone, Bluetooth, AMI and DSP firmware",
            "status": "CONFIRMED_PACKAGE_TOPOLOGY",
            "evidence": ["S001", "S002"],
        },
        {
            "id": "most-transport",
            "label": "Head-unit control and update transport over MOST",
            "status": "PROBABLE",
            "evidence": ["S002-06", "S002-08"],
        },
        {
            "id": "principal-image",
            "label": "Flat big-endian SH-3 principal image",
            "status": "CONFIRMED",
            "evidence": ["S003", "S004-01"],
        },
        {
            "id": "startup-runtime",
            "label": "SH-3 startup and Wind River/VxWorks runtime fingerprint",
            "status": "CONFIRMED_BOUNDED",
            "evidence": ["S004-01", "S004-02", "S004-05"],
        },
        {
            "id": "runtime-address-space",
            "label": "Runtime-linked principal image at 0x0C000000",
            "status": "CONFIRMED_BOUNDED",
            "evidence": ["S006-01", "S006-02"],
        },
        {
            "id": "checksum-grid",
            "label": "Twenty-five sequential 512 KiB CRC32 integrity regions",
            "status": "CONFIRMED",
            "evidence": ["S003", "RQ-004"],
        },
        {
            "id": "bitmap-atlas",
            "label": "Relocated sparse-row bitmap region",
            "status": atlas_comparison["structural_status"],
            "semantic_status": atlas_comparison["semantic_status"],
            "evidence": ["S007-02", "S008-01", "S008-02"],
        },
        {
            "id": "browser-bundle",
            "label": "Embedded HTML and GIF/JPEG browser bundle",
            "status": "CONFIRMED",
            "evidence": ["S005"],
        },
        {
            "id": "post-cluster-table",
            "label": "Post-cluster runtime-address tables",
            "status": "CONFIRMED_STRUCTURE",
            "evidence": ["S005", "S006-03", "S007-01"],
        },
        {
            "id": "browser-renderer",
            "label": "Browser/UI renderer consuming the bitmap atlas",
            "status": "PROBABLE",
            "evidence": ["S007-03", "S007-05", "S008-03"],
        },
        {
            "id": "unresolved-runtime-tables",
            "label": "Post-cluster address runs 1 and 3",
            "status": "PARTIAL",
            "evidence": ["S006-05", "RQ-015"],
        },
        {
            "id": "eeprom-state",
            "label": "Versioned EEPROM migration state",
            "status": "CONFIRMED_CHAIN",
            "evidence": ["S002-05"],
        },
        {
            "id": "navigation-runtime",
            "label": "Navigation engine and map-format boundary",
            "status": "OPEN",
            "evidence": ["RQ-009"],
        },
        {
            "id": "internal-filesystem",
            "label": "Internal filesystem or proprietary object store",
            "status": "OPEN",
            "evidence": ["RQ-010"],
        },
    ]
    edges = [
        {
            "source": "update-media",
            "target": "metainfo-selector",
            "relation": "describes component payloads and policies",
            "status": "CONFIRMED",
        },
        {
            "source": "update-media",
            "target": "peripheral-firmware",
            "relation": "contains device-specific application and bootloader payloads",
            "status": "CONFIRMED_PACKAGE_TOPOLOGY",
        },
        {
            "source": "most-inventory",
            "target": "metainfo-selector",
            "relation": "provides target tuple for selection",
            "status": "PROBABLE",
        },
        {
            "source": "most-inventory",
            "target": "peripheral-firmware",
            "relation": "matches installed hardware to device-specific records",
            "status": "PROBABLE_RUNTIME_BEHAVIOR",
        },
        {
            "source": "metainfo-selector",
            "target": "principal-image",
            "relation": "selects, checks and stages the head-unit payload",
            "status": "PROBABLE_RUNTIME_BEHAVIOR",
        },
        {
            "source": "metainfo-selector",
            "target": "checksum-grid",
            "relation": "provides segmented integrity expectations",
            "status": "CONFIRMED_METADATA_RELATION",
        },
        {
            "source": "principal-image",
            "target": "startup-runtime",
            "relation": "begins execution at file offset zero",
            "status": "CONFIRMED",
        },
        {
            "source": "startup-runtime",
            "target": "runtime-address-space",
            "relation": "initializes the linked runtime image",
            "status": "PROBABLE",
        },
        {
            "source": "startup-runtime",
            "target": "most-transport",
            "relation": "hosts network-facing service tasks",
            "status": "PROBABLE",
        },
        {
            "source": "most-transport",
            "target": "peripheral-firmware",
            "relation": "coordinates device control and staged downloads",
            "status": "PROBABLE",
        },
        {
            "source": "browser-bundle",
            "target": "post-cluster-table",
            "relation": "is immediately followed by runtime-address tables",
            "status": "CONFIRMED_PHYSICAL_LAYOUT",
        },
        {
            "source": "post-cluster-table",
            "target": "bitmap-atlas",
            "relation": "contains two exact edges to the atlas block",
            "status": "CONFIRMED_STRUCTURE",
        },
        {
            "source": "post-cluster-table",
            "target": "unresolved-runtime-tables",
            "relation": "contains additional mapped but semantically unresolved runs",
            "status": "PARTIAL",
        },
        {
            "source": "bitmap-atlas",
            "target": "browser-renderer",
            "relation": "provides bitmap glyph data",
            "status": "PROBABLE",
        },
        {
            "source": "metainfo-selector",
            "target": "eeprom-state",
            "relation": "selects a version/CRC-specific migration",
            "status": "CONFIRMED_METADATA_CHAIN",
        },
        {
            "source": "startup-runtime",
            "target": "navigation-runtime",
            "relation": "hosts navigation services",
            "status": "HYPOTHESIS",
        },
        {
            "source": "startup-runtime",
            "target": "internal-filesystem",
            "relation": "loads persistent runtime objects",
            "status": "HYPOTHESIS",
        },
    ]
    return {
        "schema": "phoenix-mmi.operational-graph/v1",
        "nodes": nodes,
        "edges": edges,
        "confirmed_node_count": sum(
            str(node["status"]).startswith("CONFIRMED") for node in nodes
        ),
        "probable_node_count": sum(node["status"] == "PROBABLE" for node in nodes),
        "open_node_count": sum(node["status"] == "OPEN" for node in nodes),
        "interpretation": (
            "The graph is a confidence-graded working model. OPEN and HYPOTHESIS nodes "
            "are explicit gaps, not inferred implementation facts."
        ),
    }


def build_public_operational_report(report: dict[str, object]) -> dict[str, object]:
    public = copy.deepcopy(report)
    return public

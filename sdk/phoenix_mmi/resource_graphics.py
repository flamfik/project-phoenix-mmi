"""Neutral geometry, pixel-layout hypotheses and offline raster previews."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from .resource_catalog import ResourceCatalog, unique_decoded_records


MAX_PREVIEW_PIXELS = 4_194_304


@dataclass(frozen=True)
class PixelLayout:
    layout_id: str
    byte_order: str
    red_shift: int
    red_bits: int
    green_shift: int
    green_bits: int
    blue_shift: int
    blue_bits: int
    unused_mask: int


PIXEL_LAYOUTS = (
    PixelLayout("BGR565_BE", "big", 0, 5, 5, 6, 11, 5, 0),
    PixelLayout("BGR565_LE", "little", 0, 5, 5, 6, 11, 5, 0),
    PixelLayout("RGB565_BE", "big", 11, 5, 5, 6, 0, 5, 0),
    PixelLayout("RGB565_LE", "little", 11, 5, 5, 6, 0, 5, 0),
    PixelLayout("XBGR1555_BE", "big", 0, 5, 5, 5, 10, 5, 0x8000),
    PixelLayout("XBGR1555_LE", "little", 0, 5, 5, 5, 10, 5, 0x8000),
    PixelLayout("XRGB1555_BE", "big", 10, 5, 5, 5, 0, 5, 0x8000),
    PixelLayout("XRGB1555_LE", "little", 10, 5, 5, 5, 0, 5, 0x8000),
)
_LAYOUTS = {item.layout_id: item for item in PIXEL_LAYOUTS}


def geometry_class(width: int, height: int) -> str:
    """Assign a shape class without inferring a UI role."""

    if width <= 0 or height <= 0:
        raise ValueError("geometry must be positive")
    if width == 480 and height == 240:
        return "DISPLAY_SIZED_480X240"
    if width == 480:
        return "FULL_WIDTH_STRIP"
    if height >= width * 2:
        return "TALL_RECTANGLE"
    if width >= height * 2:
        return "WIDE_RECTANGLE"
    if max(width, height) <= 64:
        return "COMPACT_RECTANGLE"
    return "GENERAL_RECTANGLE"


def build_geometry_taxonomy(catalog: ResourceCatalog) -> dict[str, object]:
    records = unique_decoded_records(catalog)
    classes = Counter(geometry_class(item.width, item.height) for item in records)
    geometries = Counter((item.width, item.height) for item in records)
    return {
        "schema": "phoenix-mmi.resource-geometry-taxonomy/v1",
        "analysis_mode": "decoded-content-deduplicated-neutral-shape-classes",
        "unique_resource_count": len(records),
        "distinct_geometry_count": len(geometries),
        "class_counts": dict(sorted(classes.items())),
        "geometries": [
            {
                "width": width,
                "height": height,
                "resource_count": count,
                "shape_class": geometry_class(width, height),
            }
            for (width, height), count in sorted(geometries.items())
        ],
        "classification": {
            "geometry_contract": "CONFIRMED",
            "ui_semantic_roles": "NOT_ASSIGNED",
        },
        "publication_safety": {
            "decoded_raster_bytes_included": False,
            "content_hashes_included": False,
            "resource_names_included": False,
            "extracted_resources_included": False,
        },
    }


def _scale(value: int, bits: int) -> int:
    return (value * 255 + ((1 << bits) - 1) // 2) // ((1 << bits) - 1)


def decode_rgb16(raster: bytes, layout_id: str) -> bytes:
    if len(raster) % 2:
        raise ValueError("16-bit raster has an odd byte count")
    layout = _LAYOUTS.get(layout_id)
    if layout is None:
        raise ValueError(f"unknown pixel layout: {layout_id}")
    output = bytearray(len(raster) // 2 * 3)
    cursor = 0
    for offset in range(0, len(raster), 2):
        word = int.from_bytes(raster[offset : offset + 2], layout.byte_order)
        red = _scale(
            (word >> layout.red_shift) & ((1 << layout.red_bits) - 1),
            layout.red_bits,
        )
        green = _scale(
            (word >> layout.green_shift) & ((1 << layout.green_bits) - 1),
            layout.green_bits,
        )
        blue = _scale(
            (word >> layout.blue_shift) & ((1 << layout.blue_bits) - 1),
            layout.blue_bits,
        )
        output[cursor : cursor + 3] = bytes((red, green, blue))
        cursor += 3
    return bytes(output)


def _layout_metrics(
    raster: bytes, width: int, height: int, layout: PixelLayout
) -> dict[str, object]:
    if len(raster) != width * height * 2:
        raise ValueError("pixel-layout source geometry differs")
    rgb = decode_rgb16(raster, layout.layout_id)
    luminance = [
        (77 * rgb[index] + 150 * rgb[index + 1] + 29 * rgb[index + 2]) >> 8
        for index in range(0, len(rgb), 3)
    ]
    horizontal = sum(
        abs(luminance[row * width + column] - luminance[row * width + column - 1])
        for row in range(height)
        for column in range(1, width)
    )
    vertical = sum(
        abs(luminance[row * width + column] - luminance[(row - 1) * width + column])
        for row in range(1, height)
        for column in range(width)
    )
    edge_count = height * max(0, width - 1) + width * max(0, height - 1)
    words = [
        int.from_bytes(raster[index : index + 2], layout.byte_order)
        for index in range(0, len(raster), 2)
    ]
    unused_one_ratio = (
        sum(bool(word & layout.unused_mask) for word in words) / len(words)
        if layout.unused_mask
        else 0.0
    )
    colors = {
        rgb[index : index + 3] for index in range(0, len(rgb), 3)
    }
    return {
        "layout_id": layout.layout_id,
        "normalized_neighbor_variation": round(
            (horizontal + vertical) / max(1, edge_count * 255), 8
        ),
        "distinct_rgb_count": len(colors),
        "unused_bit_one_ratio": round(unused_one_ratio, 8),
    }


def evaluate_pixel_layouts(
    rasters: Iterable[tuple[str, bytes, int, int]],
) -> dict[str, object]:
    sources = list(rasters)
    if not sources:
        raise ValueError("pixel-layout evaluation requires at least one raster")
    rows = []
    for layout in PIXEL_LAYOUTS:
        metrics = [
            _layout_metrics(raster, width, height, layout)
            for _, raster, width, height in sources
        ]
        rows.append(
            {
                "layout_id": layout.layout_id,
                "source_count": len(metrics),
                "mean_neighbor_variation": round(
                    sum(
                        float(item["normalized_neighbor_variation"])
                        for item in metrics
                    )
                    / len(metrics),
                    8,
                ),
                "mean_unused_bit_one_ratio": round(
                    sum(float(item["unused_bit_one_ratio"]) for item in metrics)
                    / len(metrics),
                    8,
                ),
                "minimum_distinct_rgb_count": min(
                    int(item["distinct_rgb_count"]) for item in metrics
                ),
            }
        )
    ranked = sorted(
        rows, key=lambda item: (item["mean_neighbor_variation"], item["layout_id"])
    )
    return {
        "schema": "phoenix-mmi.pixel-layout-hypotheses/v1",
        "analysis_mode": "fixed-eight-layout-structural-metric-comparison",
        "source_count": len(sources),
        "candidate_count": len(rows),
        "candidates": sorted(rows, key=lambda item: str(item["layout_id"])),
        "smoothness_ranking": [
            str(item["layout_id"]) for item in ranked
        ],
        "classification": {
            "pixel_unit_width": "CONFIRMED_16_BIT",
            "pixel_layout": "NOT_ESTABLISHED",
            "ranking_interpretation": "HEURISTIC_ONLY",
        },
        "publication_safety": {
            "decoded_raster_bytes_included": False,
            "rendered_previews_included": False,
            "content_hashes_included": False,
        },
    }


def render_ppm(
    raster: bytes, width: int, height: int, layout_id: str
) -> bytes:
    if width <= 0 or height <= 0 or width * height > MAX_PREVIEW_PIXELS:
        raise ValueError("preview geometry exceeds safety bound")
    if len(raster) != width * height * 2:
        raise ValueError("preview raster geometry differs")
    rgb = decode_rgb16(raster, layout_id)
    return f"P6\n{width} {height}\n255\n".encode("ascii") + rgb


def build_candidate_previews(
    raster: bytes,
    width: int,
    height: int,
    *,
    layout_ids: tuple[str, ...] = (
        "RGB565_BE",
        "RGB565_LE",
        "XRGB1555_BE",
        "XRGB1555_LE",
    ),
) -> dict[str, bytes]:
    if len(layout_ids) != len(set(layout_ids)):
        raise ValueError("preview layout IDs must be unique")
    return {
        layout_id: render_ppm(raster, width, height, layout_id)
        for layout_id in sorted(layout_ids)
    }


def build_public_preview_summary(
    previews: dict[str, bytes], *, width: int, height: int
) -> dict[str, object]:
    if not previews:
        raise ValueError("preview summary requires at least one candidate")
    return {
        "schema": "phoenix-mmi.offline-preview-summary/v1",
        "analysis_mode": "private-format-explicit-candidate-rendering",
        "candidate_preview_count": len(previews),
        "candidate_layouts": sorted(previews),
        "width": width,
        "height": height,
        "aggregate_private_preview_bytes": sum(len(value) for value in previews.values()),
        "classification": {
            "offline_preview_pipeline": "CONFIRMED",
            "selected_pixel_layout": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "preview_files_committed": False,
            "preview_bytes_included": False,
            "decoded_raster_bytes_included": False,
            "source_content_hashes_included": False,
            "firmware_bytes_included": False,
        },
    }

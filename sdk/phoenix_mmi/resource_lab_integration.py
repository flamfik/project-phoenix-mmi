"""Deterministic synthetic integration gate for Milestone M3."""

from __future__ import annotations

import hashlib
import json

from .resource_catalog import (
    build_public_resource_catalog,
    build_resource_catalog,
    scan_embedded_xim2,
)
from .resource_graphics import (
    build_candidate_previews,
    build_geometry_taxonomy,
    build_public_preview_summary,
    evaluate_pixel_layouts,
)
from .resource_text import (
    build_font_catalog,
    build_language_topology,
    build_resource_relationship_graph,
    build_text_catalog,
)
from .yim import decode_yim_rle


class MemoryReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.size = len(data)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size:
            raise ValueError("memory-reader bounds differ")
        return self._data[offset : offset + length]

    def find_all(
        self,
        needle: bytes,
        *,
        chunk_size: int = 1024 * 1024,
        max_hits: int | None = None,
    ) -> list[int]:
        del chunk_size
        if not needle:
            raise ValueError("needle must not be empty")
        output = []
        cursor = 0
        while max_hits is None or len(output) < max_hits:
            offset = self._data.find(needle, cursor)
            if offset < 0:
                break
            output.append(offset)
            cursor = offset + 1
        return output


def build_synthetic_yim(
    raster: bytes, *, width: int, height: int
) -> bytes:
    if len(raster) != width * height * 2 or not raster:
        raise ValueError("synthetic raster geometry differs")
    units = len(raster) // 2
    if units > 0x7FFF:
        raise ValueError("synthetic literal command exceeds bound")
    payload = (0x8000 | units).to_bytes(2, "big") + raster
    size = 60 + len(payload)
    preamble = (
        f"{0x12345678:08x}{0x9ABC:04x}{size:08x}{1:04x}"
    ).encode("ascii")
    return (
        preamble
        + b"XIM2"
        + (size - 24).to_bytes(4, "big")
        + width.to_bytes(2, "big")
        + height.to_bytes(2, "big")
        + (28).to_bytes(4, "big")
        + bytes(12)
        + (size - 52).to_bytes(4, "big")
        + (0x00100001).to_bytes(4, "big")
        + payload
    )


def _synthetic_sfnt() -> bytes:
    tables = (
        (b"cmap", b"CMAP"),
        (b"head", bytes(12) + b"\x5f\x0f\x3c\xf5"),
        (b"maxp", b"MAXP"),
        (b"name", b"NAME"),
    )
    directory_end = 12 + len(tables) * 16
    cursor = directory_end
    rows = []
    payload = bytearray()
    for tag, data in tables:
        rows.append(
            tag
            + bytes(4)
            + cursor.to_bytes(4, "big")
            + len(data).to_bytes(4, "big")
        )
        payload.extend(data)
        padding = (-len(data)) % 4
        payload.extend(bytes(padding))
        cursor += len(data) + padding
    return (
        b"\x00\x01\x00\x00"
        + len(tables).to_bytes(2, "big")
        + (64).to_bytes(2, "big")
        + (2).to_bytes(2, "big")
        + bytes(2)
        + b"".join(rows)
        + bytes(payload)
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def run_resource_lab_integration() -> dict[str, object]:
    raster = bytes.fromhex(
        "0000 f800 07e0 001f ffff 7bef 39e7 4208".replace(" ", "")
    )
    yim = build_synthetic_yim(raster, width=4, height=2)
    decoded = decode_yim_rle(yim)
    embedded_blob = b"prefix" + yim[24:] + b"suffix"
    embedded = {
        release: scan_embedded_xim2(MemoryReader(embedded_blob), release=release)
        for release in ("cd1", "cd3")
    }
    standalone_source = {
        "source_id": "SYNTHETIC-YIM",
        "extension": ".YIM",
        "data": yim,
        "members": [
            {
                "disc": "cd1",
                "path": "MMI_HI/DATA/DEFAULT/SCREEN.YIM",
                "size": len(yim),
            },
            {
                "disc": "cd3",
                "path": "MMI_HI/DATA/DEFAULT/SCREEN.YIM",
                "size": len(yim),
            },
        ],
    }
    catalog_private = build_resource_catalog(
        embedded, [(standalone_source, decoded)]
    )
    catalog = build_public_resource_catalog(catalog_private)
    geometry = build_geometry_taxonomy(catalog_private)
    pixels = evaluate_pixel_layouts(
        [("synthetic", raster, 4, 2)]
    )
    previews_private = build_candidate_previews(raster, 4, 2)
    preview = build_public_preview_summary(
        previews_private, width=4, height=2
    )
    sfnt = _synthetic_sfnt()
    readers = {
        "cd1": MemoryReader(
            b"MMI MENU ENGLISHUK font icon /ui/" + sfnt
        ),
        "cd3": MemoryReader(
            b"MMI MENU ENGLISHUK font icon /ui/ updated" + sfnt
        ),
    }
    text = build_text_catalog(readers)
    fonts = build_font_catalog(
        readers,
        {
            "structural_status": "SYNTHETIC_CONTROL",
            "semantic_status": "NOT_APPLICABLE",
            "semantic_confirmation": False,
        },
    )
    language_sources = [
        {
            "source_id": "SYNTHETIC-LOD-DE",
            "extension": ".LOD",
            "members": [
                {
                    "disc": release,
                    "path": f"SDS/{'GERMAN'}/FLASH.LOD",
                    "size": 10,
                }
                for release in ("cd1", "cd3")
            ],
        },
        {
            "source_id": "SYNTHETIC-LOD-EN",
            "extension": ".LOD",
            "members": [
                {
                    "disc": release,
                    "path": f"SDS/{'ENGLISHUK'}/FLASH.LOD",
                    "size": 12,
                }
                for release in ("cd1", "cd3")
            ],
        },
        standalone_source,
    ]
    language = build_language_topology(language_sources)
    graph = build_resource_relationship_graph(
        catalog, geometry, pixels, preview, text, fonts, language
    )
    report: dict[str, object] = {
        "schema": "phoenix-mmi.m3-resource-lab-integration/v1",
        "fixture_class": "SYNTHETIC_NON_FIRMWARE_RESOURCE_CORPUS",
        "catalog": {
            "schema": catalog["schema"],
            "record_count": catalog["record_count"],
            "unique_decoded_content_count": catalog[
                "unique_decoded_content_count"
            ],
        },
        "geometry": {
            "schema": geometry["schema"],
            "unique_resource_count": geometry["unique_resource_count"],
        },
        "pixels": {
            "schema": pixels["schema"],
            "candidate_count": pixels["candidate_count"],
            "selected_layout": pixels["classification"]["pixel_layout"],
        },
        "preview": {
            "schema": preview["schema"],
            "candidate_preview_count": preview["candidate_preview_count"],
        },
        "text": {
            "schema": text["schema"],
            "artifact_count": len(text["artifacts"]),
        },
        "fonts": {
            "schema": fonts["schema"],
            "validated_count": sum(
                item["validated_standard_font_count"]
                for item in fonts["artifacts"]
            ),
        },
        "language": {
            "schema": language["schema"],
            "locale_count": language["locale_count"],
        },
        "graph": {
            "schema": graph["schema"],
            "node_count": graph["node_count"],
            "edge_count": graph["edge_count"],
        },
        "publication_safety": {
            "fixture_is_firmware": False,
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "decoded_raster_bytes_included": False,
            "preview_bytes_included": False,
            "raw_strings_included": False,
            "installable_artifacts_included": False,
        },
    }
    report["integration_fingerprint"] = hashlib.sha256(
        _canonical(report)
    ).hexdigest()
    report["passed"] = (
        report["catalog"]["record_count"] == 3
        and report["geometry"]["unique_resource_count"] == 1
        and report["pixels"]["candidate_count"] == 8
        and report["preview"]["candidate_preview_count"] == 4
        and report["fonts"]["validated_count"] == 2
        and report["language"]["locale_count"] == 2
        and report["graph"]["node_count"] >= 10
        and report["publication_safety"]["firmware_bytes_included"] is False
    )
    return report

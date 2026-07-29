"""Publication-safe text, font-candidate and language-topology research."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
from typing import Iterable, Protocol

from .strings import CATEGORY_TERMS, StringRecord, extract_strings


_LOCALE_MARKERS = {
    "ENGLISH": "en-GB",
    "ENGLISHU": "en-GB",
    "ENGLISHUK": "en-GB",
    "FRENCH": "fr-FR",
    "GERMAN": "de-DE",
    "ITALIAN": "it-IT",
    "SPANISH": "es-ES",
}


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def find_all(
        self,
        needle: bytes,
        *,
        chunk_size: int = 1024 * 1024,
        max_hits: int | None = None,
    ) -> list[int]: ...


def _length_bucket(length: int) -> str:
    if length < 8:
        return "5-7"
    if length < 16:
        return "8-15"
    if length < 32:
        return "16-31"
    if length < 64:
        return "32-63"
    return "64+"


def _string_summary(records: list[StringRecord]) -> dict[str, object]:
    unique = {(item.encoding, item.text) for item in records}
    encodings = Counter(item.encoding for item in records)
    lengths = Counter(_length_bucket(len(item.text)) for item in records)
    categories: Counter[str] = Counter()
    locales: Counter[str] = Counter()
    for item in records:
        folded = item.text.casefold()
        for category, terms in CATEGORY_TERMS.items():
            if any(term in folded for term in terms):
                categories[category] += 1
        upper = item.text.upper()
        for marker, locale in _LOCALE_MARKERS.items():
            if marker in upper:
                locales[locale] += 1
    return {
        "record_count": len(records),
        "unique_record_count": len(unique),
        "encoding_counts": dict(sorted(encodings.items())),
        "length_bucket_counts": dict(sorted(lengths.items())),
        "category_hit_counts": dict(sorted(categories.items())),
        "locale_marker_counts": dict(sorted(locales.items())),
        "path_like_record_count": sum(
            "/" in item.text or "\\" in item.text for item in records
        ),
    }


def build_text_catalog(readers: dict[str, _Reader]) -> dict[str, object]:
    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("text catalog requires cd1 and cd3")
    private = {
        release: extract_strings(reader, min_length=5)
        for release, reader in sorted(readers.items())
    }
    sets = {
        release: {(item.encoding, item.text) for item in records}
        for release, records in private.items()
    }
    return {
        "schema": "phoenix-mmi.resource-text-catalog/v1",
        "analysis_mode": "private-string-extraction-public-aggregate",
        "artifacts": [
            {"artifact": release, **_string_summary(private[release])}
            for release in ("cd1", "cd3")
        ],
        "cross_version": {
            "shared_unique_record_count": len(sets["cd1"] & sets["cd3"]),
            "cd1_only_unique_record_count": len(sets["cd1"] - sets["cd3"]),
            "cd3_only_unique_record_count": len(sets["cd3"] - sets["cd1"]),
        },
        "classification": {
            "text_presence": "CONFIRMED",
            "text_semantic_ownership": "NOT_ASSIGNED",
        },
        "publication_safety": {
            "raw_strings_included": False,
            "string_hashes_included": False,
            "raw_offsets_included": False,
            "local_paths_included": False,
            "firmware_bytes_included": False,
        },
    }


@dataclass(frozen=True)
class FontCandidate:
    kind: str
    offset: int
    span: int
    sha256: str


def _sfnt_candidate(
    reader: _Reader, offset: int, kind: str
) -> FontCandidate | None:
    header = reader.read(offset, 12)
    if len(header) != 12:
        return None
    num_tables = int.from_bytes(header[4:6], "big")
    if not 1 <= num_tables <= 256:
        return None
    maximum_power = 1 << (num_tables.bit_length() - 1)
    expected_search_range = maximum_power * 16
    expected_entry_selector = maximum_power.bit_length() - 1
    expected_range_shift = num_tables * 16 - expected_search_range
    if (
        int.from_bytes(header[6:8], "big") != expected_search_range
        or int.from_bytes(header[8:10], "big") != expected_entry_selector
        or int.from_bytes(header[10:12], "big") != expected_range_shift
    ):
        return None
    directory = reader.read(offset + 12, num_tables * 16)
    if len(directory) != num_tables * 16:
        return None
    end = 12 + len(directory)
    tags: set[bytes] = set()
    tables: dict[bytes, tuple[int, int]] = {}
    for index in range(num_tables):
        row = directory[index * 16 : (index + 1) * 16]
        tag = row[0:4]
        table_offset = int.from_bytes(row[8:12], "big")
        table_length = int.from_bytes(row[12:16], "big")
        if (
            not all(32 <= value < 127 for value in tag)
            or tag in tags
            or table_offset < 12 + len(directory)
            or table_offset % 4
            or table_length <= 0
            or offset + table_offset + table_length > reader.size
        ):
            return None
        tags.add(tag)
        tables[tag] = (table_offset, table_length)
        end = max(end, table_offset + table_length)
    if not {b"cmap", b"head", b"maxp", b"name"}.issubset(tags):
        return None
    head_offset, head_length = tables[b"head"]
    if (
        head_length < 16
        or reader.read(offset + head_offset + 12, 4) != b"\x5f\x0f\x3c\xf5"
    ):
        return None
    data = reader.read(offset, end)
    if len(data) != end:
        return None
    return FontCandidate(kind, offset, end, hashlib.sha256(data).hexdigest())


def _pcf_candidate(reader: _Reader, offset: int) -> FontCandidate | None:
    header = reader.read(offset, 8)
    if len(header) != 8 or header[:4] != b"\x01fcp":
        return None
    count = int.from_bytes(header[4:8], "little")
    if not 1 <= count <= 64:
        return None
    table = reader.read(offset + 8, count * 16)
    if len(table) != count * 16:
        return None
    end = 8 + len(table)
    for index in range(count):
        row = table[index * 16 : (index + 1) * 16]
        size = int.from_bytes(row[8:12], "little")
        table_offset = int.from_bytes(row[12:16], "little")
        if size <= 0 or offset + table_offset + size > reader.size:
            return None
        end = max(end, table_offset + size)
    data = reader.read(offset, end)
    return FontCandidate("PCF", offset, end, hashlib.sha256(data).hexdigest())


def scan_font_candidates(reader: _Reader) -> tuple[FontCandidate, ...]:
    candidates: list[FontCandidate] = []
    for magic, kind in (
        (b"\x00\x01\x00\x00", "TRUETYPE_SFNT"),
        (b"OTTO", "OPENTYPE_CFF"),
    ):
        for offset in reader.find_all(magic, max_hits=4096):
            candidate = _sfnt_candidate(reader, offset, kind)
            if candidate is not None:
                candidates.append(candidate)
    for offset in reader.find_all(b"\x01fcp", max_hits=4096):
        candidate = _pcf_candidate(reader, offset)
        if candidate is not None:
            candidates.append(candidate)
    return tuple(
        sorted(
            {(item.kind, item.offset): item for item in candidates}.values(),
            key=lambda item: (item.offset, item.kind),
        )
    )


def build_font_catalog(
    readers: dict[str, _Reader], atlas_evidence: dict[str, object]
) -> dict[str, object]:
    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("font catalog requires cd1 and cd3")
    private = {
        release: scan_font_candidates(reader)
        for release, reader in sorted(readers.items())
    }
    sets = {
        release: {item.sha256 for item in rows}
        for release, rows in private.items()
    }
    kind_counts = {
        release: dict(sorted(Counter(item.kind for item in rows).items()))
        for release, rows in private.items()
    }
    structural_status = atlas_evidence.get("structural_status", "UNAVAILABLE")
    semantic_status = atlas_evidence.get("semantic_status", "UNAVAILABLE")
    return {
        "schema": "phoenix-mmi.font-candidate-catalog/v1",
        "analysis_mode": "validated-standard-container-and-prior-atlas-evidence",
        "artifacts": [
            {
                "artifact": release,
                "validated_standard_font_count": len(private[release]),
                "kind_counts": kind_counts[release],
            }
            for release in ("cd1", "cd3")
        ],
        "cross_version": {
            "shared_standard_font_content_count": len(
                sets["cd1"] & sets["cd3"]
            ),
            "cd1_only_standard_font_content_count": len(
                sets["cd1"] - sets["cd3"]
            ),
            "cd3_only_standard_font_content_count": len(
                sets["cd3"] - sets["cd1"]
            ),
        },
        "bitmap_atlas_evidence": {
            "structural_status": structural_status,
            "semantic_status": semantic_status,
            "semantic_confirmation": bool(
                atlas_evidence.get("semantic_confirmation", False)
            ),
        },
        "classification": {
            "standard_font_container_presence": (
                "CONFIRMED"
                if any(private.values())
                else "NOT_FOUND_UNDER_VALIDATED_SFNT_PCF_MODEL"
            ),
            "bitmap_font_model": "PROBABLE_NOT_CONFIRMED",
            "renderer_consumer": "NOT_IDENTIFIED",
        },
        "publication_safety": {
            "font_bytes_included": False,
            "rendered_glyphs_included": False,
            "content_hashes_included": False,
            "offsets_included": False,
            "firmware_bytes_included": False,
        },
    }


def _locale_from_path(path: str) -> str | None:
    parts = [item.upper() for item in PurePosixPath(path).parts]
    matches = {
        locale
        for marker, locale in _LOCALE_MARKERS.items()
        if marker in parts
    }
    if len(matches) > 1:
        raise ValueError(f"ambiguous locale path: {path}")
    return next(iter(matches), None)


def build_language_topology(
    sources: Iterable[dict[str, object]],
) -> dict[str, object]:
    locale_rows: dict[str, dict[str, object]] = {}
    default_member_count = 0
    for source in sources:
        extension = str(source["extension"])
        for member in source["members"]:
            path = str(member["path"])
            locale = _locale_from_path(path)
            if locale is None:
                if extension == ".YIM" and "DEFAULT" in path.upper():
                    default_member_count += 1
                continue
            row = locale_rows.setdefault(
                locale,
                {
                    "member_count": 0,
                    "member_bytes": 0,
                    "discs": set(),
                    "source_ids": set(),
                },
            )
            row["member_count"] += 1
            row["member_bytes"] += int(member["size"])
            row["discs"].add(str(member["disc"]))
            row["source_ids"].add(str(source["source_id"]))
    rows = []
    for locale, value in sorted(locale_rows.items()):
        rows.append(
            {
                "locale": locale,
                "member_count": value["member_count"],
                "member_bytes": value["member_bytes"],
                "disc_count": len(value["discs"]),
                "unique_content_count": len(value["source_ids"]),
                "present_on_cd1_and_cd3": value["discs"] == {"cd1", "cd3"},
            }
        )
    return {
        "schema": "phoenix-mmi.language-pack-topology/v1",
        "analysis_mode": "fixed-locale-path-routing-content-deduplicated",
        "locale_count": len(rows),
        "locales": rows,
        "default_display_resource_member_count": default_member_count,
        "classification": {
            "locale_topology": "CONFIRMED_FROM_CONTAINER_PROVENANCE",
            "lod_payload_semantics": "UNRESOLVED",
            "locale_display_binding": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "member_paths_included": False,
            "source_ids_included": False,
            "payload_bytes_included": False,
            "content_hashes_included": False,
            "local_paths_included": False,
        },
    }


def build_resource_relationship_graph(
    catalog: dict[str, object],
    geometry: dict[str, object],
    pixels: dict[str, object],
    preview: dict[str, object],
    text: dict[str, object],
    fonts: dict[str, object],
    language: dict[str, object],
) -> dict[str, object]:
    nodes = [
        ("update-media", "CONFIRMED"),
        ("standalone-yim", "CONFIRMED"),
        ("embedded-xim2", "CONFIRMED"),
        ("decoded-16bit-raster", "CONFIRMED_STRUCTURE"),
        ("geometry-taxonomy", "CONFIRMED_STRUCTURE"),
        ("pixel-layout", "OPEN"),
        ("offline-preview", "CONFIRMED_TOOLING"),
        ("resource-text", "CONFIRMED_STRUCTURE"),
        ("standard-font-container", fonts["classification"]["standard_font_container_presence"]),
        ("bitmap-atlas", "PROBABLE_SEMANTIC"),
        ("language-lod", "CONFIRMED_TOPOLOGY"),
        ("lod-decoder", "BLOCKED"),
        ("renderer-consumer", "OPEN"),
    ]
    edges = [
        ("update-media", "standalone-yim", "contains"),
        ("update-media", "language-lod", "contains"),
        ("standalone-yim", "decoded-16bit-raster", "strictly-decodes-to"),
        ("embedded-xim2", "decoded-16bit-raster", "strictly-decodes-to"),
        ("standalone-yim", "embedded-xim2", "one-exact-content-overlap"),
        ("decoded-16bit-raster", "geometry-taxonomy", "has-validated-shape"),
        ("decoded-16bit-raster", "pixel-layout", "requires-unresolved-layout"),
        ("pixel-layout", "offline-preview", "selects-explicit-candidate"),
        ("resource-text", "renderer-consumer", "probable-consumer-input"),
        ("bitmap-atlas", "renderer-consumer", "probable-consumer-input"),
        ("language-lod", "lod-decoder", "requires"),
    ]
    return {
        "schema": "phoenix-mmi.resource-relationship-graph/v1",
        "analysis_mode": "confidence-graded-evidence-synthesis",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": [
            {"id": node_id, "status": status} for node_id, status in nodes
        ],
        "edges": [
            {"source": source, "target": target, "relation": relation}
            for source, target, relation in edges
        ],
        "source_contracts": {
            "catalog_schema": catalog["schema"],
            "geometry_schema": geometry["schema"],
            "pixel_schema": pixels["schema"],
            "preview_schema": preview["schema"],
            "text_schema": text["schema"],
            "font_schema": fonts["schema"],
            "language_schema": language["schema"],
        },
        "classification": {
            "read_only_resource_model": "CONFIRMED_PARTIAL",
            "runtime_renderer_model": "NOT_ESTABLISHED",
            "safe_mutation_ready": False,
        },
        "publication_safety": {
            "raw_strings_included": False,
            "payload_bytes_included": False,
            "decoded_raster_bytes_included": False,
            "resource_names_included": False,
            "installable_artifacts_included": False,
        },
    }

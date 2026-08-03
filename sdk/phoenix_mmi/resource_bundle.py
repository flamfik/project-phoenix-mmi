"""Static structure analysis for the filler-bounded MMI browser-resource island."""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import asdict, dataclass
import hashlib
from html.parser import HTMLParser
import ipaddress
import re
from typing import Iterable
from urllib.parse import urlparse

from .binary import BinaryReader


@dataclass(frozen=True)
class HTMLDocument:
    offset: int
    end: int
    length: int
    sha256: str
    doctype_present: bool
    tag_counts: dict[str, int]
    image_reference_count: int
    image_extension_counts: dict[str, int]
    link_reference_count: int
    http_reference_count: int
    private_ipv4_reference_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PointerRun:
    offset: int
    end: int
    count: int
    values: tuple[int, ...]

    def public_dict(self, *, island_offset: int = 0) -> dict[str, object]:
        return {
            "offset": self.offset,
            "island_offset": island_offset + self.offset,
            "end": self.end,
            "count": self.count,
            "minimum_value": min(self.values),
            "maximum_value": max(self.values),
            "first_value": self.values[0],
            "last_value": self.values[-1],
            "distinct_value_count": len(set(self.values)),
            "monotonic_non_decreasing": all(
                left <= right for left, right in zip(self.values, self.values[1:])
            ),
            "raw_bytes_included": False,
        }


class _HTMLSummaryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: Counter[str] = Counter()
        self.image_references: list[str] = []
        self.link_references: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        self.tags[tag] += 1
        attributes = {key.casefold(): value or "" for key, value in attrs}
        if tag == "img" and attributes.get("src"):
            self.image_references.append(attributes["src"])
        for key in ("src", "href"):
            if attributes.get(key):
                self.link_references.append(attributes[key])


def _resource_extension(reference: str) -> str | None:
    match = re.search(r"\.(gif|jpe?g|png)(?:[?#].*)?$", reference.casefold())
    if not match:
        return None
    extension = match.group(1)
    return "jpg" if extension in ("jpg", "jpeg") else extension


def _is_private_ipv4_reference(reference: str) -> bool:
    try:
        hostname = urlparse(reference).hostname
        if not hostname:
            return False
        address = ipaddress.ip_address(hostname)
        return address.version == 4 and address.is_private
    except ValueError:
        return False


def find_embedded_html(data: bytes, *, base_offset: int = 0) -> list[HTMLDocument]:
    """Find complete HTML documents without returning their raw contents."""

    folded = data.lower()
    documents: list[HTMLDocument] = []
    cursor = 0
    while True:
        html_start = folded.find(b"<html", cursor)
        if html_start < 0:
            break
        doctype_start = folded.rfind(b"<!doctype", max(cursor, html_start - 256), html_start)
        start = doctype_start if doctype_start >= cursor else html_start
        close = folded.find(b"</html>", html_start)
        if close < 0:
            break
        end = close + len(b"</html>")
        while end < len(data) and data[end] in b"\r\n":
            end += 1
        raw = data[start:end]
        parser = _HTMLSummaryParser()
        parser.feed(raw.decode("latin1", "replace"))
        extension_counts = Counter(
            extension
            for reference in parser.image_references
            if (extension := _resource_extension(reference)) is not None
        )
        http_references = [
            reference
            for reference in parser.link_references
            if reference.casefold().startswith(("http://", "https://"))
        ]
        documents.append(
            HTMLDocument(
                offset=base_offset + start,
                end=base_offset + end,
                length=end - start,
                sha256=hashlib.sha256(raw).hexdigest(),
                doctype_present=doctype_start >= cursor,
                tag_counts=dict(sorted(parser.tags.items())),
                image_reference_count=len(parser.image_references),
                image_extension_counts=dict(sorted(extension_counts.items())),
                link_reference_count=len(parser.link_references),
                http_reference_count=len(http_references),
                private_ipv4_reference_count=sum(
                    _is_private_ipv4_reference(reference) for reference in http_references
                ),
            )
        )
        cursor = end
    return documents


def find_pointer_runs(
    data: bytes,
    *,
    minimum: int = 0x0C000000,
    maximum: int = 0x0D000000,
    minimum_count: int = 3,
) -> list[PointerRun]:
    """Find aligned runs of big-endian 32-bit values in one address range."""

    if minimum_count < 2:
        raise ValueError("minimum_count must be at least 2")
    runs: list[PointerRun] = []
    for alignment in range(4):
        current_offsets: list[int] = []
        current_values: list[int] = []
        for offset in range(alignment, len(data) - 3, 4):
            value = int.from_bytes(data[offset : offset + 4], "big")
            if minimum <= value < maximum:
                current_offsets.append(offset)
                current_values.append(value)
                continue
            if len(current_values) >= minimum_count:
                runs.append(
                    PointerRun(
                        offset=current_offsets[0],
                        end=current_offsets[-1] + 4,
                        count=len(current_values),
                        values=tuple(current_values),
                    )
                )
            current_offsets = []
            current_values = []
        if len(current_values) >= minimum_count:
            runs.append(
                PointerRun(
                    offset=current_offsets[0],
                    end=current_offsets[-1] + 4,
                    count=len(current_values),
                    values=tuple(current_values),
                )
            )
    return sorted(runs, key=lambda item: (item.offset, item.count))


def compare_pointer_runs(
    left: list[PointerRun], right: list[PointerRun]
) -> dict[str, object]:
    """Compare ordinal runs only when their count signatures are identical."""

    left_signature = [run.count for run in left]
    right_signature = [run.count for run in right]
    if left_signature != right_signature:
        return {
            "status": "UNPAIRED",
            "left_count_signature": left_signature,
            "right_count_signature": right_signature,
            "pairs": [],
        }
    pairs = []
    for index, (left_run, right_run) in enumerate(zip(left, right)):
        deltas = [
            right_value - left_value
            for left_value, right_value in zip(left_run.values, right_run.values)
        ]
        counts = Counter(deltas)
        mode, mode_count = counts.most_common(1)[0]
        pairs.append(
            {
                "index": index,
                "count": left_run.count,
                "left_offset": left_run.offset,
                "right_offset": right_run.offset,
                "offset_delta": right_run.offset - left_run.offset,
                "value_delta_mode": mode,
                "value_delta_mode_count": mode_count,
                "distinct_value_delta_count": len(counts),
                "all_values_same_delta": len(counts) == 1,
            }
        )
    return {
        "status": "PAIRED_BY_COUNT_SIGNATURE",
        "count_signature": left_signature,
        "pairs": pairs,
    }


def _find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return hits
        hits.append(offset)
        start = offset + 1


def test_relative_offset_tables(
    regions: dict[str, bytes],
    models: dict[str, list[int]],
    *,
    widths: tuple[int, ...] = (2, 4),
    endians: tuple[str, ...] = ("big", "little"),
    strides: tuple[int, ...] = (2, 4, 8, 12, 16),
) -> dict[str, object]:
    """Test complete contiguous/strided resource-offset table hypotheses."""

    full_candidates: list[dict[str, object]] = []
    coverage: list[dict[str, object]] = []
    for model_name, values in models.items():
        for width in widths:
            if any(value < 0 or value >= 1 << (width * 8) for value in values):
                continue
            for endian in endians:
                packed = [value.to_bytes(width, endian) for value in values]
                nonzero_indices = [index for index, value in enumerate(values) if value != 0]
                matched_indices: set[int] = set()
                for region in regions.values():
                    for index in nonzero_indices:
                        if packed[index] in region:
                            matched_indices.add(index)
                coverage.append(
                    {
                        "model": model_name,
                        "width": width,
                        "endian": endian,
                        "matched_nonzero_target_count": len(matched_indices),
                        "nonzero_target_count": len(nonzero_indices),
                    }
                )
                for stride in sorted({stride for stride in strides if stride >= width}):
                    span = (len(values) - 1) * stride + width
                    for region_name, region in regions.items():
                        if span > len(region):
                            continue
                        for first_hit in _find_all(region, packed[0]):
                            if first_hit + span > len(region):
                                continue
                            if all(
                                region[first_hit + index * stride : first_hit + index * stride + width]
                                == packed[index]
                                for index in range(len(values))
                            ):
                                full_candidates.append(
                                    {
                                        "model": model_name,
                                        "region": region_name,
                                        "offset": first_hit,
                                        "width": width,
                                        "endian": endian,
                                        "stride": stride,
                                        "entry_count": len(values),
                                    }
                                )
    return {
        "models_tested": sorted(models),
        "regions_tested": sorted(regions),
        "widths_tested": list(widths),
        "endians_tested": list(endians),
        "strides_tested": list(strides),
        "full_candidate_count": len(full_candidates),
        "full_candidates": full_candidates,
        "individual_value_coverage": coverage,
        "interpretation": (
            "A zero full-candidate count rejects only the listed complete fixed-width, "
            "fixed-stride offset-table models."
        ),
    }


def analyze_resource_bundle(
    reader: BinaryReader,
    *,
    island: dict[str, object],
    cluster: dict[str, object],
    resources: Iterable[dict[str, object]],
) -> dict[str, object]:
    island_offset = int(island["offset"])
    island_end = int(island["end"])
    cluster_offset = int(cluster["offset"])
    cluster_end = int(cluster["end"])
    if not island_offset <= cluster_offset <= cluster_end <= island_end:
        raise ValueError("resource cluster lies outside the candidate island")
    data = reader.read(island_offset, island_end - island_offset)
    prefix_length = cluster_offset - island_offset
    cluster_relative_end = cluster_end - island_offset
    prefix = data[:prefix_length]
    resource_cluster = data[prefix_length:cluster_relative_end]
    suffix = data[cluster_relative_end:]
    ordered_resources = sorted(resources, key=lambda item: int(item["offset"]))
    island_relative_starts = [int(item["offset"]) - island_offset for item in ordered_resources]
    cluster_relative_starts = [int(item["offset"]) - cluster_offset for item in ordered_resources]
    documents = find_embedded_html(data)
    pointer_runs = find_pointer_runs(suffix)
    offset_tables = test_relative_offset_tables(
        {"pre-resource": prefix, "post-cluster": suffix},
        {
            "island-relative-resource-starts": island_relative_starts,
            "cluster-relative-resource-starts": cluster_relative_starts,
        },
    )
    format_counts = Counter(str(item["format"]) for item in ordered_resources)
    main_document = documents[0] if documents and documents[0].offset == 0 else None
    core = data[:cluster_relative_end]
    return {
        "schema": "phoenix-mmi.resource-bundle/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "filename": reader.path.name,
            "sha256": reader.sha256(),
            "size_bytes": reader.size,
        },
        "island": {
            "offset": island_offset,
            "end": island_end,
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "core_bundle": {
            "offset": island_offset,
            "end": cluster_end,
            "length": len(core),
            "sha256": hashlib.sha256(core).hexdigest(),
            "pre_resource_length": len(prefix),
            "pre_resource_sha256": hashlib.sha256(prefix).hexdigest(),
            "resource_cluster_length": len(resource_cluster),
            "resource_cluster_sha256": hashlib.sha256(resource_cluster).hexdigest(),
        },
        "html": {
            "document_count": len(documents),
            "documents": [document.to_dict() for document in documents],
            "main_document_at_island_start": main_document is not None,
            "main_document_trailing_separator_length": (
                prefix_length - main_document.length if main_document else None
            ),
            "raw_html_included": False,
            "raw_uris_included": False,
        },
        "resources": {
            "validated_count": len(ordered_resources),
            "format_counts": dict(sorted(format_counts.items())),
            "main_html_image_reference_count": (
                main_document.image_reference_count if main_document else None
            ),
            "resource_minus_main_html_image_reference_count": (
                len(ordered_resources) - main_document.image_reference_count
                if main_document
                else None
            ),
        },
        "post_cluster": {
            "offset_within_island": cluster_relative_end,
            "length": len(suffix),
            "sha256": hashlib.sha256(suffix).hexdigest(),
            "pointer_address_range": {"minimum": 0x0C000000, "maximum": 0x0D000000},
            "pointer_runs": [
                run.public_dict(island_offset=cluster_relative_end) for run in pointer_runs
            ],
        },
        "relative_offset_table_tests": offset_tables,
        "publication_safety": {
            "firmware_bytes_included": False,
            "resource_bytes_included": False,
            "raw_html_included": False,
            "raw_uris_included": False,
            "arbitrary_raw_strings_included": False,
        },
        "_internal_pointer_runs": [
            {"offset": run.offset, "end": run.end, "values": list(run.values)}
            for run in pointer_runs
        ],
    }


def build_public_resource_bundle(report: dict[str, object]) -> dict[str, object]:
    public = copy.deepcopy(report)
    public.pop("_internal_pointer_runs", None)
    return public


def compare_resource_bundles(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    left_runs = [
        PointerRun(
            offset=int(item["offset"]),
            end=int(item["end"]),
            count=len(item["values"]),
            values=tuple(int(value) for value in item["values"]),
        )
        for item in left["_internal_pointer_runs"]
    ]
    right_runs = [
        PointerRun(
            offset=int(item["offset"]),
            end=int(item["end"]),
            count=len(item["values"]),
            values=tuple(int(value) for value in item["values"]),
        )
        for item in right["_internal_pointer_runs"]
    ]
    left_documents = left["html"]["documents"]
    right_documents = right["html"]["documents"]
    return {
        "schema": "phoenix-mmi.resource-bundle-comparison/v1",
        "left": left["artifact"]["label"],
        "right": right["artifact"]["label"],
        "core_bundle_equal": left["core_bundle"]["sha256"]
        == right["core_bundle"]["sha256"],
        "core_bundle_length_equal": left["core_bundle"]["length"]
        == right["core_bundle"]["length"],
        "html_document_count_equal": len(left_documents) == len(right_documents),
        "html_document_hashes_equal": [
            left_item["sha256"] == right_item["sha256"]
            for left_item, right_item in zip(left_documents, right_documents)
        ],
        "post_cluster_length_delta": right["post_cluster"]["length"]
        - left["post_cluster"]["length"],
        "post_cluster_sha256_equal": left["post_cluster"]["sha256"]
        == right["post_cluster"]["sha256"],
        "pointer_runs": compare_pointer_runs(left_runs, right_runs),
        "relative_offset_table_candidates": {
            "left": left["relative_offset_table_tests"]["full_candidate_count"],
            "right": right["relative_offset_table_tests"]["full_candidate_count"],
        },
        "publication_safety": {"artifact_bytes_included": False},
    }

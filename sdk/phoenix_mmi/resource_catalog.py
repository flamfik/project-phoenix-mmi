"""Private resource identities and publication-safe XIM2 catalog summaries."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Iterable, Protocol

from .yim import YimDecodeResult


RESOURCE_CATALOG_SCHEMA = "phoenix-mmi.resource-catalog/v1"
_XIM2_HEADER_SIZE = 36
_MAX_XIM2_SPAN = 16 * 1024 * 1024


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...


@dataclass(frozen=True)
class ResourceRecord:
    logical_id: str
    origin: str
    release: str
    ordinal: int
    offset: int | None
    span: int
    width: int
    height: int
    codec_word: int
    encoded_sha256: str
    decoded_sha256: str
    decoded_bytes: int

    def __post_init__(self) -> None:
        if self.origin not in {"embedded-main-image", "standalone-update"}:
            raise ValueError("unsupported resource origin")
        if self.release not in {"cd1", "cd3", "shared-cd1-cd3"}:
            raise ValueError("unsupported resource release")
        if (
            self.ordinal < 0
            or self.offset is not None
            and self.offset < 0
            or self.span <= 0
            or self.width <= 0
            or self.height <= 0
            or self.decoded_bytes != self.width * self.height * 2
        ):
            raise ValueError("invalid resource geometry or bounds")
        for digest in (self.encoded_sha256, self.decoded_sha256):
            if len(digest) != 64 or any(value not in "0123456789abcdef" for value in digest):
                raise ValueError("resource digest is not lowercase SHA-256")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DecodedEmbeddedResource:
    record: ResourceRecord
    raster: bytes


@dataclass(frozen=True)
class ResourceCatalog:
    catalog_id: str
    records: tuple[ResourceRecord, ...]

    def __post_init__(self) -> None:
        ids = [item.logical_id for item in self.records]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ValueError("resource records must have sorted unique logical IDs")

    @property
    def fingerprint(self) -> str:
        body = {
            "schema": RESOURCE_CATALOG_SCHEMA,
            "catalog_id": self.catalog_id,
            "records": [item.to_dict() for item in self.records],
        }
        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": RESOURCE_CATALOG_SCHEMA,
            "catalog_id": self.catalog_id,
            "catalog_fingerprint": self.fingerprint,
            "record_count": len(self.records),
            "records": [item.to_dict() for item in self.records],
            "publication_class": "PRIVATE_LOCAL",
        }


def _decode_embedded(
    data: bytes, offset: int, *, release: str, ordinal: int
) -> DecodedEmbeddedResource | None:
    if offset < 0 or offset + _XIM2_HEADER_SIZE > len(data):
        return None
    if data[offset : offset + 4] != b"XIM2":
        return None
    span = int.from_bytes(data[offset + 4 : offset + 8], "big")
    width = int.from_bytes(data[offset + 8 : offset + 10], "big")
    height = int.from_bytes(data[offset + 10 : offset + 12], "big")
    header_size = int.from_bytes(data[offset + 12 : offset + 16], "big")
    reserved = data[offset + 16 : offset + 28]
    payload_span = int.from_bytes(data[offset + 28 : offset + 32], "big")
    codec_word = int.from_bytes(data[offset + 32 : offset + 36], "big")
    end = offset + span
    expected = width * height * 2
    if not (
        _XIM2_HEADER_SIZE <= span <= _MAX_XIM2_SPAN
        and end <= len(data)
        and 0 < width <= 4096
        and 0 < height <= 4096
        and expected <= _MAX_XIM2_SPAN
        and header_size == 28
        and not any(reserved)
        and payload_span == span - 28
    ):
        return None
    payload = data[offset + _XIM2_HEADER_SIZE : end]
    cursor = 0
    output = bytearray()
    while cursor < len(payload):
        if cursor + 2 > len(payload):
            return None
        command = int.from_bytes(payload[cursor : cursor + 2], "big")
        cursor += 2
        count = command & 0x7FFF
        if not count or len(output) + count * 2 > expected:
            return None
        if command & 0x8000:
            byte_count = count * 2
            if cursor + byte_count > len(payload):
                return None
            output.extend(payload[cursor : cursor + byte_count])
            cursor += byte_count
        else:
            if cursor + 2 > len(payload):
                return None
            output.extend(payload[cursor : cursor + 2] * count)
            cursor += 2
    if len(output) != expected:
        return None
    encoded = data[offset:end]
    raster = bytes(output)
    return DecodedEmbeddedResource(
        ResourceRecord(
            logical_id=f"embedded-{release}-{ordinal:03d}",
            origin="embedded-main-image",
            release=release,
            ordinal=ordinal,
            offset=offset,
            span=span,
            width=width,
            height=height,
            codec_word=codec_word,
            encoded_sha256=hashlib.sha256(encoded).hexdigest(),
            decoded_sha256=hashlib.sha256(raster).hexdigest(),
            decoded_bytes=len(raster),
        ),
        raster,
    )


def scan_embedded_xim2(
    reader: _Reader, *, release: str
) -> tuple[DecodedEmbeddedResource, ...]:
    """Return strictly decoded records for private local analysis."""

    if release not in {"cd1", "cd3"}:
        raise ValueError("embedded release must be cd1 or cd3")
    data = reader.read(0, reader.size)
    offsets = []
    cursor = 0
    while True:
        offset = data.find(b"XIM2", cursor)
        if offset < 0:
            break
        offsets.append(offset)
        cursor = offset + 1
    accepted = []
    for offset in offsets:
        decoded = _decode_embedded(
            data, offset, release=release, ordinal=len(accepted)
        )
        if decoded is not None:
            accepted.append(decoded)
    return tuple(accepted)


def build_resource_catalog(
    embedded: dict[str, tuple[DecodedEmbeddedResource, ...]],
    standalone: Iterable[tuple[dict[str, object], YimDecodeResult]],
) -> ResourceCatalog:
    if sorted(embedded) != ["cd1", "cd3"]:
        raise ValueError("catalog requires cd1 and cd3 embedded resources")
    records = [
        resource.record
        for release in ("cd1", "cd3")
        for resource in embedded[release]
    ]
    for ordinal, (source, result) in enumerate(standalone):
        data = bytes(source["data"])
        encoded = data[24:]
        records.append(
            ResourceRecord(
                logical_id=f"standalone-shared-{ordinal:03d}",
                origin="standalone-update",
                release="shared-cd1-cd3",
                ordinal=ordinal,
                offset=None,
                span=len(encoded),
                width=result.envelope.width,
                height=result.envelope.height,
                codec_word=result.envelope.codec_word,
                encoded_sha256=hashlib.sha256(encoded).hexdigest(),
                decoded_sha256=hashlib.sha256(result.raster).hexdigest(),
                decoded_bytes=len(result.raster),
            )
        )
    return ResourceCatalog(
        "mmi5570-resource-corpus",
        tuple(sorted(records, key=lambda item: item.logical_id)),
    )


def unique_decoded_records(catalog: ResourceCatalog) -> tuple[ResourceRecord, ...]:
    by_digest: dict[str, ResourceRecord] = {}
    for record in catalog.records:
        by_digest.setdefault(record.decoded_sha256, record)
    return tuple(sorted(by_digest.values(), key=lambda item: item.decoded_sha256))


def build_public_resource_catalog(
    catalog: ResourceCatalog,
) -> dict[str, object]:
    origins = Counter(item.origin for item in catalog.records)
    releases = Counter(item.release for item in catalog.records)
    unique = unique_decoded_records(catalog)
    geometry_counts = Counter((item.width, item.height) for item in unique)
    cd1 = {
        item.decoded_sha256
        for item in catalog.records
        if item.release == "cd1"
    }
    cd3 = {
        item.decoded_sha256
        for item in catalog.records
        if item.release == "cd3"
    }
    standalone = {
        item.decoded_sha256
        for item in catalog.records
        if item.origin == "standalone-update"
    }
    embedded = cd1 | cd3
    return {
        "schema": "phoenix-mmi.resource-catalog-summary/v1",
        "analysis_mode": "strict-private-identity-public-aggregate",
        "catalog_schema": RESOURCE_CATALOG_SCHEMA,
        "record_count": len(catalog.records),
        "origin_counts": dict(sorted(origins.items())),
        "release_counts": dict(sorted(releases.items())),
        "unique_encoded_content_count": len(
            {item.encoded_sha256 for item in catalog.records}
        ),
        "unique_decoded_content_count": len(unique),
        "distinct_geometry_count": len(geometry_counts),
        "geometry_counts": [
            {"width": width, "height": height, "resource_count": count}
            for (width, height), count in sorted(geometry_counts.items())
        ],
        "cross_version": {
            "embedded_sets_equal": cd1 == cd3,
            "shared_embedded_decoded_count": len(cd1 & cd3),
            "standalone_unique_decoded_count": len(standalone),
            "standalone_embedded_overlap_count": len(standalone & embedded),
        },
        "classification": {
            "resource_identity": "CONFIRMED_BY_STRICT_ENCODED_AND_DECODED_HASHES",
            "semantic_roles": "NOT_ASSIGNED",
        },
        "publication_safety": {
            "logical_ids_included": False,
            "content_hashes_included": False,
            "offsets_included": False,
            "firmware_bytes_included": False,
            "decoded_raster_bytes_included": False,
            "extracted_resources_included": False,
            "local_paths_included": False,
        },
    }

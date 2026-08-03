"""Read-only navigation-media and FLDB container analysis.

The module inventories an ISO-9660/Joliet volume, validates the outer FLDB
record tables and correlates only fixed markers with the firmware-side contract.
It never returns member names, internal filenames, payload bytes or raw metadata
strings.
"""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import math
from pathlib import PurePosixPath
import re
import struct
import zlib

from .binary import BinaryReader
from .entropy import shannon_entropy
from .iso9660 import ISO9660Image, ISOEntry, SECTOR_SIZE


FLDB_MAGIC = b"FLDB"
FLDB_MINIMUM_HEADER = 32
FLDB_RECORD_SIZE = 36
INTERNAL_NAME_BYTES = 24

KNOWN_INTERNAL_SUFFIXES = {
    "b",
    "gdb",
    "gp4",
    "gpa",
    "ort",
    "plz",
    "poi",
    "ras",
    "sm5",
    "tlt",
    "v",
    "xac",
    "xah",
    "xb1c",
    "xb7",
}

FIXED_MEDIA_MARKERS = {
    "routeact-dat-lower": b"routeact.dat",
    "routeact-dat-upper": b"ROUTEACT.DAT",
    "dbinfo-header": b"!dbinfo0001",
    "dbinfo-footer": b"!enddbinfo",
    "fldb-magic": FLDB_MAGIC,
    "release-family-ehe721": b"EHE721",
    "model-audi-d3": b"Audi_D3",
    "navcd": b"navcd",
}

FIXED_HEADER_MARKERS = {
    "dbinfo-header": b"!dbinfo0001",
    "dbinfo-footer": b"!enddbinfo",
    "skip-db-update": b"skip_db update",
    "model-audi-d3": b"Audi_D3",
    "navcd": b"navcd",
    "release-family-ehe721": b"EHE721",
}

FIXED_FIRMWARE_FORMAT_MARKERS = {
    "fldb-magic": b"FLDB",
    "dbinfo-header": b"!dbinfo0001",
    "release-family-ehe721": b"EHE721",
    "xac-suffix-lower": b".xac",
    "xac-suffix-upper": b".XAC",
}

_TIMESTAMP14 = re.compile(rb"20\d{12}")


@dataclass(frozen=True)
class FLDBRecord:
    """One private record used for aggregate validation only."""

    ordinal: int
    offset: int
    size: int
    name: str
    suffix_class: str
    opaque_field_bytes: bytes


def _parse_iso_datetime(raw: bytes) -> dict[str, object] | None:
    if len(raw) != 17 or raw[:16] == b"0" * 16:
        return None
    try:
        local = datetime.strptime(raw[:16].decode("ascii"), "%Y%m%d%H%M%S%f")
    except (UnicodeDecodeError, ValueError):
        return None
    signed_quarters = raw[16] if raw[16] < 128 else raw[16] - 256
    offset_minutes = signed_quarters * 15
    local_zone = timezone(timedelta(minutes=offset_minutes))
    aware = local.replace(tzinfo=local_zone)
    return {
        "local": aware.isoformat(),
        "utc": aware.astimezone(timezone.utc).isoformat(),
        "utc_offset_minutes": offset_minutes,
    }


def _parse_volume_identifier(value: str) -> dict[str, object]:
    parsed = None
    if re.fullmatch(r"\d{8}_\d{6}", value):
        try:
            parsed = datetime.strptime(value, "%Y%m%d_%H%M%S").isoformat()
        except ValueError:
            parsed = None
    return {
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "pattern": "YYYYMMDD_HHMMSS" if parsed else "UNCLASSIFIED",
        "parsed_local_timestamp": parsed,
        "raw_identifier_included": False,
    }


def _application_marker(value: str) -> str:
    if "ULTRAISO" in value.upper():
        return "ULTRAISO_AUTHORING_FAMILY"
    return "UNRECOGNIZED"


def _outer_suffix_class(path: str) -> str:
    name = PurePosixPath(path).name.lower()
    if name.endswith(".db_"):
        return "db-underscore"
    if name.endswith(".db"):
        return "db"
    return "other"


def _internal_suffix_class(name: str) -> str:
    suffix = PurePosixPath(name).suffix.lower().lstrip(".")
    return f"suffix-{suffix}" if suffix in KNOWN_INTERNAL_SUFFIXES else "suffix-other"


def _container_profile(suffix_counts: Counter[str]) -> str:
    keys = set(suffix_counts)
    if "suffix-xac" in keys:
        return "map-component-bundle"
    if keys == {"suffix-gdb"}:
        return "single-gdb-payload"
    if keys == {"suffix-sm5"}:
        return "speech-resource-bundle"
    if keys == {"suffix-tlt"}:
        return "location-table-bundle"
    if keys <= {"suffix-xb1c", "suffix-xb7"}:
        return "runtime-update-bundle"
    if keys <= {"suffix-gp4", "suffix-gpa"}:
        return "gps-resource-single"
    return "unclassified"


def _scan_fixed_markers(chunks, markers: dict[str, bytes]) -> dict[str, int]:
    maximum = max(len(marker) for marker in markers.values())
    tail = b""
    seen: dict[str, set[int]] = {marker_id: set() for marker_id in markers}
    for chunk_offset, chunk in chunks:
        combined = tail + chunk
        base = chunk_offset - len(tail)
        for marker_id, marker in markers.items():
            start = 0
            while True:
                index = combined.find(marker, start)
                if index < 0:
                    break
                absolute = base + index
                if absolute >= 0:
                    seen[marker_id].add(absolute)
                start = index + 1
        tail = combined[-(maximum - 1) :] if maximum > 1 else b""
    return {marker_id: len(offsets) for marker_id, offsets in sorted(seen.items())}


def _sample_member_entropy(
    image: ISO9660Image,
    entry: ISOEntry,
    *,
    window_size: int = 64 * 1024,
) -> dict[str, object]:
    if entry.size == 0:
        return {"window_size": 0, "samples": [], "summary": {}}
    length = min(window_size, entry.size)
    maximum_start = entry.size - length
    offsets = sorted(
        {
            0,
            maximum_start // 4,
            maximum_start // 2,
            (maximum_start * 3) // 4,
            maximum_start,
        }
    )
    samples = []
    for offset in offsets:
        data = image.read_entry(entry, offset, length)
        samples.append(
            {
                "offset": offset,
                "length": len(data),
                "entropy": round(shannon_entropy(data), 6),
                "zero_fraction": round(data.count(0) / len(data), 6) if data else 0.0,
            }
        )
    entropies = [sample["entropy"] for sample in samples]
    return {
        "window_size": length,
        "samples": samples,
        "summary": {
            "sample_count": len(samples),
            "minimum": min(entropies),
            "maximum": max(entropies),
            "mean": round(sum(entropies) / len(entropies), 6),
        },
        "payload_bytes_included": False,
    }


def _stream_member_metrics(
    image: ISO9660Image, entry: ISOEntry
) -> dict[str, object]:
    digest = hashlib.sha256()

    def chunks():
        for offset, chunk in image.iter_entry_chunks(entry, chunk_size=8 * 1024 * 1024):
            digest.update(chunk)
            yield offset, chunk

    marker_counts = _scan_fixed_markers(chunks(), FIXED_MEDIA_MARKERS)
    return {
        "sha256": digest.hexdigest(),
        "fixed_marker_counts": marker_counts,
        "raw_marker_offsets_included": False,
    }


def _valid_name_field(raw: bytes) -> tuple[bool, str]:
    name_bytes, separator, padding = raw.partition(b"\x00")
    if not separator:
        padding = b""
    valid = bool(name_bytes) and all(32 <= value < 127 for value in name_bytes)
    valid = valid and all(value == 0 for value in padding)
    return valid, name_bytes.decode("ascii", "replace")


def parse_fldb_container(
    image: ISO9660Image,
    entry: ISOEntry,
    *,
    member_id: str,
) -> tuple[dict[str, object], list[FLDBRecord]]:
    """Validate one outer FLDB header and fixed-width record table."""

    header = image.read_entry(entry, 0, min(0x220, entry.size))
    if len(header) < FLDB_MINIMUM_HEADER:
        raise ValueError(f"{member_id} is too small for an FLDB header")
    directory_offset = int.from_bytes(header[0:4], "little")
    variant = int.from_bytes(header[4:8], "little")
    generated_epoch = int.from_bytes(header[8:12], "little")
    entry_count = int.from_bytes(header[12:16], "little")
    record_size = int.from_bytes(header[16:20], "little")
    magic = header[20:24]
    if magic != FLDB_MAGIC:
        raise ValueError(f"{member_id} does not start with an FLDB header")
    if not (FLDB_MINIMUM_HEADER <= directory_offset <= entry.size):
        raise ValueError(f"{member_id} has an invalid directory offset")
    if record_size < FLDB_RECORD_SIZE or entry_count > 1_000_000:
        raise ValueError(f"{member_id} has an unsupported record table")
    table_size = entry_count * record_size
    if directory_offset + table_size > entry.size:
        raise ValueError(f"{member_id} record table exceeds member bounds")

    table = image.read_entry(entry, directory_offset, table_size)
    records: list[FLDBRecord] = []
    valid_name_count = 0
    normalized_digest = hashlib.sha256()
    for ordinal in range(entry_count):
        raw = table[ordinal * record_size : (ordinal + 1) * record_size]
        payload_offset = int.from_bytes(raw[0:4], "little")
        payload_size = int.from_bytes(raw[4:8], "little")
        valid_name, name = _valid_name_field(raw[8:32])
        valid_name_count += int(valid_name)
        suffix_class = _internal_suffix_class(name)
        opaque = raw[32:36]
        records.append(
            FLDBRecord(
                ordinal=ordinal,
                offset=payload_offset,
                size=payload_size,
                name=name,
                suffix_class=suffix_class,
                opaque_field_bytes=opaque,
            )
        )
        normalized_digest.update(struct.pack("<II", payload_offset, payload_size))
        normalized_digest.update(suffix_class.encode("ascii") + b"\x00")
        normalized_digest.update(opaque)

    physical = sorted(records, key=lambda record: (record.offset, record.ordinal))
    overlap_count = sum(
        left.offset + left.size > right.offset
        for left, right in zip(physical, physical[1:])
    )
    gap_sizes = [
        right.offset - (left.offset + left.size)
        for left, right in zip(physical, physical[1:])
    ]
    aligned_count = sum(record.offset % SECTOR_SIZE == 0 for record in records)
    in_bounds_count = sum(
        0 <= record.offset <= entry.size
        and 0 <= record.size
        and record.offset + record.size <= entry.size
        for record in records
    )
    names = [record.name.casefold() for record in records]
    directory_end = directory_offset + table_size
    expected_first_payload = math.ceil(directory_end / SECTOR_SIZE) * SECTOR_SIZE
    header_padding = physical[0].offset - directory_end if physical else 0
    trailing_padding = (
        entry.size - (physical[-1].offset + physical[-1].size) if physical else 0
    )
    padding_bytes = header_padding + sum(gap_sizes) + trailing_padding
    suffix_counts = Counter(record.suffix_class for record in records)

    metadata = image.read_entry(
        entry,
        FLDB_MINIMUM_HEADER,
        max(0, directory_offset - FLDB_MINIMUM_HEADER),
    )
    metadata_marker_counts = {
        marker_id: metadata.count(marker)
        for marker_id, marker in sorted(FIXED_HEADER_MARKERS.items())
    }

    payload_timestamps: list[datetime] = []
    for record in records:
        head = image.read_entry(entry, record.offset, min(record.size, 4096))
        for match in _TIMESTAMP14.finditer(head):
            try:
                payload_timestamps.append(
                    datetime.strptime(match.group().decode("ascii"), "%Y%m%d%H%M%S")
                )
            except ValueError:
                continue

    try:
        generated = datetime.fromtimestamp(generated_epoch, timezone.utc).isoformat()
        generated_valid = 1990 <= datetime.fromtimestamp(
            generated_epoch, timezone.utc
        ).year <= 2100
    except (OverflowError, OSError, ValueError):
        generated = None
        generated_valid = False

    structure_valid = bool(
        entry_count
        and record_size == FLDB_RECORD_SIZE
        and valid_name_count == entry_count
        and aligned_count == entry_count
        and in_bounds_count == entry_count
        and overlap_count == 0
        and physical
        and physical[0].offset == expected_first_payload
        and padding_bytes >= 0
    )
    return (
        {
            "member_id": member_id,
            "outer_suffix_class": _outer_suffix_class(entry.path),
            "extent_sector": entry.extent,
            "size_bytes": entry.size,
            "header": {
                "magic_id": "FLDB",
                "directory_offset": directory_offset,
                "variant": variant,
                "generated_epoch": generated_epoch,
                "generated_timestamp_utc": generated,
                "generated_timestamp_valid": generated_valid,
                "entry_count": entry_count,
                "record_size": record_size,
            },
            "record_table": {
                "directory_end": directory_end,
                "expected_first_payload_offset": expected_first_payload,
                "first_payload_offset": physical[0].offset if physical else None,
                "valid_name_field_count": valid_name_count,
                "aligned_payload_offset_count": aligned_count,
                "in_bounds_payload_count": in_bounds_count,
                "overlap_count": overlap_count,
                "directory_order_monotonic_by_offset": records == physical,
                "duplicate_casefolded_name_count": len(names) - len(set(names)),
                "internal_payload_bytes": sum(record.size for record in records),
                "padding_bytes": padding_bytes,
                "minimum_inter_payload_gap": min(gap_sizes) if gap_sizes else 0,
                "maximum_inter_payload_gap": max(gap_sizes) if gap_sizes else 0,
                "opaque_nonzero_field_count": sum(
                    record.opaque_field_bytes != b"\x00\x00\x00\x00"
                    for record in records
                ),
                "normalized_sha256": normalized_digest.hexdigest(),
                "suffix_class_counts": dict(sorted(suffix_counts.items())),
                "raw_names_included": False,
                "raw_opaque_fields_included": False,
            },
            "metadata": {
                "fixed_marker_counts": metadata_marker_counts,
                "payload_head_timestamp_count": len(payload_timestamps),
                "payload_head_unique_timestamp_count": len(set(payload_timestamps)),
                "payload_head_minimum_timestamp": (
                    min(payload_timestamps).isoformat() if payload_timestamps else None
                ),
                "payload_head_maximum_timestamp": (
                    max(payload_timestamps).isoformat() if payload_timestamps else None
                ),
                "raw_metadata_included": False,
            },
            "profile": {
                "id": _container_profile(suffix_counts),
                "semantic_status": "PROBABLE_FROM_SUFFIX_FAMILY",
            },
            "structural_status": (
                "CONFIRMED_FLDB_HEADER_AND_FIXED_RECORD_TABLE"
                if structure_valid
                else "PARTIAL_OR_INVALID"
            ),
        },
        records,
    )


def _probe_opaque_integrity_fields(
    image: ISO9660Image,
    entry: ISOEntry,
    records: list[FLDBRecord],
    *,
    maximum_payload_size: int = 32 * 1024 * 1024,
) -> dict[str, object]:
    if not records:
        return {"tested_record_count": 0, "status": "NOT_TESTED"}
    indices = sorted({0, len(records) // 2, len(records) - 1})
    tested = 0
    skipped = 0
    crc_matches = 0
    adler_matches = 0
    for index in indices:
        record = records[index]
        if record.size > maximum_payload_size:
            skipped += 1
            continue
        payload = image.read_entry(entry, record.offset, record.size)
        expected = {
            int.from_bytes(record.opaque_field_bytes, "little"),
            int.from_bytes(record.opaque_field_bytes, "big"),
        }
        tested += 1
        crc_matches += int((zlib.crc32(payload) & 0xFFFFFFFF) in expected)
        adler_matches += int((zlib.adler32(payload) & 0xFFFFFFFF) in expected)
    return {
        "selection": "first-middle-last-record",
        "maximum_payload_size": maximum_payload_size,
        "tested_record_count": tested,
        "skipped_oversize_record_count": skipped,
        "crc32_ieee_match_count": crc_matches,
        "adler32_match_count": adler_matches,
        "status": (
            "COMMON_CHECKSUM_MATCH"
            if crc_matches or adler_matches
            else "OPAQUE_FIELD_COMMON_CHECKSUMS_NOT_CONFIRMED"
        ),
        "raw_fields_or_payloads_included": False,
    }


def _volume_recognition_markers(
    image: ISO9660Image, *, maximum_sector: int = 255
) -> dict[str, int]:
    counts = Counter()
    with image.path.open("rb") as handle:
        for sector in range(16, maximum_sector + 1):
            handle.seek(sector * SECTOR_SIZE)
            data = handle.read(SECTOR_SIZE)
            if len(data) != SECTOR_SIZE:
                break
            identifier = data[1:6]
            if identifier in (b"CD001", b"BEA01", b"NSR02", b"NSR03", b"TEA01"):
                counts[identifier.decode("ascii").lower()] += 1
    return dict(sorted(counts.items()))


def analyze_navigation_media(
    image: ISO9660Image,
    *,
    artifact_id: str,
    expected_sha256: str | None = None,
) -> dict[str, object]:
    """Analyze one navigation medium without extracting any member."""

    artifact_sha256 = image.sha256()
    if expected_sha256 is not None and artifact_sha256 != expected_sha256.lower():
        raise ValueError(
            f"artifact hash mismatch: expected {expected_sha256}, got {artifact_sha256}"
        )
    metadata = image.volume_metadata()
    descriptors = image.descriptors()
    entries = sorted(image.entries(), key=lambda entry: (entry.extent, entry.path))
    files = [entry for entry in entries if not entry.is_directory]
    directories = [entry for entry in entries if entry.is_directory]

    containers = []
    all_records: list[FLDBRecord] = []
    aggregate_suffix_counts: Counter[str] = Counter()
    media_marker_counts: Counter[str] = Counter()
    for index, entry in enumerate(files, start=1):
        member_id = f"member-{index:03d}"
        report, records = parse_fldb_container(image, entry, member_id=member_id)
        stream_metrics = _stream_member_metrics(image, entry)
        report["member_sha256"] = stream_metrics["sha256"]
        report["entropy_samples"] = _sample_member_entropy(image, entry)
        report["integrity_field_probe"] = _probe_opaque_integrity_fields(
            image, entry, records
        )
        report["fixed_marker_counts"] = stream_metrics["fixed_marker_counts"]
        containers.append(report)
        all_records.extend(records)
        aggregate_suffix_counts.update(record.suffix_class for record in records)
        media_marker_counts.update(stream_metrics["fixed_marker_counts"])

    volume_bytes = int(metadata["volume_space_size"]) * int(
        metadata["logical_block_size"]
    )
    contiguous = all(
        left.extent + math.ceil(left.size / SECTOR_SIZE) == right.extent
        for left, right in zip(files, files[1:])
    )
    last_extent_end = (
        files[-1].extent + math.ceil(files[-1].size / SECTOR_SIZE) if files else 0
    )
    descriptor_types = [descriptor.descriptor_type for descriptor in descriptors]
    joliet = any(descriptor.joliet_escape for descriptor in descriptors)
    all_fldb_valid = bool(containers) and all(
        container["structural_status"]
        == "CONFIRMED_FLDB_HEADER_AND_FIXED_RECORD_TABLE"
        for container in containers
    )
    generated_timestamps = [
        container["header"]["generated_timestamp_utc"]
        for container in containers
        if container["header"]["generated_timestamp_valid"]
    ]
    payload_minimums = [
        container["metadata"]["payload_head_minimum_timestamp"]
        for container in containers
        if container["metadata"]["payload_head_minimum_timestamp"]
    ]
    payload_maximums = [
        container["metadata"]["payload_head_maximum_timestamp"]
        for container in containers
        if container["metadata"]["payload_head_maximum_timestamp"]
    ]
    application_marker = _application_marker(str(metadata["application_identifier"]))
    recognition_markers = _volume_recognition_markers(image)
    return {
        "schema": "phoenix-mmi.navigation-media/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "artifact_id": artifact_id,
            "size_bytes": image.path.stat().st_size,
            "sha256": artifact_sha256,
            "hash_verified_against_register": expected_sha256 is not None,
            "local_filename_or_path_included": False,
        },
        "volume": {
            "descriptors": [
                {
                    "sector": descriptor.sector,
                    "type": descriptor.descriptor_type,
                    "identifier": descriptor.identifier,
                    "version": descriptor.version,
                    "joliet_escape": descriptor.joliet_escape,
                }
                for descriptor in descriptors
            ],
            "descriptor_sequence_status": (
                "CONFIRMED_PVD_SVD_TERMINATOR"
                if descriptor_types == [1, 2, 255]
                else "PARTIAL_OR_DIFFERENT"
            ),
            "joliet_status": "CONFIRMED_LEVEL_3_ESCAPE" if joliet else "NOT_DETECTED",
            "logical_block_size": metadata["logical_block_size"],
            "volume_space_blocks": metadata["volume_space_size"],
            "volume_space_bytes": volume_bytes,
            "volume_space_matches_artifact_size": (
                volume_bytes == image.path.stat().st_size
            ),
            "path_table_size": metadata["path_table_size"],
            "file_structure_version": metadata["file_structure_version"],
            "system_identifier_sha256": hashlib.sha256(
                str(metadata["system_identifier"]).encode("utf-8")
            ).hexdigest(),
            "volume_identifier": _parse_volume_identifier(
                str(metadata["volume_identifier"])
            ),
            "application_identifier_marker": application_marker,
            "creation_time": _parse_iso_datetime(metadata["creation_time_raw"]),
            "modification_time": _parse_iso_datetime(
                metadata["modification_time_raw"]
            ),
            "volume_recognition_marker_counts": recognition_markers,
            "udf_status": (
                "NOT_DETECTED_IN_SECTORS_16_255"
                if not any(
                    key in recognition_markers
                    for key in ("bea01", "nsr02", "nsr03", "tea01")
                )
                else "MARKERS_PRESENT"
            ),
            "raw_identifiers_included": False,
        },
        "topology": {
            "root_file_count": len(files),
            "directory_count": len(directories),
            "first_file_extent_sector": files[0].extent if files else None,
            "last_file_end_sector": last_extent_end if files else None,
            "files_are_extent_contiguous": contiguous,
            "files_fill_declared_volume_to_end": (
                last_extent_end == int(metadata["volume_space_size"])
            ),
            "outer_suffix_class_counts": dict(
                sorted(Counter(_outer_suffix_class(entry.path) for entry in files).items())
            ),
            "outer_member_bytes": sum(entry.size for entry in files),
            "iso_overhead_and_sector_padding_bytes": (
                image.path.stat().st_size - sum(entry.size for entry in files)
            ),
            "raw_member_names_included": False,
        },
        "containers": containers,
        "aggregate": {
            "validated_fldb_container_count": sum(
                container["structural_status"].startswith("CONFIRMED")
                for container in containers
            ),
            "internal_record_count": len(all_records),
            "internal_payload_bytes": sum(record.size for record in all_records),
            "suffix_class_counts": dict(sorted(aggregate_suffix_counts.items())),
            "fixed_media_marker_counts": dict(sorted(media_marker_counts.items())),
            "container_generated_minimum_utc": (
                min(generated_timestamps) if generated_timestamps else None
            ),
            "container_generated_maximum_utc": (
                max(generated_timestamps) if generated_timestamps else None
            ),
            "payload_head_timestamp_count": sum(
                container["metadata"]["payload_head_timestamp_count"]
                for container in containers
            ),
            "payload_head_minimum_timestamp": (
                min(payload_minimums) if payload_minimums else None
            ),
            "payload_head_maximum_timestamp": (
                max(payload_maximums) if payload_maximums else None
            ),
        },
        "classification": {
            "optical_filesystem": (
                "CONFIRMED_ISO9660_WITH_JOLIET"
                if descriptor_types == [1, 2, 255] and joliet
                else "PARTIAL"
            ),
            "map_container_format": (
                "CONFIRMED_FLDB_HEADER_AND_FIXED_RECORD_TABLE"
                if all_fldb_valid
                else "PARTIAL"
            ),
            "inner_payload_schema": "PARTIAL_SUFFIX_FAMILIES_ONLY",
            "routeact_filename_bridge": (
                "NOT_FOUND_UNDER_EXACT_ASCII_PROBE"
                if media_marker_counts["routeact-dat-lower"] == 0
                and media_marker_counts["routeact-dat-upper"] == 0
                else "PRESENT"
            ),
            "provenance": (
                "UNVERIFIED_PROVENANCE_ULTRAISO_AUTHORED_IMAGE"
                if application_marker == "ULTRAISO_AUTHORING_FAMILY"
                else "UNVERIFIED_PROVENANCE"
            ),
            "marketed_release_label": "NOT_AUTHENTICATED_FROM_FILENAME",
            "compatibility_with_modified_or_new_maps": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "map_payload_included": False,
            "member_or_internal_names_included": False,
            "raw_metadata_strings_included": False,
            "raw_opaque_fields_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def probe_firmware_media_markers(reader: BinaryReader) -> dict[str, object]:
    """Count only fixed format markers in one principal image."""

    return {
        "artifact_sha256": reader.sha256(),
        "marker_counts": {
            marker_id: len(reader.find_all(marker))
            for marker_id, marker in sorted(FIXED_FIRMWARE_FORMAT_MARKERS.items())
        },
        "raw_strings_or_offsets_included": False,
    }


def correlate_firmware_and_media(
    firmware_contract: dict[str, object],
    media_report: dict[str, object],
    firmware_probes: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Join independently confirmed layers without inventing a parser edge."""

    no_firmware_format_markers = all(
        all(count == 0 for count in probe["marker_counts"].values())
        for probe in firmware_probes.values()
    )
    routeact_absent = (
        media_report["classification"]["routeact_filename_bridge"]
        == "NOT_FOUND_UNDER_EXACT_ASCII_PROBE"
    )
    comparison = {
        "schema": "phoenix-mmi.firmware-media-contract/v1",
        "analysis_mode": "read-only-static",
        "firmware": {
            "navigation_data_lifecycle": firmware_contract["classification"][
                "navigation_data_lifecycle"
            ],
            "optical_service_contract": firmware_contract["classification"][
                "optical_service_contract"
            ],
            "navigation_to_optical_direct_edge": firmware_contract["classification"][
                "navigation_to_optical_direct_edge"
            ],
            "fixed_format_marker_probes": copy.deepcopy(firmware_probes),
        },
        "media": {
            "optical_filesystem": media_report["classification"]["optical_filesystem"],
            "map_container_format": media_report["classification"][
                "map_container_format"
            ],
            "inner_payload_schema": media_report["classification"][
                "inner_payload_schema"
            ],
            "routeact_filename_bridge": media_report["classification"][
                "routeact_filename_bridge"
            ],
        },
        "correlation": {
            "filesystem_layer": "PROBABLE_FIRMWARE_MEDIA_COMPATIBILITY",
            "fldb_consumer_edge": (
                "NOT_FOUND_UNDER_FIXED_LEXICAL_PROBES"
                if no_firmware_format_markers
                else "MARKER_PRESENT_REQUIRES_REVIEW"
            ),
            "routeact_media_edge": (
                "NOT_FOUND_UNDER_EXACT_ASCII_PROBE"
                if routeact_absent
                else "MARKER_PRESENT_REQUIRES_REVIEW"
            ),
            "sector_read_abi": "OPEN",
            "inner_payload_consumer": "OPEN",
            "dynamic_compatibility": "NOT_ESTABLISHED",
        },
        "interpretation": (
            "The medium independently confirms an ISO-9660/Joliet layer and FLDB "
            "record containers. Firmware independently confirms optical-service "
            "structures. No fixed lexical bridge identifies the FLDB parser, route-data "
            "consumer or sector-read ABI, so the end-to-end runtime edge remains open."
        ),
        "publication_safety": copy.deepcopy(media_report["publication_safety"]),
    }
    comparison["operational_graph"] = update_operational_graph_v4(
        firmware_contract["operational_graph"], comparison
    )
    return comparison


def update_operational_graph_v4(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    """Add confirmed medium layers while preserving parser/runtime gaps."""

    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v4"
    map_node = next(node for node in graph["nodes"] if node["id"] == "map-media-format")
    map_node.update(
        {
            "label": "Navigation medium outer format and unresolved payload schemas",
            "status": "PARTIAL_CONFIRMED_OUTER_FORMAT",
            "filesystem_status": "CONFIRMED_ISO9660_WITH_JOLIET",
            "container_status": "CONFIRMED_FLDB_HEADER_AND_FIXED_RECORD_TABLE",
            "inner_payload_schema": "OPEN",
            "provenance_status": "UNVERIFIED",
            "evidence": ["S011-01", "S011-02", "RQ-022", "RQ-029"],
        }
    )
    graph["nodes"].extend(
        (
            {
                "id": "navigation-optical-volume",
                "label": "ISO-9660/Joliet navigation volume",
                "status": "CONFIRMED_MEDIA_STRUCTURE",
                "evidence": ["S011-01"],
            },
            {
                "id": "fldb-container-set",
                "label": "FLDB header and fixed-record container set",
                "status": "CONFIRMED_MEDIA_STRUCTURE",
                "payload_schema": "OPEN",
                "evidence": ["S011-02", "S011-03"],
            },
            {
                "id": "media-build-timeline",
                "label": "Payload, container and ISO authoring timeline",
                "status": "CONFIRMED_METADATA_TIMELINE",
                "provenance": "UNVERIFIED",
                "evidence": ["S011-04"],
            },
        )
    )
    graph["edges"].extend(
        (
            {
                "source": "optical-volume-reader",
                "target": "navigation-optical-volume",
                "relation": "filesystem-level compatibility is structurally plausible",
                "status": "PROBABLE",
            },
            {
                "source": "navigation-optical-volume",
                "target": "fldb-container-set",
                "relation": "stores seven validated FLDB containers",
                "status": "CONFIRMED_MEDIA_LAYOUT",
            },
            {
                "source": "fldb-container-set",
                "target": "navigation-runtime",
                "relation": "parser and payload consumer are unresolved",
                "status": "HYPOTHESIS",
            },
            {
                "source": "media-build-timeline",
                "target": "navigation-optical-volume",
                "relation": "describes local artifact authoring metadata",
                "status": "CONFIRMED_METADATA_RELATION",
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
        "Session 011 confirms the physical ISO/Joliet and FLDB container layers. "
        "The firmware parser edge, sector ABI, inner payload schemas, provenance and "
        "modified-map compatibility remain unresolved."
    )
    return graph


def build_public_navigation_media_report(
    report: dict[str, object]
) -> dict[str, object]:
    """Return the already sanitized report through a defensive copy."""

    return copy.deepcopy(report)

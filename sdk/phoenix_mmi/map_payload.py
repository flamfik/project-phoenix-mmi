"""Publication-safe inner navigation-payload structure analysis.

The analyzer reads bounded payload prefixes directly from ISO extents.  It
validates proprietary family signatures, directory grammars and anonymous
cross-family partition relationships without returning internal names, source
bytes or metadata values.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import hashlib
from pathlib import PurePosixPath
import re
import zlib

from .entropy import shannon_entropy
from .iso9660 import ISO9660Image
from .map_media import FLDBRecord, parse_fldb_container


_FAMILY_SIGNATURES: dict[str, tuple[str, bytes]] = {
    "suffix-b": ("verysmart-xac-b-directory", b"VERYSMART XAC HD"),
    "suffix-gdb": ("deadbeef-gdb", b"\xde\xad\xbe\xef"),
    "suffix-gp4": ("gps3-gp4", b"GPS3"),
    "suffix-gpa": ("gps3-gpa", b"GPS3"),
    "suffix-ort": ("place-name-index", b"ORTSNAMEN       "),
    "suffix-plz": ("postal-code-index", b"GR POSTLEITZAHL "),
    "suffix-poi": ("global-poi-index", b"GLOBAL POIS     "),
    "suffix-ras": ("raster-info", b"DB RASTERINFOS  "),
    "suffix-sm5": ("speech-index-data", b"_type_"),
    "suffix-tlt": ("traffic-location-table", b"TMC-LOC-TABLE BR"),
    "suffix-v": ("verysmart-xac-v-directory", b"VERYSMART XAC HD"),
    "suffix-xac": ("xac-tile", b"XAC HEADER      "),
    "suffix-xah": ("xac-database-header", b"XACDB HEADER    "),
}

_STANDARD_START_SIGNATURES: dict[str, bytes] = {
    "elf": b"\x7fELF",
    "gzip": b"\x1f\x8b\x08",
    "sqlite3": b"SQLite format 3\x00",
    "xz": b"\xfd7zXZ\x00",
    "zip": b"PK\x03\x04",
}

_TIMESTAMP14 = re.compile(rb"20\d{12}")
_SIZE_OF_INDEX = re.compile(rb"_size_of_index_\s+(\d+)")
_SIZE_OF_DATA = re.compile(rb"_size_of_data_\s+(\d+)")
_NUMERIC_TAIL = re.compile(rb".*?\s+(\d+)\s+(\d+)$")
_DIGIT_GROUP = re.compile(r"\d+")


def _masked_update_signature(data: bytes) -> bool:
    return (
        len(data) >= 4
        and data[0] == 0xE5
        and data[1] == 0x42
        and data[3] == 0x30
    )


def _signature_id(suffix_class: str, data: bytes) -> tuple[str, bool]:
    if suffix_class in {"suffix-xb1c", "suffix-xb7"}:
        return "update-image-code-header", _masked_update_signature(data)
    signature = _FAMILY_SIGNATURES.get(suffix_class)
    if signature is None:
        return "unclassified", False
    signature_id, magic = signature
    return signature_id, data.startswith(magic)


def _standard_start_signature(data: bytes) -> str | None:
    for signature_id, magic in sorted(_STANDARD_START_SIGNATURES.items()):
        if data.startswith(magic):
            return signature_id
    return None


def _parse_verysmart_directory(
    data: bytes, *, size: int, suffix_class: str
) -> dict[str, object]:
    stride = 16 if suffix_class == "suffix-b" else 12
    if len(data) < 24:
        return {"status": "TRUNCATED"}
    directory_length = int.from_bytes(data[16:20], "big")
    version = data[21]
    record_count = int.from_bytes(data[22:24], "big")
    table_end = 24 + record_count * stride
    if table_end > len(data):
        return {
            "status": "BOUNDED_PREFIX_TOO_SHORT",
            "record_stride": stride,
            "record_count": record_count,
        }
    records = []
    for ordinal in range(record_count):
        raw = data[24 + ordinal * stride : 24 + (ordinal + 1) * stride]
        records.append(
            {
                "tag": int.from_bytes(raw[0:4], "big"),
                "offset": int.from_bytes(raw[4:8], "big"),
                "size": int.from_bytes(raw[8:12], "big"),
            }
        )
    monotonic = all(
        int(left["offset"]) <= int(right["offset"])
        for left, right in zip(records, records[1:])
    )
    nonoverlap = all(
        int(left["offset"]) + int(left["size"]) <= int(right["offset"])
        for left, right in zip(records, records[1:])
    )
    in_bounds = all(
        int(record["offset"]) + int(record["size"]) <= size
        for record in records
    )
    first_after_table = bool(records) and int(records[0]["offset"]) >= table_end
    structure_valid = bool(
        record_count
        and version == 1
        and directory_length == 4 + record_count * stride
        and monotonic
        and nonoverlap
        and in_bounds
        and first_after_table
    )
    return {
        "status": (
            "CONFIRMED_BIG_ENDIAN_FIXED_RECORD_DIRECTORY"
            if structure_valid
            else "PARTIAL_OR_INVALID"
        ),
        "version": version,
        "record_stride": stride,
        "record_count": record_count,
        "directory_length": directory_length,
        "directory_length_formula_matches": (
            directory_length == 4 + record_count * stride
        ),
        "offsets_monotonic": monotonic,
        "ranges_nonoverlapping": nonoverlap,
        "ranges_in_bounds": in_bounds,
        "first_payload_after_table": first_after_table,
        "raw_tags_or_records_included": False,
    }


def _parse_speech_index(data: bytes, *, size: int) -> dict[str, object]:
    index_match = _SIZE_OF_INDEX.search(data[:1024])
    payload_match = _SIZE_OF_DATA.search(data[:1024])
    if index_match is None or payload_match is None:
        return {"status": "DECLARED_SPLIT_NOT_FOUND"}
    index_size = int(index_match.group(1))
    payload_size = int(payload_match.group(1))
    if not 0 < index_size <= len(data):
        return {
            "status": "BOUNDED_PREFIX_TOO_SHORT",
            "declared_index_size": index_size,
            "declared_data_size": payload_size,
        }
    lines = data[:index_size].splitlines()
    metadata_lines = sum(line.startswith(b"_") for line in lines)
    numeric_rows = []
    for line in lines:
        match = _NUMERIC_TAIL.fullmatch(line)
        if match is not None:
            numeric_rows.append((int(match.group(1)), int(match.group(2))))
    numeric_rows_in_bounds = sum(
        offset + length <= payload_size for offset, length in numeric_rows
    )
    structure_valid = bool(
        index_size + payload_size == size
        and metadata_lines >= 5
        and numeric_rows
        and numeric_rows_in_bounds == len(numeric_rows)
    )
    return {
        "status": (
            "CONFIRMED_DECLARED_TEXT_INDEX_AND_BINARY_DATA_SPLIT"
            if structure_valid
            else "PARTIAL_OR_INVALID"
        ),
        "declared_index_size": index_size,
        "declared_data_size": payload_size,
        "declared_sizes_match_payload_size": index_size + payload_size == size,
        "index_line_count": len(lines),
        "metadata_line_count": metadata_lines,
        "numeric_reference_row_count": len(numeric_rows),
        "numeric_reference_rows_in_bounds": numeric_rows_in_bounds,
        "raw_lexicon_or_metadata_included": False,
    }


def classify_payload_header(
    suffix_class: str, data: bytes, *, size: int
) -> dict[str, object]:
    """Classify one bounded prefix without returning source bytes."""

    signature_id, signature_valid = _signature_id(suffix_class, data)
    result: dict[str, object] = {
        "signature_id": signature_id,
        "signature_status": "CONFIRMED_AT_OFFSET_ZERO" if signature_valid else "MISMATCH",
        "standard_start_signature": _standard_start_signature(data),
        "bounded_prefix_length": len(data),
        "bounded_prefix_sha256": hashlib.sha256(data).hexdigest(),
        "bounded_prefix_entropy": round(shannon_entropy(data), 6) if data else 0.0,
        "raw_header_or_metadata_included": False,
    }
    if suffix_class in {"suffix-b", "suffix-v"}:
        result["internal_directory"] = _parse_verysmart_directory(
            data, size=size, suffix_class=suffix_class
        )
    elif suffix_class == "suffix-sm5":
        result["speech_index"] = _parse_speech_index(data, size=size)
    elif suffix_class == "suffix-xac" and len(data) >= 182:
        header_size = int.from_bytes(data[16:20], "big")
        first_timestamp_valid = bool(_TIMESTAMP14.fullmatch(data[44:58]))
        second_timestamp_valid = bool(_TIMESTAMP14.fullmatch(data[60:74]))
        subrecord_type = (
            int.from_bytes(data[header_size : header_size + 4], "big")
            if header_size + 6 <= len(data)
            else None
        )
        partition_id = (
            int.from_bytes(data[header_size + 4 : header_size + 6], "big")
            if header_size + 6 <= len(data)
            else None
        )
        result["xac_header"] = {
            "header_size": header_size,
            "header_size_status": (
                "CONFIRMED_FIXED_176_BYTES" if header_size == 176 else "UNEXPECTED"
            ),
            "timestamp_field_count": int(first_timestamp_valid)
            + int(second_timestamp_valid),
            "subrecord_type": subrecord_type,
            "partition_id": partition_id,
            "partition_id_in_expected_range": (
                partition_id is not None and 0 <= partition_id <= 15
            ),
            "raw_timestamps_or_identifiers_included": False,
        }
    elif suffix_class in {"suffix-ort", "suffix-plz", "suffix-poi", "suffix-ras"}:
        declared = int.from_bytes(data[16:20], "big") if len(data) >= 20 else None
        result["length_model"] = {
            "field_offset": 16,
            "byte_order": "big",
            "declared_length": declared,
            "matches_payload_size_minus_20": declared == size - 20,
        }
    elif suffix_class == "suffix-xah":
        header_size = int.from_bytes(data[16:20], "big") if len(data) >= 20 else None
        result["header_size_model"] = {
            "field_offset": 16,
            "byte_order": "big",
            "header_size": header_size,
            "matches_bounded_subrecord_start": header_size == 140,
        }
    elif suffix_class == "suffix-gdb":
        header_size = int.from_bytes(data[4:8], "big") if len(data) >= 8 else None
        result["header_size_model"] = {
            "field_offset": 4,
            "byte_order": "big",
            "header_size": header_size,
            "matches_bounded_subrecord_start": header_size == 32,
        }
    elif suffix_class in {"suffix-xb1c", "suffix-xb7"}:
        declared = int.from_bytes(data[4:8], "big") if len(data) >= 8 else None
        result["length_model"] = {
            "field_offset": 4,
            "byte_order": "big",
            "declared_length": declared,
            "matches_payload_size": declared == size,
        }
    return result


def _name_hash_probe(record: FLDBRecord) -> dict[str, int]:
    expected = {
        int.from_bytes(record.opaque_field_bytes, "little"),
        int.from_bytes(record.opaque_field_bytes, "big"),
    }
    forms = {
        "raw": record.name.encode("ascii"),
        "lower": record.name.lower().encode("ascii"),
        "upper": record.name.upper().encode("ascii"),
        "field24": record.name.encode("ascii").ljust(24, b"\x00"),
    }
    matches: dict[str, int] = {}
    for form_id, value in forms.items():
        matches[f"crc32-{form_id}"] = int((zlib.crc32(value) & 0xFFFFFFFF) in expected)
        matches[f"adler32-{form_id}"] = int(
            (zlib.adler32(value) & 0xFFFFFFFF) in expected
        )
    structural = {
        "payload-offset": record.offset,
        "payload-size": record.size,
        "payload-end": record.offset + record.size,
        "ordinal": record.ordinal,
    }
    for field_id, value in structural.items():
        matches[field_id] = int(value in expected)
    return matches


def _numeric_groups(name: str) -> tuple[int, ...]:
    stem = PurePosixPath(name).stem
    return tuple(int(value) for value in _DIGIT_GROUP.findall(stem))


def analyze_navigation_payloads(
    image: ISO9660Image,
    *,
    artifact_id: str,
    expected_sha256: str | None = None,
    prefix_limit: int = 64 * 1024,
) -> dict[str, object]:
    """Analyze all FLDB payload families without extracting them."""

    actual_sha256 = image.sha256()
    if expected_sha256 is not None and actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"artifact hash mismatch: expected {expected_sha256}, got {actual_sha256}"
        )
    entries = sorted(
        (entry for entry in image.entries() if not entry.is_directory),
        key=lambda entry: (entry.extent, entry.path),
    )
    families: dict[str, list[dict[str, object]]] = defaultdict(list)
    stems: dict[str, set[str]] = defaultdict(set)
    numeric_names: dict[str, list[tuple[int, ...]]] = defaultdict(list)
    xac_partitions: Counter[int] = Counter()
    opaque_probe_totals: Counter[str] = Counter()
    opaque_values: set[bytes] = set()
    opaque_zero_count = 0
    total_records = 0
    for member_index, entry in enumerate(entries, start=1):
        _, records = parse_fldb_container(
            image, entry, member_id=f"member-{member_index:03d}"
        )
        for record in records:
            total_records += 1
            prefix = image.read_entry(
                entry, record.offset, min(record.size, prefix_limit)
            )
            classified = classify_payload_header(
                record.suffix_class, prefix, size=record.size
            )
            families[record.suffix_class].append(
                {"size": record.size, "header": classified}
            )
            stem = PurePosixPath(record.name).stem.casefold()
            stems[record.suffix_class].add(stem)
            numeric_names[record.suffix_class].append(_numeric_groups(record.name))
            xac_header = classified.get("xac_header")
            if isinstance(xac_header, dict):
                partition_id = xac_header.get("partition_id")
                if isinstance(partition_id, int):
                    xac_partitions[partition_id] += 1
            opaque_probe_totals.update(_name_hash_probe(record))
            opaque_values.add(record.opaque_field_bytes)
            opaque_zero_count += int(not any(record.opaque_field_bytes))

    family_reports = []
    for suffix_class, rows in sorted(families.items()):
        sizes = [int(row["size"]) for row in rows]
        headers = [row["header"] for row in rows]
        signature_ids = Counter(str(header["signature_id"]) for header in headers)
        signature_matches = sum(
            header["signature_status"] == "CONFIRMED_AT_OFFSET_ZERO"
            for header in headers
        )
        standard_starts = Counter(
            str(header["standard_start_signature"])
            for header in headers
            if header["standard_start_signature"] is not None
        )
        directory_statuses = Counter(
            str(header["internal_directory"]["status"])
            for header in headers
            if "internal_directory" in header
        )
        speech_statuses = Counter(
            str(header["speech_index"]["status"])
            for header in headers
            if "speech_index" in header
        )
        length_matches = [
            bool(header["length_model"].get("matches_payload_size_minus_20"))
            or bool(header["length_model"].get("matches_payload_size"))
            for header in headers
            if "length_model" in header
        ]
        directories = [
            header["internal_directory"]
            for header in headers
            if "internal_directory" in header
        ]
        speech_indexes = [
            header["speech_index"]
            for header in headers
            if "speech_index" in header
        ]
        xac_headers = [
            header["xac_header"] for header in headers if "xac_header" in header
        ]
        header_size_models = [
            header["header_size_model"]
            for header in headers
            if "header_size_model" in header
        ]
        family_reports.append(
            {
                "suffix_class": suffix_class,
                "record_count": len(rows),
                "minimum_size": min(sizes),
                "maximum_size": max(sizes),
                "unique_size_count": len(set(sizes)),
                "signature_ids": dict(sorted(signature_ids.items())),
                "signature_match_count": signature_matches,
                "signature_status": (
                    "CONFIRMED_FAMILY_SIGNATURE_AT_OFFSET_ZERO"
                    if signature_matches == len(rows)
                    else "PARTIAL"
                ),
                "unique_bounded_prefix_hash_count": len(
                    {str(header["bounded_prefix_sha256"]) for header in headers}
                ),
                "standard_start_signature_counts": dict(sorted(standard_starts.items())),
                "internal_directory_status_counts": dict(
                    sorted(directory_statuses.items())
                ),
                "speech_index_status_counts": dict(sorted(speech_statuses.items())),
                "length_model_match_count": sum(length_matches),
                "internal_directory_summary": (
                    {
                        "record_stride_values": sorted(
                            {
                                int(item["record_stride"])
                                for item in directories
                                if "record_stride" in item
                            }
                        ),
                        "minimum_record_count": min(
                            int(item["record_count"]) for item in directories
                        ),
                        "maximum_record_count": max(
                            int(item["record_count"]) for item in directories
                        ),
                        "unique_record_count_count": len(
                            {int(item["record_count"]) for item in directories}
                        ),
                        "all_directory_length_formulas_match": all(
                            bool(item["directory_length_formula_matches"])
                            for item in directories
                        ),
                        "all_ranges_in_bounds_nonoverlapping_and_ordered": all(
                            bool(item["offsets_monotonic"])
                            and bool(item["ranges_nonoverlapping"])
                            and bool(item["ranges_in_bounds"])
                            and bool(item["first_payload_after_table"])
                            for item in directories
                        ),
                    }
                    if directories
                    else None
                ),
                "speech_index_summary": (
                    {
                        "minimum_index_line_count": min(
                            int(item["index_line_count"]) for item in speech_indexes
                        ),
                        "maximum_index_line_count": max(
                            int(item["index_line_count"]) for item in speech_indexes
                        ),
                        "minimum_numeric_reference_row_count": min(
                            int(item["numeric_reference_row_count"])
                            for item in speech_indexes
                        ),
                        "maximum_numeric_reference_row_count": max(
                            int(item["numeric_reference_row_count"])
                            for item in speech_indexes
                        ),
                        "all_declared_sizes_match": all(
                            bool(item["declared_sizes_match_payload_size"])
                            for item in speech_indexes
                        ),
                        "all_numeric_references_in_bounds": all(
                            int(item["numeric_reference_row_count"])
                            == int(item["numeric_reference_rows_in_bounds"])
                            for item in speech_indexes
                        ),
                    }
                    if speech_indexes
                    else None
                ),
                "xac_header_summary": (
                    {
                        "fixed_header_size_match_count": sum(
                            item["header_size_status"] == "CONFIRMED_FIXED_176_BYTES"
                            for item in xac_headers
                        ),
                        "two_timestamp_field_count": sum(
                            int(item["timestamp_field_count"]) == 2
                            for item in xac_headers
                        ),
                        "subrecord_type_values": sorted(
                            {
                                int(item["subrecord_type"])
                                for item in xac_headers
                                if isinstance(item["subrecord_type"], int)
                            }
                        ),
                        "partition_id_in_expected_range_count": sum(
                            bool(item["partition_id_in_expected_range"])
                            for item in xac_headers
                        ),
                    }
                    if xac_headers
                    else None
                ),
                "header_size_model_summary": (
                    {
                        "observed_header_sizes": sorted(
                            {
                                int(item["header_size"])
                                for item in header_size_models
                                if isinstance(item["header_size"], int)
                            }
                        ),
                        "model_match_count": sum(
                            bool(item["matches_bounded_subrecord_start"])
                            for item in header_size_models
                        ),
                    }
                    if header_size_models
                    else None
                ),
                "raw_names_headers_or_payloads_included": False,
            }
        )

    overlap_counts = []
    suffixes = sorted(stems)
    for left_index, left in enumerate(suffixes):
        for right in suffixes[left_index + 1 :]:
            count = len(stems[left] & stems[right])
            if count:
                overlap_counts.append(
                    {"left_suffix": left, "right_suffix": right, "count": count}
                )

    triplet_sets = {
        suffix: {
            groups[-1]
            for groups in numeric_names[suffix]
            if groups
        }
        for suffix in ("suffix-ort", "suffix-plz", "suffix-poi")
    }
    level_sets: dict[str, set[tuple[int, int]]] = {}
    singleton_counts: dict[str, int] = {}
    for suffix in ("suffix-b", "suffix-v"):
        pairs = {
            (groups[-2], groups[-1])
            for groups in numeric_names[suffix]
            if len(groups) >= 3
        }
        level_sets[suffix] = pairs
        singleton_counts[suffix] = sum(
            len(groups) < 3 for groups in numeric_names[suffix]
        )
    expected_partitions = set(range(16))
    expected_levels = {(partition, level) for partition in range(16) for level in (3, 4)}
    partition_graph_confirmed = bool(
        set(xac_partitions) == expected_partitions
        and all(values == expected_partitions for values in triplet_sets.values())
        and all(values == expected_levels for values in level_sets.values())
    )
    opaque_matches = {
        probe_id: count
        for probe_id, count in sorted(opaque_probe_totals.items())
        if count
    }
    return {
        "schema": "phoenix-mmi.navigation-payload-families/v1",
        "analysis_mode": "read-only-static-bounded-prefixes",
        "artifact": {
            "artifact_id": artifact_id,
            "size_bytes": image.path.stat().st_size,
            "sha256": actual_sha256,
            "hash_verified_against_register": expected_sha256 is not None,
            "local_filename_or_path_included": False,
        },
        "bounded_prefix_limit": prefix_limit,
        "families": family_reports,
        "aggregate": {
            "payload_record_count": total_records,
            "family_count": len(family_reports),
            "all_records_match_declared_family_signature": all(
                report["signature_match_count"] == report["record_count"]
                for report in family_reports
            ),
            "standard_start_signature_match_count": sum(
                sum(report["standard_start_signature_counts"].values())
                for report in family_reports
            ),
        },
        "partition_topology": {
            "partition_id_minimum": min(xac_partitions) if xac_partitions else None,
            "partition_id_maximum": max(xac_partitions) if xac_partitions else None,
            "partition_count": len(xac_partitions),
            "xac_records_by_partition": {
                f"partition-{partition:02d}": count
                for partition, count in sorted(xac_partitions.items())
            },
            "complete_triplet_partition_sets": {
                suffix: values == expected_partitions
                for suffix, values in sorted(triplet_sets.items())
            },
            "complete_two_level_partition_sets": {
                suffix: values == expected_levels
                for suffix, values in sorted(level_sets.items())
            },
            "unpaired_singleton_counts": dict(sorted(singleton_counts.items())),
            "exact_stem_overlap_counts": overlap_counts,
            "status": (
                "CONFIRMED_CROSS_FAMILY_16_PARTITION_TOPOLOGY"
                if partition_graph_confirmed
                else "PARTIAL"
            ),
            "raw_names_or_partition_labels_included": False,
        },
        "opaque_field_probe": {
            "record_count": total_records,
            "unique_opaque_field_count": len(opaque_values),
            "zero_value_count": opaque_zero_count,
            "nonzero_value_count": total_records - opaque_zero_count,
            "tested_models": sorted(opaque_probe_totals),
            "nonzero_match_counts": opaque_matches,
            "status": (
                "COMMON_NAME_HASH_AND_STRUCTURAL_MODELS_NOT_CONFIRMED"
                if not opaque_matches
                else "MODEL_MATCH_REQUIRES_REVIEW"
            ),
            "raw_opaque_fields_included": False,
        },
        "classification": {
            "inner_payload_schema": "PARTIAL_PROPRIETARY_FAMILY_HEADERS_AND_DIRECTORIES",
            "partition_model": (
                "CONFIRMED_CROSS_FAMILY_16_PARTITION_TOPOLOGY"
                if partition_graph_confirmed
                else "PARTIAL"
            ),
            "speech_payload_model": (
                "CONFIRMED_DECLARED_TEXT_INDEX_AND_BINARY_DATA_SPLIT"
                if all(
                    report["speech_index_status_counts"].get(
                        "CONFIRMED_DECLARED_TEXT_INDEX_AND_BINARY_DATA_SPLIT", 0
                    )
                    == report["record_count"]
                    for report in family_reports
                    if report["suffix_class"] == "suffix-sm5"
                )
                else "PARTIAL"
            ),
            "routing_or_coordinate_encoding": "OPEN",
            "compatibility_with_modified_or_new_maps": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "payload_bytes_included": False,
            "member_or_internal_names_included": False,
            "raw_headers_or_metadata_included": False,
            "raw_opaque_fields_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def build_public_navigation_payload_report(
    report: dict[str, object]
) -> dict[str, object]:
    """Return a defensive copy of the publication-safe report."""

    return copy.deepcopy(report)

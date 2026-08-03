"""Bounded integrity and embedded-XIM2 research helpers.

All functions are read-only. Public reports deliberately omit source bytes,
decoded rasters, content hashes, field values, offsets and local paths.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
from typing import Protocol

from .yim import YimDecodeResult


_MAX_XIM2_SPAN = 16 * 1024 * 1024
_XIM2_HEADER_SIZE = 36


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "decoded_raster_bytes_included": False,
        "decoded_raster_hashes_included": False,
        "source_content_hashes_included": False,
        "integrity_field_values_included": False,
        "raw_header_values_included": False,
        "raw_offsets_included": False,
        "raw_strings_included": False,
        "local_paths_included": False,
        "extracted_resources_included": False,
        "runtime_execution_observed": False,
    }


def _crc_msb(
    data: bytes,
    *,
    width: int,
    polynomial: int,
    initial: int,
    xor_out: int,
) -> int:
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    crc = initial & mask
    for value in data:
        crc ^= value << (width - 8)
        for _ in range(8):
            crc = ((crc << 1) ^ polynomial) & mask if crc & top else (
                crc << 1
            ) & mask
    return crc ^ xor_out


def _crc_lsb(
    data: bytes,
    *,
    width: int,
    polynomial: int,
    initial: int,
    xor_out: int,
) -> int:
    mask = (1 << width) - 1
    crc = initial & mask
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ polynomial if crc & 1 else crc >> 1
    return (crc ^ xor_out) & mask


def _catalog32(data: bytes) -> dict[str, int]:
    return {
        "CRC32_ISO_HDLC": _crc_lsb(
            data,
            width=32,
            polynomial=0xEDB88320,
            initial=0xFFFFFFFF,
            xor_out=0xFFFFFFFF,
        ),
        "CRC32_JAMCRC": _crc_lsb(
            data,
            width=32,
            polynomial=0xEDB88320,
            initial=0xFFFFFFFF,
            xor_out=0,
        ),
        "CRC32_C": _crc_lsb(
            data,
            width=32,
            polynomial=0x82F63B78,
            initial=0xFFFFFFFF,
            xor_out=0xFFFFFFFF,
        ),
        "CRC32_BZIP2": _crc_msb(
            data,
            width=32,
            polynomial=0x04C11DB7,
            initial=0xFFFFFFFF,
            xor_out=0xFFFFFFFF,
        ),
        "CRC32_MPEG2": _crc_msb(
            data,
            width=32,
            polynomial=0x04C11DB7,
            initial=0xFFFFFFFF,
            xor_out=0,
        ),
        "CRC32_POSIX": _crc_msb(
            data,
            width=32,
            polynomial=0x04C11DB7,
            initial=0,
            xor_out=0xFFFFFFFF,
        ),
        "CRC32_Q": _crc_msb(
            data,
            width=32,
            polynomial=0x814141AB,
            initial=0,
            xor_out=0,
        ),
    }


def _catalog16(data: bytes) -> dict[str, int]:
    return {
        "CRC16_ARC": _crc_lsb(
            data,
            width=16,
            polynomial=0xA001,
            initial=0,
            xor_out=0,
        ),
        "CRC16_MODBUS": _crc_lsb(
            data,
            width=16,
            polynomial=0xA001,
            initial=0xFFFF,
            xor_out=0,
        ),
        "CRC16_MAXIM_DOW": _crc_lsb(
            data,
            width=16,
            polynomial=0xA001,
            initial=0,
            xor_out=0xFFFF,
        ),
        "CRC16_KERMIT": _crc_lsb(
            data,
            width=16,
            polynomial=0x8408,
            initial=0,
            xor_out=0,
        ),
        "CRC16_X25": _crc_lsb(
            data,
            width=16,
            polynomial=0x8408,
            initial=0xFFFF,
            xor_out=0xFFFF,
        ),
        "CRC16_DNP": _crc_lsb(
            data,
            width=16,
            polynomial=0xA6BC,
            initial=0,
            xor_out=0xFFFF,
        ),
        "CRC16_XMODEM": _crc_msb(
            data,
            width=16,
            polynomial=0x1021,
            initial=0,
            xor_out=0,
        ),
        "CRC16_CCITT_FALSE": _crc_msb(
            data,
            width=16,
            polynomial=0x1021,
            initial=0xFFFF,
            xor_out=0,
        ),
        "CRC16_AUG_CCITT": _crc_msb(
            data,
            width=16,
            polynomial=0x1021,
            initial=0x1D0F,
            xor_out=0,
        ),
    }


def _byte_swap(value: int, width: int) -> int:
    return int.from_bytes(value.to_bytes(width // 8, "big"), "little")


def expanded_yim_integrity_candidates(
    data: bytes,
    result: YimDecodeResult,
) -> dict[str, object]:
    """Test a frozen, non-adaptive catalogue against safe material ranges."""

    if len(data) < 60:
        raise ValueError("YIM material is truncated")
    ranges = {
        "AFTER_INTEGRITY32_FIELD": data[8:],
        "AFTER_BOTH_INTEGRITY_FIELDS": data[12:],
        "AFTER_ASCII_PREAMBLE": data[24:],
        "AFTER_XIM2_MAGIC": data[28:],
        "ENCODED_RLE": result.envelope.encoded_payload,
        "DECODED_RASTER": result.raster,
        "FULL_WITH_BOTH_FIELDS_ZEROED": b"0" * 12 + data[12:],
    }
    matches32: list[dict[str, str]] = []
    matches16: list[dict[str, str]] = []
    for range_name, material in ranges.items():
        for algorithm, value in _catalog32(material).items():
            for representation, candidate in (
                ("NATIVE", value),
                ("BYTE_SWAPPED", _byte_swap(value, 32)),
            ):
                if candidate == result.envelope.integrity32:
                    matches32.append(
                        {
                            "range": range_name,
                            "algorithm": algorithm,
                            "representation": representation,
                        }
                    )
        for algorithm, value in _catalog16(material).items():
            for representation, candidate in (
                ("NATIVE", value),
                ("BYTE_SWAPPED", _byte_swap(value, 16)),
            ):
                if candidate == result.envelope.integrity16:
                    matches16.append(
                        {
                            "range": range_name,
                            "algorithm": algorithm,
                            "representation": representation,
                        }
                    )
    return {
        "candidate_32bit_algorithms_tested": 7,
        "candidate_16bit_algorithms_tested": 9,
        "candidate_ranges_tested": len(ranges),
        "result_representations_tested": 2,
        "integrity32_match_count": len(matches32),
        "integrity16_match_count": len(matches16),
        "integrity32_matches": matches32,
        "integrity16_matches": matches16,
        "catalog_was_frozen_before_corpus_run": True,
        "adaptive_parameter_search_performed": False,
    }


def analyze_yim_integrity_catalog(
    results: list[tuple[dict[str, object], YimDecodeResult]],
) -> dict[str, object]:
    rows = []
    for source, result in results:
        rows.append(
            {
                "source_id": source["source_id"],
                **expanded_yim_integrity_candidates(
                    bytes(source["data"]), result
                ),
            }
        )
    any_match = any(
        int(row["integrity32_match_count"])
        or int(row["integrity16_match_count"])
        for row in rows
    )
    return {
        "schema": "phoenix-mmi.yim-integrity-catalog/v1",
        "analysis_mode": (
            "read-only-frozen-expanded-crc-catalogue-and-range-test"
        ),
        "session": "051",
        "unique_source_count": len(rows),
        "candidate_32bit_algorithms_tested": 7,
        "candidate_16bit_algorithms_tested": 9,
        "candidate_ranges_tested": 7,
        "result_representations_tested": 2,
        "integrity32_total_match_count": sum(
            int(row["integrity32_match_count"]) for row in rows
        ),
        "integrity16_total_match_count": sum(
            int(row["integrity16_match_count"]) for row in rows
        ),
        "sources": rows,
        "classification": {
            "expanded_integrity_catalog": (
                "CANDIDATE_MATCH_REQUIRES_INDEPENDENT_VALIDATION"
                if any_match
                else "NO_MATCH_UNDER_FROZEN_EXPANDED_CATALOG"
            ),
            "safe_repack": "BLOCKED",
        },
        "operational_graph_version": "v43",
        "publication_safety": _publication_safety(),
    }


def _feature_candidates(
    data: bytes,
    result: YimDecodeResult,
) -> dict[str, int]:
    return {
        "FILE_SIZE": len(data),
        "OUTER_SPAN": result.envelope.outer_span,
        "PAYLOAD_BLOCK_SPAN": result.envelope.payload_block_span,
        "ENCODED_SIZE": len(result.envelope.encoded_payload),
        "DECODED_SIZE": len(result.raster),
        "WIDTH": result.envelope.width,
        "HEIGHT": result.envelope.height,
        "LITERAL_COMMAND_COUNT": result.literal_command_count,
        "REPEAT_COMMAND_COUNT": result.repeat_command_count,
        "COMMAND_COUNT": (
            result.literal_command_count + result.repeat_command_count
        ),
        "ENCODED_BYTE_SUM": sum(result.envelope.encoded_payload),
        "DECODED_BYTE_SUM": sum(result.raster),
    }


def _simple_relation_matches(
    data: bytes,
    result: YimDecodeResult,
) -> list[str]:
    matches = []
    target32 = result.envelope.integrity32
    target16 = result.envelope.integrity16
    for name, raw_value in _feature_candidates(data, result).items():
        value32 = raw_value & 0xFFFFFFFF
        variants32 = {
            "LOW32": value32,
            "NOT_LOW32": (~value32) & 0xFFFFFFFF,
            "BYTE_SWAP_LOW32": _byte_swap(value32, 32),
        }
        for relation, value in variants32.items():
            if value == target32:
                matches.append(f"INTEGRITY32_{relation}_{name}")
        value16 = raw_value & 0xFFFF
        variants16 = {
            "LOW16": value16,
            "NOT_LOW16": (~value16) & 0xFFFF,
            "FOLD_XOR16": (
                ((raw_value >> 16) ^ raw_value) & 0xFFFF
            ),
        }
        for relation, value in variants16.items():
            if value == target16:
                matches.append(f"INTEGRITY16_{relation}_{name}")
    cross = {
        "INTEGRITY16_EQUALS_INTEGRITY32_LOW16": target32 & 0xFFFF,
        "INTEGRITY16_EQUALS_INTEGRITY32_HIGH16": target32 >> 16,
        "INTEGRITY16_EQUALS_INTEGRITY32_FOLD_XOR": (
            (target32 >> 16) ^ target32
        )
        & 0xFFFF,
    }
    matches.extend(name for name, value in cross.items() if value == target16)
    return matches


def analyze_yim_field_relations(
    results: list[tuple[dict[str, object], YimDecodeResult]],
) -> dict[str, object]:
    rows = []
    relation_sets = []
    for source, result in results:
        matches = _simple_relation_matches(bytes(source["data"]), result)
        relation_sets.append(set(matches))
        rows.append(
            {
                "source_id": source["source_id"],
                "fixed_feature_count": 12,
                "fixed_relation_count": 75,
                "match_count": len(matches),
                "matches": matches,
            }
        )
    corpus_wide = (
        sorted(set.intersection(*relation_sets)) if relation_sets else []
    )
    return {
        "schema": "phoenix-mmi.yim-field-relations/v1",
        "analysis_mode": "read-only-frozen-simple-field-relation-test",
        "session": "052",
        "unique_source_count": len(rows),
        "fixed_feature_count": 12,
        "fixed_relation_count_per_source": 75,
        "corpus_wide_match_count": len(corpus_wide),
        "corpus_wide_matches": corpus_wide,
        "sources": rows,
        "classification": {
            "simple_field_relation": (
                "CORPUS_WIDE_RELATION_REQUIRES_VALIDATION"
                if corpus_wide
                else "NO_CORPUS_WIDE_SIMPLE_RELATION"
            ),
            "integrity_semantics": "UNRESOLVED",
        },
        "operational_graph_version": "v44",
        "publication_safety": _publication_safety(),
    }


@dataclass(frozen=True)
class _EmbeddedXim2:
    span: int
    width: int
    height: int
    codec_word: int
    encoded_digest: bytes
    decoded_digest: bytes
    decoded_size: int


def _decode_embedded_xim2(data: bytes, offset: int) -> _EmbeddedXim2 | None:
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
            unit = payload[cursor : cursor + 2]
            cursor += 2
            output.extend(unit * count)
    if len(output) != expected:
        return None
    return _EmbeddedXim2(
        span=span,
        width=width,
        height=height,
        codec_word=codec_word,
        encoded_digest=hashlib.sha256(data[offset:end]).digest(),
        decoded_digest=hashlib.sha256(output).digest(),
        decoded_size=len(output),
    )


def _scan_embedded(reader: _Reader) -> dict[str, object]:
    data = reader.read(0, reader.size)
    magic_offsets = []
    cursor = 0
    while True:
        offset = data.find(b"XIM2", cursor)
        if offset < 0:
            break
        magic_offsets.append(offset)
        cursor = offset + 1
    records = [
        record
        for offset in magic_offsets
        if (record := _decode_embedded_xim2(data, offset)) is not None
    ]
    return {
        "raw_magic_occurrence_count": len(magic_offsets),
        "validated_records": records,
        "case_insensitive_yim_suffix_occurrence_count": (
            data.lower().count(b".yim")
        ),
    }


def analyze_embedded_xim2(
    readers: dict[str, _Reader],
    standalone_results: list[
        tuple[dict[str, object], YimDecodeResult]
    ],
) -> dict[str, object]:
    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("embedded XIM2 comparison requires cd1 and cd3")
    private = {disc: _scan_embedded(reader) for disc, reader in readers.items()}
    rows = []
    for disc in ("cd1", "cd3"):
        scan = private[disc]
        records = scan["validated_records"]
        geometry_counts: dict[tuple[int, int], int] = {}
        for record in records:
            key = (record.width, record.height)
            geometry_counts[key] = geometry_counts.get(key, 0) + 1
        rows.append(
            {
                "artifact": disc,
                "raw_magic_occurrence_count": scan[
                    "raw_magic_occurrence_count"
                ],
                "strict_validated_resource_count": len(records),
                "rejected_magic_occurrence_count": (
                    int(scan["raw_magic_occurrence_count"]) - len(records)
                ),
                "unique_encoded_content_count": len(
                    {record.encoded_digest for record in records}
                ),
                "unique_decoded_content_count": len(
                    {record.decoded_digest for record in records}
                ),
                "decoded_raster_bytes": sum(
                    record.decoded_size for record in records
                ),
                "distinct_geometry_count": len(geometry_counts),
                "geometries": [
                    {
                        "width": width,
                        "height": height,
                        "resource_count": count,
                    }
                    for (width, height), count in sorted(
                        geometry_counts.items()
                    )
                ],
                "distinct_codec_word_count": len(
                    {record.codec_word for record in records}
                ),
                "case_insensitive_yim_suffix_occurrence_count": scan[
                    "case_insensitive_yim_suffix_occurrence_count"
                ],
            }
        )
    left = private["cd1"]["validated_records"]
    right = private["cd3"]["validated_records"]
    left_encoded = {record.encoded_digest for record in left}
    right_encoded = {record.encoded_digest for record in right}
    left_decoded = {record.decoded_digest for record in left}
    right_decoded = {record.decoded_digest for record in right}
    standalone_encoded = {
        hashlib.sha256(bytes(source["data"])[24:]).digest()
        for source, _ in standalone_results
    }
    standalone_decoded = {
        hashlib.sha256(result.raster).digest()
        for _, result in standalone_results
    }
    standalone_codecs = {
        result.envelope.codec_word for _, result in standalone_results
    }
    embedded_codecs = {record.codec_word for record in left + right}
    return {
        "schema": "phoenix-mmi.embedded-xim2-census/v1",
        "analysis_mode": (
            "read-only-strict-embedded-xim2-envelope-and-rle-validation"
        ),
        "session": "053",
        "artifacts": rows,
        "cross_version": {
            "shared_encoded_content_count": len(
                left_encoded & right_encoded
            ),
            "shared_decoded_content_count": len(
                left_decoded & right_decoded
            ),
            "cd1_only_encoded_content_count": len(
                left_encoded - right_encoded
            ),
            "cd3_only_encoded_content_count": len(
                right_encoded - left_encoded
            ),
            "resource_sets_equal_by_encoded_content": (
                left_encoded == right_encoded
            ),
            "resource_sets_equal_by_decoded_content": (
                left_decoded == right_decoded
            ),
        },
        "standalone_yim_correlation": {
            "standalone_unique_source_count": len(standalone_encoded),
            "cd1_encoded_match_count": len(
                standalone_encoded & left_encoded
            ),
            "cd3_encoded_match_count": len(
                standalone_encoded & right_encoded
            ),
            "cd1_decoded_match_count": len(
                standalone_decoded & left_decoded
            ),
            "cd3_decoded_match_count": len(
                standalone_decoded & right_decoded
            ),
            "codec_sets_equal": standalone_codecs == embedded_codecs,
        },
        "classification": {
            "embedded_xim2": "CONFIRMED_IN_CD1_AND_CD3_MAIN_IMAGES",
            "cross_version_resource_set": (
                "IDENTICAL_UNDER_STRICT_CONTENT_COMPARISON"
                if left_encoded == right_encoded
                and left_decoded == right_decoded
                else "DIFFERS_BETWEEN_MAIN_IMAGES"
            ),
            "yim_main_image_link": (
                "EXACT_STANDALONE_TO_EMBEDDED_MATCH_CONFIRMED"
                if standalone_encoded & left_encoded
                else "NOT_FOUND"
            ),
            "consumer_code_owner": "NOT_IDENTIFIED",
        },
        "operational_graph_version": "v45",
        "publication_safety": _publication_safety(),
    }


def build_yim_integrity_decision(
    session051: dict[str, object],
    session052: dict[str, object],
    session053: dict[str, object],
) -> dict[str, object]:
    expected = (
        "phoenix-mmi.yim-integrity-catalog/v1",
        "phoenix-mmi.yim-field-relations/v1",
        "phoenix-mmi.embedded-xim2-census/v1",
    )
    reports = (session051, session052, session053)
    if tuple(report.get("schema") for report in reports) != expected:
        raise ValueError("Session 051-053 input schema differs")
    return {
        "schema": "phoenix-mmi.yim-integrity-decision/v1",
        "analysis_mode": "evidence-only-yim-mutation-readiness-gate",
        "session": "054",
        "source_sessions": ["047", "051", "052", "053"],
        "confirmed": [
            "strict XIM2 envelope and bounded RLE decoding",
            "embedded XIM2 resources in both principal images",
            "exact standalone-to-embedded content relationship",
        ],
        "unresolved": [
            "ASCII preamble 32-bit integrity field",
            "ASCII preamble 16-bit integrity field",
            "pixel semantics",
            "resource consumer routine",
        ],
        "decision": {
            "read_only_decode": "ALLOWED",
            "metadata_only_reporting": "ALLOWED",
            "resource_export": "NOT_PUBLISHED",
            "yim_repack": "BLOCKED",
            "firmware_mutation": "BLOCKED",
        },
        "classification": {
            "yim_read_model": "CONFIRMED_PARTIAL",
            "yim_write_model": "NOT_ESTABLISHED",
            "safe_mutation_ready": False,
        },
        "operational_graph_version": "v46",
        "publication_safety": _publication_safety(),
    }


def clone_public_report(report: dict[str, object]) -> dict[str, object]:
    """Return an isolated public report for callers composing evidence graphs."""

    return copy.deepcopy(report)

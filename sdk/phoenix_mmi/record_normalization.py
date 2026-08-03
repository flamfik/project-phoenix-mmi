"""Validated record-container normalization for Session 041.

Only standard Intel HEX data-address semantics and checksum-valid Motorola
S-record data records are reconstructed. Opaque vendor metadata and
unvalidated envelope bytes are never interpreted or used to bridge regions.
Decoded bytes remain in memory and are omitted from publication reports.
"""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
from typing import Iterable, Protocol

from .cross_payload_homolog import (
    _signature_scan,
    derive_cross_payload_signature,
)


_RECORD_EXTENSIONS = frozenset({".HEX", ".LOD", ".SW", ".YIM"})
_INTEL_STANDARD_TYPES = frozenset({0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
_INTEL_VENDOR_METADATA_TYPES = frozenset({0x10, 0x11})
_SREC_ADDRESS_LENGTHS = {
    0: 2,
    1: 2,
    2: 3,
    3: 4,
    5: 2,
    6: 3,
    7: 4,
    8: 3,
    9: 2,
}
_SREC_DATA_TYPES = frozenset({1, 2, 3})
_SREC_TERMINATION_TYPES = frozenset({7, 8, 9})
_COMPONENT_SPAN = 240


class _Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def sha256(self) -> str: ...


@dataclass(frozen=True)
class RecordPayloadInput:
    disc: str
    path: str
    data: bytes


@dataclass(frozen=True)
class DecodedRegion:
    start_address: int
    data: bytes


@dataclass(frozen=True)
class NormalizationResult:
    format_name: str
    classification: str
    fully_validated: bool
    decoded_regions: tuple[DecodedRegion, ...]
    metrics: dict[str, object]


def record_member_eligible(path: str, size: int) -> bool:
    extension = PurePosixPath(path).suffix.upper()
    return extension in _RECORD_EXTENSIONS and size >= _COMPONENT_SPAN


def _regions_from_memory(memory: dict[int, int]) -> tuple[DecodedRegion, ...]:
    if not memory:
        return ()
    addresses = sorted(memory)
    regions: list[DecodedRegion] = []
    start = addresses[0]
    previous = start
    data = bytearray([memory[start]])
    for address in addresses[1:]:
        if address == previous + 1:
            data.append(memory[address])
        else:
            regions.append(DecodedRegion(start, bytes(data)))
            start = address
            data = bytearray([memory[address]])
        previous = address
    regions.append(DecodedRegion(start, bytes(data)))
    return tuple(regions)


def decode_intel_hex(data: bytes) -> NormalizationResult:
    """Validate an Intel HEX member and reconstruct only data-record bytes."""

    lines = data.splitlines()
    if not lines:
        raise ValueError("empty Intel HEX member")
    memory: dict[int, int] = {}
    base_address = 0
    eof_seen = False
    record_types: Counter[int] = Counter()
    vendor_metadata_count = 0
    identical_overlap_count = 0
    for index, line in enumerate(lines):
        if not line or not line.startswith(b":"):
            raise ValueError("Intel HEX line lacks colon prefix")
        if eof_seen:
            raise ValueError("Intel HEX contains records after EOF")
        encoded = line[1:]
        if len(encoded) % 2:
            raise ValueError("Intel HEX line has odd encoded length")
        try:
            raw = bytes.fromhex(encoded.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Intel HEX line is not ASCII hexadecimal") from error
        if len(raw) < 5:
            raise ValueError("Intel HEX record is truncated")
        count = raw[0]
        if count != len(raw) - 5:
            raise ValueError("Intel HEX byte count differs")
        if sum(raw) & 0xFF:
            raise ValueError("Intel HEX checksum differs")
        offset = int.from_bytes(raw[1:3], "big")
        record_type = raw[3]
        payload = raw[4 : 4 + count]
        record_types[record_type] += 1

        if record_type in _INTEL_VENDOR_METADATA_TYPES:
            if not (
                index == 0
                and count == 4
                and offset == 0
                and vendor_metadata_count == 0
            ):
                raise ValueError("unsupported Intel HEX vendor metadata geometry")
            vendor_metadata_count += 1
            continue
        if record_type not in _INTEL_STANDARD_TYPES:
            raise ValueError("unsupported Intel HEX record type")
        if record_type == 0x00:
            if offset + count > 0x10000:
                raise ValueError("Intel HEX data record crosses 16-bit window")
            absolute = base_address + offset
            for relative, value in enumerate(payload):
                address = absolute + relative
                prior = memory.get(address)
                if prior is not None:
                    if prior != value:
                        raise ValueError("conflicting Intel HEX overlap")
                    identical_overlap_count += 1
                memory[address] = value
        elif record_type == 0x01:
            if count != 0 or offset != 0:
                raise ValueError("invalid Intel HEX EOF record")
            eof_seen = True
        elif record_type == 0x02:
            if count != 2 or offset != 0:
                raise ValueError("invalid Intel HEX segment-base record")
            base_address = int.from_bytes(payload, "big") << 4
        elif record_type == 0x03:
            if count != 4 or offset != 0:
                raise ValueError("invalid Intel HEX start-segment record")
        elif record_type == 0x04:
            if count != 2 or offset != 0:
                raise ValueError("invalid Intel HEX linear-base record")
            base_address = int.from_bytes(payload, "big") << 16
        elif record_type == 0x05:
            if count != 4 or offset != 0:
                raise ValueError("invalid Intel HEX start-linear record")

    if not eof_seen:
        raise ValueError("Intel HEX EOF record is absent")
    regions = _regions_from_memory(memory)
    return NormalizationResult(
        format_name="INTEL_HEX",
        classification=(
            "VALID_WITH_OPAQUE_VENDOR_METADATA"
            if vendor_metadata_count
            else "FULLY_VALIDATED_STANDARD_RECORDS"
        ),
        fully_validated=True,
        decoded_regions=regions,
        metrics={
            "line_count": len(lines),
            "record_type_counts": {
                f"0x{record_type:02x}": count
                for record_type, count in sorted(record_types.items())
            },
            "vendor_metadata_record_count": vendor_metadata_count,
            "vendor_metadata_payload_interpreted": False,
            "eof_record_count": int(eof_seen),
            "decoded_byte_count": len(memory),
            "decoded_region_count": len(regions),
            "scannable_region_count": sum(
                len(region.data) >= _COMPONENT_SPAN for region in regions
            ),
            "identical_overlap_byte_count": identical_overlap_count,
            "conflicting_overlap_byte_count": 0,
            "address_values_published": False,
        },
    )


def _srec_record(line: bytes) -> tuple[int, int, bytes]:
    match = re.fullmatch(rb"S([0-9])([0-9A-Fa-f]+)", line)
    if match is None:
        raise ValueError("S-record line grammar differs")
    record_type = int(match.group(1))
    address_length = _SREC_ADDRESS_LENGTHS.get(record_type)
    if address_length is None:
        raise ValueError("unsupported S-record type")
    encoded = match.group(2)
    if len(encoded) % 2:
        raise ValueError("S-record line has odd encoded length")
    raw = bytes.fromhex(encoded.decode("ascii"))
    if not raw or raw[0] != len(raw) - 1:
        raise ValueError("S-record byte count differs")
    if sum(raw) & 0xFF != 0xFF:
        raise ValueError("S-record checksum differs")
    if len(raw) < 1 + address_length + 1:
        raise ValueError("S-record address or checksum is truncated")
    address = int.from_bytes(raw[1 : 1 + address_length], "big")
    payload = raw[1 + address_length : -1]
    return record_type, address, payload


def decode_srecord_envelope(data: bytes) -> NormalizationResult:
    """Recover checksum-valid S-record runs without bridging opaque bytes."""

    accepted: list[dict[str, object]] = []
    candidate_line_count = 0
    invalid_candidate_count = 0
    offset = 0
    for physical in data.splitlines(keepends=True):
        line = physical.rstrip(b"\r\n")
        if len(line) >= 2 and line[:1] == b"S" and line[1:2].isdigit():
            candidate_line_count += 1
            try:
                record_type, address, payload = _srec_record(line)
            except ValueError:
                invalid_candidate_count += 1
            else:
                accepted.append(
                    {
                        "start": offset,
                        "end": offset + len(line),
                        "type": record_type,
                        "address": address,
                        "payload": payload,
                    }
                )
        offset += len(physical)

    data_records = [
        row for row in accepted if int(row["type"]) in _SREC_DATA_TYPES
    ]
    terminations = [
        row
        for row in accepted
        if int(row["type"]) in _SREC_TERMINATION_TYPES
    ]
    if not data_records:
        raise ValueError("no checksum-valid S-record data records")
    termination_valid = (
        len(terminations) == 1
        and accepted[-1] is terminations[0]
        and {
            1: 9,
            2: 8,
            3: 7,
        }.get(int(data_records[-1]["type"]))
        == int(terminations[0]["type"])
    )
    if not termination_valid:
        raise ValueError("S-record termination contract differs")

    regions: list[DecodedRegion] = []
    current_start: int | None = None
    current_end = 0
    current_physical_end = 0
    current_data = bytearray()
    type_counts: Counter[int] = Counter()
    for row in accepted:
        record_type = int(row["type"])
        type_counts[record_type] += 1
        if record_type not in _SREC_DATA_TYPES:
            continue
        address = int(row["address"])
        payload = bytes(row["payload"])
        physical_gap = int(row["start"]) - current_physical_end
        separator_only = (
            current_start is not None
            and physical_gap in (1, 2)
            and data[current_physical_end : int(row["start"])]
            in (b"\n", b"\r\n")
        )
        if (
            current_start is None
            or address != current_end
            or not separator_only
        ):
            if current_start is not None:
                regions.append(DecodedRegion(current_start, bytes(current_data)))
            current_start = address
            current_data = bytearray()
        current_data.extend(payload)
        current_end = address + len(payload)
        current_physical_end = int(row["end"])
    if current_start is not None:
        regions.append(DecodedRegion(current_start, bytes(current_data)))

    accepted_text_bytes = sum(
        int(row["end"]) - int(row["start"]) for row in accepted
    )
    return NormalizationResult(
        format_name="MOTOROLA_S_RECORD",
        classification=(
            "PARTIAL_VALIDATED_RECORD_RUNS"
            if invalid_candidate_count
            else "FULLY_VALIDATED_RECORD_STREAM"
        ),
        fully_validated=invalid_candidate_count == 0,
        decoded_regions=tuple(regions),
        metrics={
            "candidate_line_count": candidate_line_count,
            "accepted_record_count": len(accepted),
            "invalid_candidate_line_count": invalid_candidate_count,
            "record_type_counts": {
                f"S{record_type}": count
                for record_type, count in sorted(type_counts.items())
            },
            "termination_record_count": len(terminations),
            "termination_contract_validated": termination_valid,
            "decoded_byte_count": sum(len(region.data) for region in regions),
            "decoded_region_count": len(regions),
            "scannable_region_count": sum(
                len(region.data) >= _COMPONENT_SPAN for region in regions
            ),
            "accepted_record_text_byte_count": accepted_text_bytes,
            "unvalidated_envelope_byte_count": len(data) - accepted_text_bytes,
            "opaque_bytes_used_to_bridge_regions": False,
            "address_values_published": False,
        },
    )


def normalize_record_payload(path: str, data: bytes) -> NormalizationResult:
    extension = PurePosixPath(path).suffix.upper()
    if extension == ".HEX":
        return decode_intel_hex(data)
    if extension == ".SW":
        return decode_srecord_envelope(data)
    if extension in {".LOD", ".YIM"}:
        return NormalizationResult(
            format_name="UNSUPPORTED_BINARY_CONTAINER",
            classification="NO_VALIDATED_RECORD_DECODER",
            fully_validated=False,
            decoded_regions=(),
            metrics={
                "decoded_byte_count": 0,
                "decoded_region_count": 0,
                "scannable_region_count": 0,
                "raw_fallback_rescanned": False,
                "address_values_published": False,
            },
        )
    raise ValueError("member extension is outside the record corpus")


def _format_template() -> dict[str, object]:
    return {
        "member_count": 0,
        "unique_source_content_count": 0,
        "fully_validated_unique_source_count": 0,
        "partial_or_unsupported_unique_source_count": 0,
        "classification_counts": {},
        "decoded_byte_count": 0,
        "decoded_region_count": 0,
        "scannable_region_count": 0,
    }


def analyze_record_normalized_homologs(
    left_reader: _Reader,
    right_reader: _Reader,
    session038: dict[str, object],
    session039: dict[str, object],
    session040: dict[str, object],
    payloads: Iterable[RecordPayloadInput],
) -> dict[str, object]:
    """Repeat Session 040 on validated address-contiguous decoded regions."""

    if session040.get("schema") != (
        "phoenix-mmi.cross-payload-homolog-comparison/v1"
    ):
        raise ValueError("unsupported Session 040 schema")
    if session040.get("left_artifact_sha256") != left_reader.sha256():
        raise ValueError("Session 040 left principal-image hash differs")
    if session040.get("right_artifact_sha256") != right_reader.sha256():
        raise ValueError("Session 040 right principal-image hash differs")
    if session040["classification"].get("cross_payload_homolog") != (
        "NOT_FOUND_UNDER_FIXED_SIGNATURE_MODEL"
    ):
        raise ValueError("Session 040 raw-payload result changed")

    signature = derive_cross_payload_signature(
        left_reader, right_reader, session038, session039
    )
    target_references = (
        signature["_internal_left_component"],
        signature["_internal_right_component"],
    )
    control_references = (signature["_internal_control_component"],)

    members = [
        payload
        for payload in payloads
        if record_member_eligible(payload.path, len(payload.data))
    ]
    unique_sources: dict[str, dict[str, object]] = {}
    disc_summaries: dict[str, dict[str, object]] = {}
    for payload in members:
        disc = str(payload.disc)
        disc_row = disc_summaries.setdefault(
            disc,
            {
                "record_candidate_member_count": 0,
                "record_candidate_member_bytes": 0,
                "extension_counts": {},
                "normalized_member_count": 0,
            },
        )
        extension = PurePosixPath(payload.path).suffix.upper()
        disc_row["record_candidate_member_count"] += 1
        disc_row["record_candidate_member_bytes"] += len(payload.data)
        extension_counts = disc_row["extension_counts"]
        extension_counts[extension] = extension_counts.get(extension, 0) + 1
        digest = hashlib.sha256(payload.data).hexdigest()
        row = unique_sources.get(digest)
        if row is None:
            try:
                normalization = normalize_record_payload(
                    payload.path, payload.data
                )
            except ValueError as error:
                normalization = NormalizationResult(
                    format_name="REJECTED_RECORD_CONTAINER",
                    classification="VALIDATION_REJECTED",
                    fully_validated=False,
                    decoded_regions=(),
                    metrics={
                        "decoded_byte_count": 0,
                        "decoded_region_count": 0,
                        "scannable_region_count": 0,
                        "validation_error_class": type(error).__name__,
                        "address_values_published": False,
                    },
                )
            row = {
                "normalization": normalization,
                "source_size": len(payload.data),
                "members": [],
            }
            unique_sources[digest] = row
        row["members"].append(
            {
                "disc": disc,
                "path": payload.path,
                "extension": extension,
                "size": len(payload.data),
            }
        )

    format_summaries: dict[str, dict[str, object]] = {}
    unique_regions: dict[str, dict[str, object]] = {}
    for source in unique_sources.values():
        normalization = source["normalization"]
        format_row = format_summaries.setdefault(
            normalization.format_name, _format_template()
        )
        format_row["unique_source_content_count"] += 1
        if normalization.fully_validated:
            format_row["fully_validated_unique_source_count"] += 1
        else:
            format_row[
                "partial_or_unsupported_unique_source_count"
            ] += 1
        format_row["member_count"] += len(source["members"])
        classes = format_row["classification_counts"]
        classes[normalization.classification] = (
            classes.get(normalization.classification, 0) + 1
        )
        format_row["decoded_byte_count"] += int(
            normalization.metrics["decoded_byte_count"]
        )
        format_row["decoded_region_count"] += int(
            normalization.metrics["decoded_region_count"]
        )
        format_row["scannable_region_count"] += int(
            normalization.metrics["scannable_region_count"]
        )
        if normalization.decoded_regions:
            for member in source["members"]:
                disc_summaries[member["disc"]]["normalized_member_count"] += 1
        for index, region in enumerate(normalization.decoded_regions):
            digest = hashlib.sha256(region.data).hexdigest()
            region_row = unique_regions.get(digest)
            source_rows = [
                {
                    "disc": member["disc"],
                    "path": member["path"],
                    "format_name": normalization.format_name,
                    "source_classification": normalization.classification,
                    "source_region_index": index,
                }
                for member in source["members"]
            ]
            if region_row is None:
                region_row = {
                    "data": region.data,
                    "sources": [],
                }
                unique_regions[digest] = region_row
            region_row["sources"].extend(source_rows)

    target_hits: list[dict[str, object]] = []
    control_hits: list[dict[str, object]] = []
    target_first_occurrences = 0
    control_first_occurrences = 0
    saturation_count = 0
    unique_decoded_bytes = 0
    scannable_unique_region_count = 0
    for region in unique_regions.values():
        data = bytes(region["data"])
        unique_decoded_bytes += len(data)
        if len(data) < _COMPONENT_SPAN:
            continue
        scannable_unique_region_count += 1
        target = _signature_scan(
            data, signature["anchors"], target_references
        )
        control = _signature_scan(
            data, signature["controls"], control_references
        )
        target_first_occurrences += int(
            target["first_anchor_occurrence_count"]
        )
        control_first_occurrences += int(
            control["first_anchor_occurrence_count"]
        )
        saturation_count += int(
            target["scan_saturated"] or control["scan_saturated"]
        )
        if target["geometry_match_count"]:
            target_hits.append(
                {
                    "sources": copy.deepcopy(region["sources"]),
                    "region_size": len(data),
                    "matches": target["matches"],
                }
            )
        if control["geometry_match_count"]:
            control_hits.append(
                {
                    "sources": copy.deepcopy(region["sources"]),
                    "region_size": len(data),
                    "matches": control["matches"],
                }
            )

    target_strong = sum(
        any(match["strong_similarity_gate_passed"] for match in row["matches"])
        for row in target_hits
    )
    control_strong = sum(
        any(match["strong_similarity_gate_passed"] for match in row["matches"])
        for row in control_hits
    )
    if saturation_count:
        classification = "INCONCLUSIVE_NORMALIZED_SCAN_SATURATED"
    elif control_strong:
        classification = "NORMALIZED_MODEL_NOT_DISCRIMINATING"
    elif target_strong:
        classification = "NORMALIZED_CROSS_PAYLOAD_HOMOLOG_SUPPORTED"
    elif target_hits:
        classification = "NORMALIZED_ANCHOR_GEOMETRY_CANDIDATE_ONLY"
    else:
        classification = "NOT_FOUND_IN_VALIDATED_DECODED_REGIONS"

    normalized_unique_sources = sum(
        bool(row["normalization"].decoded_regions)
        for row in unique_sources.values()
    )
    unsupported_unique_sources = sum(
        row["normalization"].classification
        == "NO_VALIDATED_RECORD_DECODER"
        for row in unique_sources.values()
    )
    rejected_unique_sources = sum(
        row["normalization"].classification == "VALIDATION_REJECTED"
        for row in unique_sources.values()
    )
    return {
        "schema": "phoenix-mmi.record-normalized-homolog-comparison/v1",
        "analysis_mode": (
            "read-only-validated-record-decoding-fixed-signature-search"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session040_schema": session040["schema"],
        "normalization_contract": {
            "eligible_extensions": sorted(_RECORD_EXTENSIONS),
            "minimum_source_size": _COMPONENT_SPAN,
            "intel_hex_standard_types": [
                f"0x{value:02x}" for value in sorted(_INTEL_STANDARD_TYPES)
            ],
            "intel_hex_vendor_metadata_types": [
                f"0x{value:02x}"
                for value in sorted(_INTEL_VENDOR_METADATA_TYPES)
            ],
            "vendor_metadata_payload_interpreted": False,
            "srecord_data_types": [
                f"S{value}" for value in sorted(_SREC_DATA_TYPES)
            ],
            "srecord_termination_types": [
                f"S{value}" for value in sorted(_SREC_TERMINATION_TYPES)
            ],
            "opaque_bytes_used_to_bridge_regions": False,
            "gap_fill_used": False,
            "raw_fallback_rescanned": False,
            "decoded_bytes_published": False,
            "address_values_published": False,
        },
        "signature_contract": copy.deepcopy(
            session040["signature_contract"]
        ),
        "source_corpus": {
            "member_count": len(members),
            "member_bytes": sum(len(payload.data) for payload in members),
            "unique_source_content_count": len(unique_sources),
            "normalized_unique_source_count": normalized_unique_sources,
            "unsupported_unique_source_count": unsupported_unique_sources,
            "rejected_unique_source_count": rejected_unique_sources,
        },
        "format_summaries": {
            key: value for key, value in sorted(format_summaries.items())
        },
        "normalization_profiles": sorted(
            (
                {
                    "format_name": row["normalization"].format_name,
                    "classification": row[
                        "normalization"
                    ].classification,
                    "fully_validated": row[
                        "normalization"
                    ].fully_validated,
                    "source_size": row["source_size"],
                    "member_count": len(row["members"]),
                    "disc_ids": sorted(
                        {member["disc"] for member in row["members"]}
                    ),
                    "extensions": sorted(
                        {member["extension"] for member in row["members"]}
                    ),
                    "metrics": copy.deepcopy(
                        row["normalization"].metrics
                    ),
                }
                for row in unique_sources.values()
            ),
            key=lambda row: (
                row["format_name"],
                row["source_size"],
                row["classification"],
                row["member_count"],
            ),
        ),
        "disc_summaries": {
            key: value for key, value in sorted(disc_summaries.items())
        },
        "decoded_corpus": {
            "unique_region_content_count": len(unique_regions),
            "scannable_unique_region_count": scannable_unique_region_count,
            "unique_decoded_region_bytes": unique_decoded_bytes,
            "decoded_region_bytes_published": False,
        },
        "target_homologs": target_hits,
        "control_homologs": control_hits,
        "summary": {
            "target_first_anchor_occurrence_count": target_first_occurrences,
            "target_geometry_hit_unique_region_count": len(target_hits),
            "target_strong_hit_unique_region_count": target_strong,
            "control_first_anchor_occurrence_count": control_first_occurrences,
            "control_geometry_hit_unique_region_count": len(control_hits),
            "control_strong_hit_unique_region_count": control_strong,
            "saturated_unique_region_count": saturation_count,
        },
        "classification": {
            "record_normalized_homolog": classification,
            "cross_payload_owner": "OPEN",
            "semantic_owner": "OPEN",
            "exact_section_boundary": "OPEN",
            "runtime_loader_transform": "NOT_OBSERVED",
            "runtime_execution_observed": False,
        },
        "interpretation": (
            "The unchanged Session 040 target and control geometry is searched "
            "only in checksum-valid, address-contiguous Intel HEX and Motorola "
            "S-record regions. Opaque vendor metadata, invalid S-record lines "
            "and binary container bytes never contribute inferred data."
        ),
        "limits": [
            "Intel HEX vendor records 0x10 and 0x11 are accepted only as one opaque first record with fixed count and address geometry.",
            "Motorola S-record recovery is partial when invalid candidate lines or opaque envelope bytes are present.",
            "Decoded regions are never joined across address or physical-envelope gaps.",
            "LOD and YIM remain unsupported binary containers and are not decoded.",
            "Compressed, encrypted, relocated or split non-record forms remain open.",
            "A structural homolog cannot establish semantic ownership by itself.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "decoded_region_bytes_included": False,
            "raw_component_bytes_included": False,
            "raw_signature_bytes_included": False,
            "signature_hashes_included": False,
            "instruction_bytes_included": False,
            "mnemonic_names_included": False,
            "raw_strings_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
            "map_payload_included": False,
        },
    }


def update_operational_graph_v34(
    prior_graph: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v34"
    graph["nodes"].append(
        {
            "id": "record-normalized-cross-payload-homolog",
            "status": report["classification"]["record_normalized_homolog"],
            "semantic_status": "STRUCTURAL_PROVENANCE_NOT_OWNER_PROOF",
            "evidence": report["interpretation"],
        }
    )
    graph["edges"].extend(
        [
            {
                "source": "reorder-rz012-cross-payload-homolog",
                "target": "record-normalized-cross-payload-homolog",
                "status": report["classification"][
                    "record_normalized_homolog"
                ],
                "relation": "repeats-fixed-signature-after-record-decoding",
            },
            {
                "source": "record-normalized-cross-payload-homolog",
                "target": "reorder-rz012-semantic-owner",
                "status": (
                    "OPEN"
                    if report["classification"][
                        "record_normalized_homolog"
                    ]
                    == "NORMALIZED_CROSS_PAYLOAD_HOMOLOG_SUPPORTED"
                    else "BOUNDED_NEGATIVE"
                ),
                "relation": "does-not-assign-semantic-owner-by-itself",
            },
        ]
    )
    return graph


def correlate_record_normalized_homologs(
    prior_correlation: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.record-normalized-homolog-correlation/v1",
        "analysis_mode": report["analysis_mode"],
        "firmware": copy.deepcopy(report["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_homolog_edge": "NOT_ASSERTED",
        "interpretation": report["interpretation"],
        "operational_graph": update_operational_graph_v34(
            prior_correlation["operational_graph"], report
        ),
        "publication_safety": copy.deepcopy(report["publication_safety"]),
    }


def build_public_record_normalized_homolog_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

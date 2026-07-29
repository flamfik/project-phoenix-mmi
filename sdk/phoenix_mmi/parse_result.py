"""Normalized, publication-aware parser results for read-only artifacts."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
from pathlib import PurePosixPath
from typing import Callable

from .format_registry import DEFAULT_FORMAT_REGISTRY, FormatRegistry
from .record_normalization import (
    NormalizationResult,
    decode_intel_hex,
    decode_srecord_envelope,
)
from .yim import parse_yim_envelope


PARSE_RESULT_SCHEMA = "phoenix-mmi.parse-result/v1"
MAX_PARSE_BYTES = 64 * 1024 * 1024
MAX_LOD_SCAN_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class ParseDiagnostic:
    code: str
    severity: str
    message: str

    def __post_init__(self) -> None:
        if self.severity not in {"INFO", "WARNING", "ERROR"}:
            raise ValueError("unsupported diagnostic severity")

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class ParseRegion:
    ordinal: int
    offset: int
    address: int | None
    data: bytes
    role: str

    def __post_init__(self) -> None:
        if self.ordinal < 0 or self.offset < 0 or self.address is not None and self.address < 0:
            raise ValueError("parse-region coordinates must be non-negative")

    def to_dict(self, *, include_data: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "ordinal": self.ordinal,
            "offset": self.offset,
            "address": self.address,
            "size_bytes": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "role": self.role,
        }
        if include_data:
            value["data_hex"] = self.data.hex()
        return value


@dataclass(frozen=True)
class ParseResult:
    parser_id: str
    family: str
    classification: str
    fully_validated: bool
    consumed_bytes: int
    source_size: int
    regions: tuple[ParseRegion, ...]
    diagnostics: tuple[ParseDiagnostic, ...]
    metrics: dict[str, object]

    def __post_init__(self) -> None:
        if self.consumed_bytes < 0 or self.source_size < self.consumed_bytes:
            raise ValueError("invalid parser consumption bounds")
        if tuple(region.ordinal for region in self.regions) != tuple(
            range(len(self.regions))
        ):
            raise ValueError("parse-region ordinals must be contiguous")

    def to_dict(self, *, include_region_data: bool = False) -> dict[str, object]:
        return {
            "schema": PARSE_RESULT_SCHEMA,
            "parser_id": self.parser_id,
            "family": self.family,
            "classification": self.classification,
            "fully_validated": self.fully_validated,
            "consumed_bytes": self.consumed_bytes,
            "source_size": self.source_size,
            "region_count": len(self.regions),
            "regions": [
                region.to_dict(include_data=include_region_data)
                for region in self.regions
            ],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "metrics": dict(sorted(self.metrics.items())),
            "raw_source_bytes_included": False,
            "region_data_included": include_region_data,
        }


def _from_normalized(result: NormalizationResult, source_size: int) -> ParseResult:
    regions = tuple(
        ParseRegion(index, 0, region.start_address, region.data, "decoded-data")
        for index, region in enumerate(result.decoded_regions)
    )
    diagnostics = ()
    if not result.fully_validated:
        diagnostics = (
            ParseDiagnostic(
                "OPAQUE_ENVELOPE_REMAINS",
                "WARNING",
                "Validated records were recovered without interpreting all envelope bytes.",
            ),
        )
    return ParseResult(
        parser_id=result.format_name.casefold().replace("_", "-"),
        family=result.format_name,
        classification=result.classification,
        fully_validated=result.fully_validated,
        consumed_bytes=source_size,
        source_size=source_size,
        regions=regions,
        diagnostics=diagnostics,
        metrics=result.metrics,
    )


def parse_intel_hex(data: bytes) -> ParseResult:
    return _from_normalized(decode_intel_hex(data), len(data))


def parse_srecord(data: bytes) -> ParseResult:
    return _from_normalized(decode_srecord_envelope(data), len(data))


def parse_yim(data: bytes) -> ParseResult:
    envelope = parse_yim_envelope(data)
    return ParseResult(
        parser_id="yim-xim2-envelope",
        family="YIM_XIM2_RESOURCE",
        classification="VALIDATED_ENVELOPE_OPAQUE_INTEGRITY",
        fully_validated=False,
        consumed_bytes=60,
        source_size=len(data),
        regions=(
            ParseRegion(0, 60, None, envelope.encoded_payload, "encoded-rle"),
        ),
        diagnostics=(
            ParseDiagnostic(
                "YIM_INTEGRITY_UNRESOLVED",
                "WARNING",
                "Envelope geometry is validated; integrity fields remain unresolved.",
            ),
        ),
        metrics={
            "width": envelope.width,
            "height": envelope.height,
            "codec_word": envelope.codec_word,
            "encoded_payload_bytes": len(envelope.encoded_payload),
            "integrity_fields_interpreted": False,
        },
    )


def parse_lod_bounded(
    data: bytes, *, source_size: int | None = None, limit: int = MAX_LOD_SCAN_BYTES
) -> ParseResult:
    """Describe bounded LOD byte topology without claiming record semantics."""

    declared_size = len(data) if source_size is None else source_size
    if declared_size < len(data) or limit <= 0 or len(data) > limit:
        raise ValueError("LOD input exceeds the declared bounded scan contract")
    values = Counter(data)
    transitions = sum(left != right for left, right in zip(data, data[1:]))
    runs: list[tuple[int, int, int]] = []
    start = 0
    for offset in range(1, len(data) + 1):
        if offset == len(data) or data[offset] != data[start]:
            if offset - start >= 32:
                runs.append((start, offset, data[start]))
            start = offset
    return ParseResult(
        parser_id="lod-bounded-topology",
        family="LOD_LANGUAGE_PAYLOAD",
        classification="OPAQUE_STRUCTURAL_ONLY",
        fully_validated=False,
        consumed_bytes=len(data),
        source_size=declared_size,
        regions=(),
        diagnostics=(
            ParseDiagnostic(
                "LOD_SEMANTICS_UNRESOLVED",
                "WARNING",
                "No record, address, length, checksum or compression semantics are assigned.",
            ),
        ),
        metrics={
            "bounded_scan_bytes": len(data),
            "scan_complete": len(data) == declared_size,
            "distinct_byte_count": len(values),
            "transition_count": transitions,
            "long_fill_run_count": len(runs),
            "long_ff_run_count": sum(value == 0xFF for _, _, value in runs),
            "long_zero_run_count": sum(value == 0 for _, _, value in runs),
            "record_model_established": False,
            "address_model_established": False,
            "integrity_model_established": False,
        },
    )


Parser = Callable[[bytes], ParseResult]
_PARSERS: dict[str, Parser] = {
    "INTEL_HEX_TEXT": parse_intel_hex,
    "S_RECORD_STREAM": parse_srecord,
    "YIM_XIM2_RESOURCE": parse_yim,
    "LOD_LANGUAGE_PAYLOAD": parse_lod_bounded,
}


def parse_artifact(
    data: bytes,
    *,
    path: str = "artifact.bin",
    source_size: int | None = None,
    registry: FormatRegistry = DEFAULT_FORMAT_REGISTRY,
) -> ParseResult:
    if len(data) > MAX_PARSE_BYTES:
        raise ValueError("parser input exceeds global safety bound")
    declared_size = len(data) if source_size is None else source_size
    evidence = registry.primary(data, path=path, size=declared_size)
    if evidence is None:
        raise ValueError("artifact has no supported validated or routed format")
    parser = _PARSERS.get(evidence.family)
    if parser is None:
        raise ValueError(f"no normalized parser for {evidence.family}")
    if evidence.family == "LOD_LANGUAGE_PAYLOAD":
        return parse_lod_bounded(data, source_size=declared_size)
    return parser(data)


def build_public_parser_contract_summary() -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.parser-contract-summary/v1",
        "result_schema": PARSE_RESULT_SCHEMA,
        "parser_families": sorted(_PARSERS),
        "parser_count": len(_PARSERS),
        "global_input_limit_bytes": MAX_PARSE_BYTES,
        "lod_scan_limit_bytes": MAX_LOD_SCAN_BYTES,
        "lod_semantic_decoder_present": False,
        "publication_default_includes_region_data": False,
        "raw_artifact_bytes_included": False,
    }

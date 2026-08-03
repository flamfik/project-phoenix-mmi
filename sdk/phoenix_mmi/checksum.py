"""Checksum primitives and conservative region-to-METAINFO correlation."""

from __future__ import annotations

import re
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

from .binary import BinaryReader
from .segments import CandidateSegment


@dataclass(frozen=True)
class ChecksumExpectation:
    index: int
    value: int
    field: str

    @property
    def hex_value(self) -> str:
        return f"{self.value:08x}"


@dataclass(frozen=True)
class MetainfoChecksumSet:
    section: str
    filename: str
    flash_start_address: int | None
    expectations: tuple[ChecksumExpectation, ...]


@dataclass(frozen=True)
class CandidateRegion:
    offset: int
    end: int
    source: str

    @property
    def length(self) -> int:
        return self.end - self.offset


@dataclass(frozen=True)
class ChecksumMatch:
    index: int
    expected: str
    offset: int
    end: int
    length: int
    source: str
    algorithm: str = "CRC32/IEEE"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


SECTION_RE = re.compile(r"^\[(.+)]$")
FIELD_RE = re.compile(r'^([^=]+?)\s*=\s*"?([^"\r\n]*?)"?\s*$')
CHECKSUM_RE = re.compile(r"^checksum(?P<index>\d*)$", re.IGNORECASE)


def crc32_bytes(data: bytes, initial: int = 0) -> int:
    return zlib.crc32(data, initial) & 0xFFFFFFFF


def crc32_region(
    reader: BinaryReader,
    offset: int,
    length: int,
    *,
    chunk_size: int = 1024 * 1024,
) -> int:
    if offset < 0 or length < 0 or offset + length > reader.size:
        raise ValueError("checksum region is outside the artifact")
    crc = 0
    remaining = length
    cursor = offset
    while remaining:
        chunk = reader.read(cursor, min(chunk_size, remaining))
        if not chunk:
            raise EOFError("unexpected end of artifact")
        crc = zlib.crc32(chunk, crc)
        cursor += len(chunk)
        remaining -= len(chunk)
    return crc & 0xFFFFFFFF


def _parse_number(value: str) -> int:
    cleaned = value.strip()
    if cleaned.lower().startswith("0x"):
        return int(cleaned, 16)
    if re.fullmatch(r"[0-9a-fA-F]{8}", cleaned):
        return int(cleaned, 16)
    return int(cleaned, 10)


def _parse_checksum(value: str) -> int:
    cleaned = value.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return int(cleaned, 16)


def parse_metainfo_checksums(
    path: str | Path,
    artifact_filename: str | None = None,
    *,
    section_name: str | None = None,
) -> MetainfoChecksumSet:
    """Load checksum fields from the METAINFO record for one payload."""

    if (artifact_filename is None) == (section_name is None):
        raise ValueError("select exactly one METAINFO record by filename or section_name")

    sections: list[tuple[str, dict[str, str]]] = []
    current_name: str | None = None
    current_fields: dict[str, str] = {}
    for raw_line in Path(path).read_text("latin1").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        section_match = SECTION_RE.match(line)
        if section_match:
            if current_name is not None:
                sections.append((current_name, current_fields))
            current_name = section_match.group(1)
            current_fields = {}
            continue
        field_match = FIELD_RE.match(line)
        if current_name is not None and field_match:
            current_fields[field_match.group(1).strip()] = field_match.group(2).strip()
    if current_name is not None:
        sections.append((current_name, current_fields))

    if section_name is not None:
        wanted = section_name.casefold()
        matches = [(name, fields) for name, fields in sections if name.casefold() == wanted]
        selector = f"section {section_name!r}"
    else:
        wanted = str(artifact_filename).casefold()
        matches = [
            (name, fields)
            for name, fields in sections
            if fields.get("FileName", "").casefold() == wanted
        ]
        selector = f"filename {artifact_filename!r}"
    if not matches:
        raise KeyError(f"no METAINFO record matches {selector}")
    if len(matches) != 1:
        raise KeyError(f"expected one METAINFO record for {selector}, found {len(matches)}")

    section, fields = matches[0]
    expectations: list[ChecksumExpectation] = []
    for field, raw_value in fields.items():
        match = CHECKSUM_RE.match(field)
        if not match:
            continue
        index = int(match.group("index") or 0)
        expectations.append(ChecksumExpectation(index, _parse_checksum(raw_value), field))
    expectations.sort(key=lambda item: item.index)

    flash_start = fields.get("FlashStartAddress")
    return MetainfoChecksumSet(
        section=section,
        filename=fields["FileName"],
        flash_start_address=_parse_number(flash_start) if flash_start else None,
        expectations=tuple(expectations),
    )


def candidate_regions(
    size: int,
    segments: list[CandidateSegment],
    *,
    block_sizes: tuple[int, ...] = (
        0x10000,
        0x20000,
        0x40000,
        0x80000,
        0x100000,
        0x200000,
    ),
) -> list[CandidateRegion]:
    """Generate bounded CRC candidates without claiming vendor segmentation."""

    regions: dict[tuple[int, int], CandidateRegion] = {}

    def add(offset: int, end: int, source: str) -> None:
        if 0 <= offset < end <= size:
            regions.setdefault((offset, end), CandidateRegion(offset, end, source))

    if size:
        add(0, size, "whole-file")
    for segment in segments:
        add(segment.offset, segment.end, f"candidate-segment:{segment.index}")
    for block_size in block_sizes:
        for offset in range(0, size, block_size):
            end = min(size, offset + block_size)
            add(offset, end, f"aligned-block:0x{block_size:x}")
    return sorted(regions.values(), key=lambda region: (region.offset, region.end))


def map_crc32_expectations(
    reader: BinaryReader,
    expectations: tuple[ChecksumExpectation, ...] | list[ChecksumExpectation],
    regions: list[CandidateRegion],
) -> list[ChecksumMatch]:
    """Match expected values only against an explicit, reproducible region set."""

    expected_by_value: dict[int, list[ChecksumExpectation]] = {}
    for expectation in expectations:
        expected_by_value.setdefault(expectation.value, []).append(expectation)

    matches: list[ChecksumMatch] = []
    for region in regions:
        value = crc32_region(reader, region.offset, region.length)
        for expectation in expected_by_value.get(value, []):
            matches.append(
                ChecksumMatch(
                    index=expectation.index,
                    expected=expectation.hex_value,
                    offset=region.offset,
                    end=region.end,
                    length=region.length,
                    source=region.source,
                )
            )
    return matches


def detect_sequential_crc32_layouts(
    reader: BinaryReader,
    expectations: tuple[ChecksumExpectation, ...] | list[ChecksumExpectation],
    *,
    block_sizes: tuple[int, ...] = (
        0x10000,
        0x20000,
        0x40000,
        0x80000,
        0x100000,
        0x200000,
    ),
) -> list[dict[str, object]]:
    """Detect whether checksum indices describe consecutive fixed-size chunks."""

    ordered = sorted(expectations, key=lambda item: item.index)
    if not ordered or [item.index for item in ordered] != list(range(len(ordered))):
        return []

    layouts: list[dict[str, object]] = []
    for block_size in block_sizes:
        chunk_count = (reader.size + block_size - 1) // block_size
        if chunk_count != len(ordered):
            continue
        regions: list[dict[str, object]] = []
        complete = True
        for expectation in ordered:
            offset = expectation.index * block_size
            end = min(reader.size, offset + block_size)
            actual = crc32_region(reader, offset, end - offset)
            matched = actual == expectation.value
            complete = complete and matched
            regions.append(
                {
                    "index": expectation.index,
                    "offset": offset,
                    "end": end,
                    "length": end - offset,
                    "expected": expectation.hex_value,
                    "actual": f"{actual:08x}",
                    "matched": matched,
                }
            )
        if complete:
            layouts.append(
                {
                    "algorithm": "CRC32/IEEE",
                    "block_size": block_size,
                    "block_size_hex": f"0x{block_size:x}",
                    "chunk_count": chunk_count,
                    "complete": True,
                    "tail_length": regions[-1]["length"],
                    "regions": regions,
                }
            )
    return layouts

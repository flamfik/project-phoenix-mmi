"""Printable-string discovery with publication-safe aggregate reporting."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from .binary import BinaryReader


@dataclass(frozen=True)
class StringRecord:
    offset: int
    encoding: str
    text: str


TECHNICAL_MARKERS = (
    "SH3",
    "SH7709A",
    "QNX",
    "VxWorks",
    "Wind River",
    "MOST",
    "EEPROM",
    "CRC",
    "NAV",
    "GPS",
    "BECKER",
    "AUDID3",
    "MMI",
    "HTML",
)

CATEGORY_TERMS: dict[str, tuple[str, ...]] = {
    "platform": ("qnx", "vxworks", "wind river", "sh3", "sh7709", "becker", "audid3"),
    "most": ("most", "optical", "ringbreak"),
    "navigation": ("nav", "gps", "route", "map"),
    "eeprom-checksum": ("eeprom", "crc", "checksum", "flash"),
    "ui-resource": ("menu", "icon", "font", "bitmap", "html", "screen"),
    "diagnostic": ("error", "warning", "debug", "task", "exception"),
}


def _patterns(min_length: int) -> tuple[tuple[str, re.Pattern[bytes]], ...]:
    if min_length < 2:
        raise ValueError("min_length must be at least 2")
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    utf16le_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    utf16be_pattern = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % min_length)
    return (
        ("ascii", ascii_pattern),
        ("utf-16le", utf16le_pattern),
        ("utf-16be", utf16be_pattern),
    )


def extract_strings(
    reader: BinaryReader,
    *,
    min_length: int = 5,
    max_records: int = 200_000,
) -> list[StringRecord]:
    """Extract bounded ASCII/UTF-16 records for local research use."""

    data = reader.read(0, reader.size)
    records: list[StringRecord] = []
    for encoding, pattern in _patterns(min_length):
        for match in pattern.finditer(data):
            raw = match.group(0)
            text = raw.decode(encoding, "replace")
            records.append(StringRecord(match.start(), encoding, text))
            if len(records) >= max_records:
                return sorted(records, key=lambda record: (record.offset, record.encoding))
    return sorted(records, key=lambda record: (record.offset, record.encoding))


def summarize_strings(records: list[StringRecord]) -> dict[str, object]:
    """Summarize without embedding arbitrary firmware strings in reports."""

    encodings = Counter(record.encoding for record in records)
    categories: Counter[str] = Counter()
    markers: set[str] = set()
    marker_counts: Counter[str] = Counter()
    marker_hits: dict[str, list[int]] = {marker: [] for marker in TECHNICAL_MARKERS}
    path_like = 0
    for record in records:
        folded = record.text.casefold()
        for category, terms in CATEGORY_TERMS.items():
            if any(term in folded for term in terms):
                categories[category] += 1
        for marker in TECHNICAL_MARKERS:
            if marker.casefold() in folded:
                markers.add(marker)
                marker_counts[marker] += 1
                if len(marker_hits[marker]) < 8:
                    marker_hits[marker].append(record.offset)
        if "/" in record.text or "\\" in record.text:
            path_like += 1
    return {
        "record_count": len(records),
        "encodings": dict(sorted(encodings.items())),
        "category_hits": dict(sorted(categories.items())),
        "technical_markers": sorted(markers),
        "technical_marker_hits": {
            marker: {"count": marker_counts[marker], "first_offsets": offsets}
            for marker, offsets in sorted(marker_hits.items())
            if offsets
        },
        "path_like_records": path_like,
        "raw_strings_included": False,
    }

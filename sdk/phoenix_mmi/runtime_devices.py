"""Publication-safe lexical device and subsystem boundary catalog."""

from __future__ import annotations

import re
from typing import Protocol

from .strings import extract_strings


class Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...


DEVICE_FAMILIES: dict[str, tuple[str, ...]] = {
    "AUDIO_DSP": ("audio", "dsp", "amplifier", "volume"),
    "DISPLAY_INPUT": ("display", "screen", "key", "button", "rotary"),
    "FILESYSTEM_FLASH": ("dosfs", "tffs", "flash", "fat"),
    "NAVIGATION_GPS": ("navigation", "route", "gps", "map"),
    "NETWORK_STACK": ("socket", "tcp", "udp", "http", "ethernet"),
    "OPTICAL_MEDIA": ("cdrom", "atapi", "optical", "dvd"),
    "VEHICLE_NETWORK": ("most", "ringbreak", "can"),
}


def _contains_term(text: str, term: str) -> bool:
    """Match delimited words or CamelCase-style markers, not substrings."""

    folded = text.casefold()
    delimited = re.search(
        rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])",
        folded,
    )
    if delimited is not None:
        return True
    for token in (term.capitalize(), term.upper()):
        cursor = 0
        while True:
            offset = text.find(token, cursor)
            if offset < 0:
                break
            before = text[offset - 1 : offset]
            end = offset + len(token)
            after = text[end : end + 1]
            if (
                not before or before.islower() or before.isdigit()
            ) and (
                not after or after.isupper() or after.isdigit()
            ):
                return True
            cursor = offset + 1
    return False


def _family_records(reader: Reader) -> dict[str, set[tuple[str, str]]]:
    output = {family: set() for family in DEVICE_FAMILIES}
    for record in extract_strings(reader, min_length=5):
        if len(record.text) > 200:
            continue
        for family, terms in DEVICE_FAMILIES.items():
            if any(_contains_term(record.text, term) for term in terms):
                output[family].add((record.encoding, record.text))
    return output


def analyze_device_boundaries(
    readers: dict[str, Reader],
) -> dict[str, object]:
    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("device boundary analysis requires cd1 and cd3")
    private = {
        release: _family_records(readers[release])
        for release in ("cd1", "cd3")
    }
    artifacts = []
    for release in ("cd1", "cd3"):
        artifacts.append(
            {
                "artifact": release,
                "families": [
                    {
                        "family": family,
                        "unique_lexical_record_count": len(
                            private[release][family]
                        ),
                        "classification": (
                            "LEXICAL_FAMILY_PRESENT"
                            if private[release][family]
                            else "NO_FIXED_TERM_HIT"
                        ),
                    }
                    for family in sorted(DEVICE_FAMILIES)
                ],
            }
        )
    shared = {
        family: len(private["cd1"][family] & private["cd3"][family])
        for family in DEVICE_FAMILIES
    }
    nodes = [
        {
            "id": family.casefold().replace("_", "-"),
            "status": (
                "CONFIRMED_LEXICAL_BOUNDARY"
                if shared[family]
                else "ONE_SIDED_OR_ABSENT"
            ),
        }
        for family in sorted(DEVICE_FAMILIES)
    ]
    return {
        "schema": "phoenix-mmi.runtime-device-boundaries/v1",
        "analysis_mode": "fixed-family-private-strings-public-cardinality",
        "artifacts": artifacts,
        "cross_version": {
            "shared_unique_record_counts": dict(sorted(shared.items())),
            "bilaterally_present_family_count": sum(
                bool(value) for value in shared.values()
            ),
        },
        "boundary_graph": {
            "node_count": len(nodes),
            "nodes": nodes,
            "edges": [
                {
                    "source": "vxworks-runtime",
                    "target": row["id"],
                    "relation": "contains-static-lexical-support-for",
                }
                for row in nodes
            ],
        },
        "classification": {
            "device_family_presence": "CONFIRMED_LEXICAL_BOUNDED",
            "driver_entry_points": "NOT_ESTABLISHED",
            "hardware_register_map": "NOT_ESTABLISHED",
            "vehicle_protocol_semantics": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "raw_strings_included": False,
            "string_hashes_included": False,
            "offsets_included": False,
            "hardware_addresses_included": False,
            "vehicle_identifiers_included": False,
            "firmware_bytes_included": False,
        },
    }

"""Bounded VxWorks IPC vocabulary and static reference evidence."""

from __future__ import annotations

from collections import Counter
import re
from typing import Protocol

from .runtime_inventory import RUNTIME_API_PROBES, _token_offsets
from .strings import extract_strings
from .superh import find_pc_relative_referrers


class Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def find_all(
        self,
        needle: bytes,
        *,
        chunk_size: int = 1024 * 1024,
        max_hits: int | None = None,
    ) -> list[int]: ...


IPC_FAMILIES = ("MESSAGE_QUEUE", "SEMAPHORE", "EVENT", "WATCHDOG_TIMER")
_LEXICAL_TERMS = {
    "QUEUE_LABEL": ("queue", "msgq"),
    "EVENT_LABEL": ("event", "signal"),
    "LOCK_LABEL": ("mutex", "semaphore", "lock"),
    "TIMER_LABEL": ("timer", "timeout", "watchdog"),
}


def _contains_term(text: str, term: str) -> bool:
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


def _reference_profile(
    reader: Reader, offsets: list[int], *, runtime_base: int
) -> dict[str, int]:
    literal_words = 0
    code_referrers = 0
    for marker_offset in offsets:
        for value in (marker_offset, runtime_base + marker_offset):
            if not 0 <= value <= 0xFFFFFFFF:
                continue
            for literal_offset in reader.find_all(
                value.to_bytes(4, "big"), max_hits=64
            ):
                literal_words += 1
                code_referrers += len(
                    find_pc_relative_referrers(reader, literal_offset)
                )
    return {
        "literal_word_occurrence_count": literal_words,
        "pc_relative_code_referrer_count": code_referrers,
    }


def analyze_ipc_contract(
    readers: dict[str, Reader], *, runtime_base: int = 0x0C000000
) -> dict[str, object]:
    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("IPC analysis requires cd1 and cd3")
    artifacts = []
    family_presence: dict[str, set[str]] = {}
    lexical_sets: dict[str, set[tuple[str, str]]] = {}
    for release in ("cd1", "cd3"):
        reader = readers[release]
        rows = []
        present: set[str] = set()
        for family in IPC_FAMILIES:
            token_offsets = [
                offset
                for token in RUNTIME_API_PROBES[family]
                for offset in _token_offsets(reader, token)
            ]
            if token_offsets:
                present.add(family)
            rows.append(
                {
                    "family": family,
                    "present_probe_count": sum(
                        bool(_token_offsets(reader, token))
                        for token in RUNTIME_API_PROBES[family]
                    ),
                    "bounded_occurrence_count": len(token_offsets),
                    **_reference_profile(
                        reader, token_offsets, runtime_base=runtime_base
                    ),
                }
            )
        family_presence[release] = present
        labels = []
        for record in extract_strings(reader, min_length=5):
            matches = [
                family
                for family, terms in _LEXICAL_TERMS.items()
                if any(_contains_term(record.text, term) for term in terms)
            ]
            if matches and len(record.text) <= 160:
                labels.append((record.encoding, record.text, matches[0]))
        lexical_sets[release] = {(encoding, text) for encoding, text, _ in labels}
        artifacts.append(
            {
                "artifact": release,
                "families": rows,
                "ipc_label_record_count": len(labels),
                "ipc_label_family_counts": dict(
                    sorted(Counter(family for _, _, family in labels).items())
                ),
            }
        )
    return {
        "schema": "phoenix-mmi.runtime-ipc-contract/v1",
        "analysis_mode": "fixed-vxworks-ipc-probes-and-bounded-static-references",
        "runtime_address_model": {
            "name": "runtime-link-base",
            "base": runtime_base,
            "status": "CONFIRMED_BOUNDED_STATIC_MODEL",
        },
        "artifacts": artifacts,
        "cross_version": {
            "shared_present_families": sorted(
                family_presence["cd1"] & family_presence["cd3"]
            ),
            "shared_ipc_label_unique_count": len(
                lexical_sets["cd1"] & lexical_sets["cd3"]
            ),
        },
        "classification": {
            "fixed_vxworks_ipc_api_vocabulary": (
                "CONFIRMED_BOUNDED"
                if family_presence["cd1"] & family_presence["cd3"]
                else "NOT_FOUND_UNDER_FIXED_PROBE_SET"
            ),
            "ipc_related_lexical_records": "CONFIRMED_AGGREGATE",
            "ipc_primitive_vocabulary": "NOT_ESTABLISHED",
            "queue_event_lock_payload_schema": "NOT_ESTABLISHED",
            "producer_consumer_pairing": "NOT_ESTABLISHED",
            "runtime_scheduling_behavior": "NOT_OBSERVED",
        },
        "publication_safety": {
            "raw_strings_included": False,
            "offsets_included": False,
            "runtime_addresses_included": False,
            "firmware_bytes_included": False,
            "runtime_execution_observed": False,
        },
    }

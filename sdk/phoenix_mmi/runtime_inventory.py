"""Static runtime task/service inventory without publishing firmware strings."""

from __future__ import annotations

from collections import Counter
import re
from typing import Protocol

from .strings import StringRecord, extract_strings


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


RUNTIME_API_PROBES: dict[str, tuple[bytes, ...]] = {
    "TASK_LIFECYCLE": (
        b"taskSpawn",
        b"taskCreate",
        b"taskDelete",
        b"taskSuspend",
        b"taskResume",
        b"taskDelay",
        b"taskPrioritySet",
        b"taskIdSelf",
    ),
    "MESSAGE_QUEUE": (
        b"msgQCreate",
        b"msgQDelete",
        b"msgQSend",
        b"msgQReceive",
        b"msgQNumMsgs",
    ),
    "SEMAPHORE": (
        b"semBCreate",
        b"semCCreate",
        b"semMCreate",
        b"semTake",
        b"semGive",
        b"semDelete",
    ),
    "EVENT": (
        b"eventSend",
        b"eventReceive",
        b"eventClear",
    ),
    "WATCHDOG_TIMER": (
        b"wdCreate",
        b"wdStart",
        b"wdCancel",
        b"wdDelete",
        b"tickGet",
    ),
    "IO_SUBSYSTEM": (
        b"iosDrvInstall",
        b"iosDevAdd",
        b"iosDevDelete",
        b"ioctl",
        b"select",
    ),
}

_SERVICE_TERMS: dict[str, tuple[str, ...]] = {
    "TASK_LABEL": ("task", "thread", "worker"),
    "SERVICE_LABEL": ("service", "server", "manager"),
    "EVENT_LABEL": ("event", "handler", "dispatch"),
    "TIMER_LABEL": ("timer", "watchdog", "timeout"),
}
_IDENTIFIER_BOUNDARY = re.compile(rb"[A-Za-z0-9_]")


def _token_offsets(reader: Reader, token: bytes) -> list[int]:
    """Find identifier-bounded token occurrences."""

    data = reader.read(0, reader.size)
    offsets: list[int] = []
    cursor = 0
    while len(offsets) < 4096:
        offset = data.find(token, cursor)
        if offset < 0:
            break
        before = data[offset - 1 : offset] if offset else b""
        end = offset + len(token)
        after = data[end : end + 1]
        if (
            not before
            or _IDENTIFIER_BOUNDARY.fullmatch(before) is None
        ) and (
            not after
            or _IDENTIFIER_BOUNDARY.fullmatch(after) is None
        ):
            offsets.append(offset)
        cursor = offset + 1
    return offsets


def _candidate_class(record: StringRecord) -> str | None:
    if len(record.text) > 160:
        return None
    folded = record.text.casefold()
    matches = [
        family
        for family, terms in _SERVICE_TERMS.items()
        if any(term in folded for term in terms)
    ]
    return matches[0] if len(matches) == 1 else (
        "MULTI_RUNTIME_LABEL" if matches else None
    )


def analyze_runtime_inventory(
    readers: dict[str, Reader],
) -> tuple[dict[str, object], dict[str, object]]:
    """Return publication-safe aggregates and a private local evidence set."""

    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("runtime inventory requires cd1 and cd3")
    private_artifacts: dict[str, dict[str, object]] = {}
    public_artifacts = []
    candidate_sets: dict[str, set[tuple[str, str]]] = {}
    for release in ("cd1", "cd3"):
        reader = readers[release]
        records = extract_strings(reader, min_length=5)
        candidates = [
            (record, family)
            for record in records
            if (family := _candidate_class(record)) is not None
        ]
        candidate_sets[release] = {
            (record.encoding, record.text) for record, _ in candidates
        }
        api_hits: dict[str, dict[str, list[int]]] = {}
        for family, tokens in RUNTIME_API_PROBES.items():
            per_token = {}
            for index, token in enumerate(tokens):
                offsets = _token_offsets(reader, token)
                if offsets:
                    per_token[f"{family}-{index + 1:02d}"] = offsets
            api_hits[family] = per_token
        label_counts = Counter(family for _, family in candidates)
        public_artifacts.append(
            {
                "artifact": release,
                "runtime_label_record_count": len(candidates),
                "runtime_label_unique_count": len(candidate_sets[release]),
                "runtime_label_family_counts": dict(sorted(label_counts.items())),
                "api_families": [
                    {
                        "family": family,
                        "probe_count": len(RUNTIME_API_PROBES[family]),
                        "present_probe_count": len(api_hits[family]),
                        "bounded_occurrence_count": sum(
                            len(offsets)
                            for offsets in api_hits[family].values()
                        ),
                    }
                    for family in sorted(RUNTIME_API_PROBES)
                ],
            }
        )
        private_artifacts[release] = {
            "api_hits": api_hits,
            "runtime_labels": [
                {
                    "offset": record.offset,
                    "encoding": record.encoding,
                    "classification": family,
                    "text": record.text,
                }
                for record, family in candidates
            ],
        }
    public = {
        "schema": "phoenix-mmi.runtime-inventory/v1",
        "analysis_mode": "fixed-api-probes-private-labels-public-aggregates",
        "artifacts": public_artifacts,
        "cross_version": {
            "shared_runtime_label_unique_count": len(
                candidate_sets["cd1"] & candidate_sets["cd3"]
            ),
            "cd1_only_runtime_label_unique_count": len(
                candidate_sets["cd1"] - candidate_sets["cd3"]
            ),
            "cd3_only_runtime_label_unique_count": len(
                candidate_sets["cd3"] - candidate_sets["cd1"]
            ),
        },
        "classification": {
            "runtime_platform": "CONFIRMED_VXWORKS_FAMILY",
            "task_service_lexical_inventory": "CONFIRMED_BOUNDED",
            "actual_scheduled_task_set": "NOT_ESTABLISHED",
            "task_entry_points": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "raw_strings_included": False,
            "string_hashes_included": False,
            "offsets_included": False,
            "firmware_bytes_included": False,
            "runtime_execution_observed": False,
        },
    }
    private = {
        "schema": "phoenix-mmi.runtime-inventory-private/v1",
        "publication_class": "PRIVATE_LOCAL",
        "artifacts": private_artifacts,
    }
    return public, private

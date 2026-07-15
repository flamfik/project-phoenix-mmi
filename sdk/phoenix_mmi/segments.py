"""Evidence-backed candidate segment model.

Segments produced here are analytical candidates. They must not be described as
vendor-defined flash regions until a table or loader behavior confirms them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re

from .binary import BinaryReader
from .entropy import EntropyWindow, entropy_transitions
from .fingerprint import FingerprintHit


@dataclass(frozen=True)
class CandidateSegment:
    index: int
    offset: int
    end: int
    length: int
    mean_entropy: float | None
    boundary_evidence: tuple[str, ...]
    status: str = "HYPOTHESIS"

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["boundary_evidence"] = list(self.boundary_evidence)
        return data


@dataclass(frozen=True)
class FillerRun:
    offset: int
    end: int
    length: int
    value: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def find_filler_runs(reader: BinaryReader, *, minimum_length: int = 4096) -> list[FillerRun]:
    if minimum_length <= 0:
        raise ValueError("minimum_length must be positive")
    data = reader.read(0, reader.size)
    pattern = re.compile(
        rb"\x00{" + str(minimum_length).encode("ascii") + rb",}|\xff{" + str(minimum_length).encode("ascii") + rb",}"
    )
    return [
        FillerRun(match.start(), match.end(), match.end() - match.start(), f"0x{match.group(0)[0]:02x}")
        for match in pattern.finditer(data)
    ]


def build_candidate_segments(
    size: int,
    fingerprints: list[FingerprintHit],
    entropy_windows: list[EntropyWindow],
    filler_runs: list[FillerRun] | None = None,
    *,
    entropy_delta: float = 1.25,
    include_weak_signatures: bool = False,
) -> list[CandidateSegment]:
    if size < 0:
        raise ValueError("size must be non-negative")
    if size == 0:
        return []

    evidence: dict[int, set[str]] = {0: {"artifact-start"}, size: {"artifact-end"}}
    for hit in fingerprints:
        if hit.confidence == "weak" and not include_weak_signatures:
            continue
        if hit.details and hit.details.get("validated") is False:
            continue
        if 0 < hit.offset < size:
            evidence.setdefault(hit.offset, set()).add(f"signature:{hit.name}")
    for transition in entropy_transitions(entropy_windows, minimum_delta=entropy_delta):
        offset = int(transition["offset"])
        if 0 < offset < size:
            evidence.setdefault(offset, set()).add(
                f"entropy-delta:{float(transition['delta']):+.3f}"
            )
    for run in filler_runs or []:
        if 0 < run.offset < size:
            evidence.setdefault(run.offset, set()).add(f"filler-start:{run.value}")
        if 0 < run.end < size:
            evidence.setdefault(run.end, set()).add(f"filler-end:{run.value}")

    boundaries = sorted(evidence)
    segments: list[CandidateSegment] = []
    for index, (start, end) in enumerate(zip(boundaries, boundaries[1:])):
        overlapping = [
            window.entropy
            for window in entropy_windows
            if window.offset < end and window.offset + window.length > start
        ]
        mean_entropy = round(sum(overlapping) / len(overlapping), 6) if overlapping else None
        segments.append(
            CandidateSegment(
                index=index,
                offset=start,
                end=end,
                length=end - start,
                mean_entropy=mean_entropy,
                boundary_evidence=tuple(sorted(evidence[start])),
            )
        )
    return segments

"""Declarative, bounded checksum experiments with explicit non-match results."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import zlib


CHECKSUM_EXPERIMENT_SCHEMA = "phoenix-mmi.checksum-experiment/v1"
MAX_EXPERIMENT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ChecksumRegion:
    region_id: str
    offset: int
    length: int

    def __post_init__(self) -> None:
        if not self.region_id or self.offset < 0 or self.length < 0:
            raise ValueError("invalid checksum region")


@dataclass(frozen=True)
class ChecksumExperiment:
    experiment_id: str
    algorithm: str
    region: ChecksumRegion
    expected: int | None = None

    def __post_init__(self) -> None:
        if self.algorithm not in {"CRC32/IEEE", "ADLER32", "SUM16"}:
            raise ValueError(f"unsupported checksum algorithm: {self.algorithm}")
        if self.expected is not None and not 0 <= self.expected <= 0xFFFFFFFF:
            raise ValueError("expected checksum exceeds 32-bit range")


@dataclass(frozen=True)
class ChecksumExperimentResult:
    experiment_id: str
    algorithm: str
    region_id: str
    offset: int
    length: int
    actual_hex: str
    expected_hex: str | None
    outcome: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _calculate(data: bytes, algorithm: str) -> int:
    if algorithm == "CRC32/IEEE":
        return zlib.crc32(data) & 0xFFFFFFFF
    if algorithm == "ADLER32":
        return zlib.adler32(data) & 0xFFFFFFFF
    if algorithm == "SUM16":
        return sum(data) & 0xFFFF
    raise ValueError(f"unsupported checksum algorithm: {algorithm}")


def run_checksum_experiments(
    data: bytes, experiments: tuple[ChecksumExperiment, ...]
) -> tuple[ChecksumExperimentResult, ...]:
    if len(data) > MAX_EXPERIMENT_BYTES:
        raise ValueError("checksum input exceeds safety bound")
    ids = [item.experiment_id for item in experiments]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate checksum experiment ID")
    output = []
    for item in sorted(experiments, key=lambda value: value.experiment_id):
        region = item.region
        end = region.offset + region.length
        if end > len(data):
            raise ValueError(f"checksum region exceeds input: {region.region_id}")
        actual = _calculate(data[region.offset:end], item.algorithm)
        expected = item.expected
        output.append(
            ChecksumExperimentResult(
                item.experiment_id,
                item.algorithm,
                region.region_id,
                region.offset,
                region.length,
                f"{actual:08x}",
                None if expected is None else f"{expected:08x}",
                (
                    "OBSERVED"
                    if expected is None
                    else "MATCH"
                    if actual == expected
                    else "NO_MATCH"
                ),
            )
        )
    return tuple(output)


def checksum_experiment_report(
    experiments: tuple[ChecksumExperiment, ...],
    results: tuple[ChecksumExperimentResult, ...],
) -> dict[str, object]:
    if len(experiments) != len(results):
        raise ValueError("experiment/result count differs")
    counts: dict[str, int] = {}
    for result in results:
        counts[result.outcome] = counts.get(result.outcome, 0) + 1
    return {
        "schema": CHECKSUM_EXPERIMENT_SCHEMA,
        "experiment_count": len(experiments),
        "outcome_counts": dict(sorted(counts.items())),
        "results": [item.to_dict() for item in results],
        "unresolved_integrity_questions": [
            "METAINFO MetafileChecksum",
            "YIM integrity32/integrity16",
        ],
        "unknown_algorithm_bypass_present": False,
        "raw_artifact_bytes_included": False,
    }

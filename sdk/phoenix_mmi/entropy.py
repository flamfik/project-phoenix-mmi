"""Shannon entropy profiling for candidate binary-region discovery."""

from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import asdict, dataclass

from .binary import BinaryReader


@dataclass(frozen=True)
class EntropyWindow:
    offset: int
    length: int
    entropy: float
    band: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(data).values()
    )


def entropy_band(value: float) -> str:
    if value < 1.0:
        return "very-low"
    if value < 5.0:
        return "low"
    if value < 7.2:
        return "mixed"
    return "high"


def entropy_profile(
    reader: BinaryReader,
    *,
    window_size: int = 64 * 1024,
    step: int | None = None,
) -> list[EntropyWindow]:
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    step = window_size if step is None else step
    if step <= 0:
        raise ValueError("step must be positive")

    windows: list[EntropyWindow] = []
    for offset in range(0, reader.size, step):
        data = reader.read(offset, window_size)
        if not data:
            break
        value = shannon_entropy(data)
        windows.append(EntropyWindow(offset, len(data), round(value, 6), entropy_band(value)))
    return windows


def entropy_transitions(
    windows: list[EntropyWindow],
    *,
    minimum_delta: float = 1.25,
) -> list[dict[str, object]]:
    transitions: list[dict[str, object]] = []
    for previous, current in zip(windows, windows[1:]):
        delta = current.entropy - previous.entropy
        if abs(delta) >= minimum_delta:
            transitions.append(
                {
                    "offset": current.offset,
                    "from": previous.entropy,
                    "to": current.entropy,
                    "delta": round(delta, 6),
                }
            )
    return transitions


def summarize_entropy(windows: list[EntropyWindow]) -> dict[str, object]:
    if not windows:
        return {"window_count": 0}
    values = [window.entropy for window in windows]
    bands = Counter(window.band for window in windows)
    return {
        "window_count": len(windows),
        "minimum": min(values),
        "maximum": max(values),
        "mean": round(statistics.fmean(values), 6),
        "median": round(statistics.median(values), 6),
        "bands": dict(sorted(bands.items())),
    }

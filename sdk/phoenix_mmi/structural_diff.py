"""Generic deterministic structural diff for JSON-compatible values."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Mapping, Sequence


STRUCTURAL_DIFF_SCHEMA = "phoenix-mmi.structural-diff/v1"


@dataclass(frozen=True)
class Difference:
    path: str
    kind: str
    left_type: str | None
    right_type: str | None
    left_digest: str | None = None
    right_digest: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _typename(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()[:16]


def structural_diff(left: object, right: object) -> dict[str, object]:
    differences: list[Difference] = []

    def walk(a: object, b: object, path: str) -> None:
        if type(a) is not type(b):
            differences.append(
                Difference(path, "TYPE_CHANGED", _typename(a), _typename(b))
            )
            return
        if isinstance(a, dict):
            left_map: Mapping[str, object] = a
            right_map: Mapping[str, object] = b  # type: ignore[assignment]
            for key in sorted(set(left_map) | set(right_map)):
                child = f"{path}/{key.replace('~', '~0').replace('/', '~1')}"
                if key not in left_map:
                    differences.append(
                        Difference(child, "ADDED", None, _typename(right_map[key]))
                    )
                elif key not in right_map:
                    differences.append(
                        Difference(child, "REMOVED", _typename(left_map[key]), None)
                    )
                else:
                    walk(left_map[key], right_map[key], child)
            return
        if isinstance(a, list):
            left_list: Sequence[object] = a
            right_list: Sequence[object] = b  # type: ignore[assignment]
            common = min(len(left_list), len(right_list))
            for index in range(common):
                walk(left_list[index], right_list[index], f"{path}/{index}")
            for index in range(common, len(left_list)):
                differences.append(
                    Difference(
                        f"{path}/{index}", "REMOVED", _typename(left_list[index]), None
                    )
                )
            for index in range(common, len(right_list)):
                differences.append(
                    Difference(
                        f"{path}/{index}", "ADDED", None, _typename(right_list[index])
                    )
                )
            return
        if a != b:
            differences.append(
                Difference(
                    path,
                    "VALUE_CHANGED",
                    _typename(a),
                    _typename(b),
                    _digest(a),
                    _digest(b),
                )
            )

    walk(left, right, "")
    kind_counts: dict[str, int] = {}
    for item in differences:
        kind_counts[item.kind] = kind_counts.get(item.kind, 0) + 1
    return {
        "schema": STRUCTURAL_DIFF_SCHEMA,
        "equal": not differences,
        "difference_count": len(differences),
        "kind_counts": dict(sorted(kind_counts.items())),
        "differences": [item.to_dict() for item in differences],
        "scalar_values_published": False,
    }

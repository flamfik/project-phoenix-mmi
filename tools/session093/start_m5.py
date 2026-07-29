#!/usr/bin/env python3
"""Freeze and publish the Session 093 M5 UI Prototype baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phoenix_mmi.ui_prototype_audit import build_m5_baseline


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    m4_closure = json.loads(
        (
            repository
            / "research/milestones/m4/session092/milestone-m4-closure.json"
        ).read_text(encoding="utf-8")
    )
    first = build_m5_baseline(repository, m4_closure)
    second = build_m5_baseline(repository, m4_closure)
    if first != second:
        raise ValueError("Session 093 baseline is not deterministic")
    if (
        first["classification"]["m5_entry"] != "PASS"
        or first["classification"]["m5_status"] != "IN_PROGRESS"
        or first["classification"]["safe_mutation_ready"] is not False
    ):
        raise ValueError("Session 093 M5 gate failed")
    _write(args.public_output, first)
    print(
        json.dumps(
            {
                "session": first["session"],
                "m5": first["classification"]["m5_status"],
                "criteria": (
                    f"{first['exit_criteria_passed']}/"
                    f"{first['exit_criteria_total']}"
                ),
                "graph": first["operational_graph_version"],
                "deterministic": True,
                "offline_only": first["publication_safety"]["offline_only"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

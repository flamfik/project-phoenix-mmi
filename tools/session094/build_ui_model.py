#!/usr/bin/env python3
"""Build the Session 094 typed Phoenix UI information architecture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phoenix_mmi.ui_model import (
    build_phoenix_information_architecture,
    build_public_information_architecture,
)
from phoenix_mmi.ui_prototype_audit import advance_m5_progress


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
    baseline = json.loads(
        (
            repository
            / "research/milestones/m5/session093/m5-ui-prototype-baseline.json"
        ).read_text(encoding="utf-8")
    )
    first = build_public_information_architecture(
        build_phoenix_information_architecture()
    )
    second = build_public_information_architecture(
        build_phoenix_information_architecture()
    )
    if first != second:
        raise ValueError("Session 094 information model is not deterministic")
    report = advance_m5_progress(
        repository,
        baseline,
        session="094",
        transitions=[
            {
                "capability_id": "M5-CAP-010",
                "from_status": "MISSING",
                "to_status": "IMPLEMENTED",
                "probe_kind": "python-symbol",
                "probe_target": (
                    "phoenix_mmi.ui_model:"
                    "build_phoenix_information_architecture"
                ),
                "evidence": "Session 094 and SPEC-103",
                "limitation": (
                    "original prototype model is not the firmware menu"
                ),
            }
        ],
        graph_version="v86",
        graph_node_id="m5-information-architecture",
    )
    report["information_architecture"] = first
    report["determinism"] = {
        "repeat_run_equal": True,
        "model_order_stable": True,
    }
    if (
        report["exit_criteria_passed"] != 1
        or report["classification"]["m5_status"] != "IN_PROGRESS"
        or report["classification"]["safe_mutation_ready"] is not False
    ):
        raise ValueError("Session 094 progress gate failed")
    _write(args.public_output, report)
    print(
        json.dumps(
            {
                "session": report["session"],
                "criteria": (
                    f"{report['exit_criteria_passed']}/"
                    f"{report['exit_criteria_total']}"
                ),
                "graph": report["operational_graph_version"],
                "screens": first["topology"]["screen_count"],
                "entries": first["topology"]["entry_count"],
                "deterministic": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

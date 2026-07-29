#!/usr/bin/env python3
"""Generate the publication-safe Session 066 M2 foundation report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phoenix_mmi.report import write_json
from phoenix_mmi.toolkit_audit import build_m2_foundation_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit the M2 Analysis Toolkit capability baseline"
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path("."),
    )
    parser.add_argument(
        "--m1-closure",
        type=Path,
        default=Path(
            "research/milestones/m1/session065/"
            "milestone-m1-closure.json"
        ),
    )
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "--public-output",
        type=Path,
        required=True,
    )
    args = parser.parse_args()

    m1_closure = json.loads(
        args.m1_closure.read_text(encoding="utf-8")
    )
    report = build_m2_foundation_report(
        args.repository_root,
        m1_closure,
    )
    write_json(report, args.output / "session066.analysis.json")
    write_json(report, args.public_output)
    if report["classification"]["m2_entry"] != "PASS":
        raise SystemExit("M2 entry capability audit failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

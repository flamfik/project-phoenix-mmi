#!/usr/bin/env python3
"""Reproduce Sessions 061-065 and apply the M1 charter exit gate."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from phoenix_mmi.m1_closure import (
    audit_m1_evidence,
    audit_m1_media,
    audit_update_model,
    build_m1_closure,
    classify_m1_members,
    load_iso_images,
)
from phoenix_mmi.report import write_json


def _register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["artifact"]: row for row in csv.DictReader(handle)}


def _load_json(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(
            f"unsupported schema in {path}: {report.get('schema')!r}"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the read-only Sessions 061-065 M1 closure cycle"
        )
    )
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd2", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path("."),
    )
    parser.add_argument(
        "--firmware-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    parser.add_argument(
        "--session060",
        type=Path,
        default=Path(
            "research/navigation-media/session060/"
            "firmware-evidence-map-v2.json"
        ),
    )
    args = parser.parse_args()

    images = load_iso_images(
        {
            "cd1": args.firmware_cd1,
            "cd2": args.firmware_cd2,
            "cd3": args.firmware_cd3,
        }
    )
    register = _register(args.firmware_register)
    session060 = _load_json(
        args.session060,
        "phoenix-mmi.firmware-evidence-map/v2",
    )

    reports = [
        audit_m1_media(images, register),
        classify_m1_members(images),
        audit_update_model(images),
        audit_m1_evidence(args.repository_root),
    ]
    reports.append(build_m1_closure(session060, reports))

    names = {
        "061": "m1-media-reproduction.public.json",
        "062": "m1-artifact-routing.public.json",
        "063": "m1-update-model-reproduction.public.json",
        "064": "m1-evidence-traceability.json",
        "065": "milestone-m1-closure.json",
    }
    for report in reports:
        session = str(report["session"])
        write_json(
            report,
            args.output / f"session{session}.analysis.json",
        )
        write_json(
            report,
            args.public_root / f"session{session}" / names[session],
        )

    if reports[-1]["classification"]["milestone_m1"] != "COMPLETE":
        raise SystemExit("M1 closure gate did not pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

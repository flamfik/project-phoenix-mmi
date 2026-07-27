#!/usr/bin/env python3
"""Build publication-safe Session 032 relocation support reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.relocation_breakpoints import (
    analyze_relocation_breakpoints,
    build_public_relocation_breakpoint_report,
    correlate_relocation_breakpoints,
)
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["artifact"]: row for row in csv.DictReader(handle)
        }


def _load_json(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(
            f"unsupported schema in {path}: {report.get('schema')!r}"
        )
    return report


def _verify_iso(
    image: ISO9660Image, row: dict[str, str]
) -> None:
    if image.path.stat().st_size != int(row["size_bytes"]):
        raise ValueError(
            f"registered size mismatch for {image.path.name}"
        )
    if image.sha256() != row["sha256"].lower():
        raise ValueError(
            f"registered SHA-256 mismatch for {image.path.name}"
        )


def _disc_report(
    comparison: dict[str, object], *, side: str
) -> dict[str, object]:
    prefix = "left" if side == "cd1" else "right"
    return {
        "schema": "phoenix-mmi.relocation-breakpoint-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "artifact": {
            "sha256": comparison[f"{prefix}_artifact_sha256"],
            "source_path_included": False,
        },
        "classification": comparison["classification"],
        "direct_link_delta_families": comparison[
            "direct_link_delta_families"
        ],
        "support_zones": comparison["support_zones"],
        "breakpoint_brackets": comparison[
            "breakpoint_brackets"
        ],
        "pool_pair_reconciliation": comparison[
            "pool_pair_reconciliation"
        ],
        "limits": comparison["limits"],
        "publication_safety": comparison[
            "publication_safety"
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build relocation support zones and breakpoint brackets from "
            "previously confirmed bilateral anchors"
        )
    )
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "--public-output", type=Path, required=True
    )
    parser.add_argument(
        "--firmware-register",
        type=Path,
        default=Path(
            "research/firmware-5570/manifests/artifacts.csv"
        ),
    )
    parser.add_argument(
        "--session003-root",
        type=Path,
        default=Path("research/firmware-5570/session003"),
    )
    parser.add_argument(
        "--firmware-root",
        type=Path,
        default=Path("research/firmware-5570"),
    )
    parser.add_argument(
        "--navigation-root",
        type=Path,
        default=Path("research/navigation-media"),
    )
    args = parser.parse_args()

    rows = _register(args.firmware_register)
    summaries = {
        disc: _load_json(
            args.session003_root
            / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    reports = {
        "session005_left": _load_json(
            args.firmware_root
            / "session005/cd1-resource-bundle.public.json",
            "phoenix-mmi.resource-bundle/v1",
        ),
        "session005_right": _load_json(
            args.firmware_root
            / "session005/cd3-resource-bundle.public.json",
            "phoenix-mmi.resource-bundle/v1",
        ),
        "session008": _load_json(
            args.firmware_root
            / (
                "session008/"
                "cd1-cd3.firmware-operational-model.comparison.json"
            ),
            "phoenix-mmi.firmware-operational-model-comparison/v1",
        ),
        "session009": _load_json(
            args.firmware_root
            / (
                "session009/"
                "cd1-cd3.navigation-storage-boundary.comparison.json"
            ),
            "phoenix-mmi.navigation-storage-boundary-comparison/v1",
        ),
        "session015": _load_json(
            args.navigation_root
            / (
                "session015/"
                "cd1-cd3.optical-callgraph.comparison.json"
            ),
            "phoenix-mmi.optical-navigation-callgraph-comparison/v1",
        ),
        "session030": _load_json(
            args.navigation_root
            / (
                "session030/"
                "cd1-cd3.literal-pool-boundary.comparison.json"
            ),
            "phoenix-mmi.literal-pool-boundary-comparison/v1",
        ),
        "session031": _load_json(
            args.navigation_root
            / (
                "session031/"
                "cd1-cd3.piecewise-link-map.comparison.json"
            ),
            "phoenix-mmi.piecewise-link-map-comparison/v1",
        ),
    }
    prior_correlation = _load_json(
        args.navigation_root
        / "session031/piecewise-link-map-correlation.json",
        "phoenix-mmi.piecewise-link-map-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session032-"
    ) as temporary:
        readers = {}
        for disc, iso_path, member_path in (
            ("cd1", args.firmware_cd1, CD1_MEMBER),
            ("cd3", args.firmware_cd3, CD3_MEMBER),
        ):
            row = rows.get(iso_path.name)
            if row is None:
                raise ValueError(
                    f"{iso_path.name} is absent from the firmware register"
                )
            image = ISO9660Image(iso_path)
            _verify_iso(image, row)
            member = image.find_path(member_path)
            extracted = image.extract(
                member,
                Path(temporary) / disc / Path(member.path).name,
            )
            reader = BinaryReader(extracted)
            if (
                reader.sha256()
                != summaries[disc]["artifact"]["sha256"]
            ):
                raise ValueError(
                    f"{disc} principal-image hash differs from Session 003"
                )
            readers[disc] = reader

        comparison = analyze_relocation_breakpoints(
            readers["cd1"],
            readers["cd3"],
            **reports,
        )

    correlation = correlate_relocation_breakpoints(
        prior_correlation, comparison
    )
    output_reports = {
        "cd1-relocation-breakpoints.public.json": _disc_report(
            comparison, side="cd1"
        ),
        "cd3-relocation-breakpoints.public.json": _disc_report(
            comparison, side="cd3"
        ),
        "cd1-cd3.relocation-breakpoints.comparison.json": (
            comparison
        ),
        "relocation-breakpoint-correlation.json": correlation,
    }
    for name, report in output_reports.items():
        write_json(
            report,
            args.output / name.replace(".public", ".analysis"),
        )
        write_json(
            build_public_relocation_breakpoint_report(report),
            args.public_output / name,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

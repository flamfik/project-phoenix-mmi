#!/usr/bin/env python3
"""Build publication-safe Session 038 exact run-gap topology reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.report import write_json
from phoenix_mmi.run_gap_topology import (
    analyze_run_gap_topology,
    build_public_run_gap_report,
    correlate_run_gap_topology,
)


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


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


def _verify_iso(image: ISO9660Image, row: dict[str, str]) -> None:
    if image.path.stat().st_size != int(row["size_bytes"]):
        raise ValueError(f"registered size mismatch for {image.path.name}")
    if image.sha256() != row["sha256"].lower():
        raise ValueError(f"registered SHA-256 mismatch for {image.path.name}")


def _disc_report(
    comparison: dict[str, object], *, side: str
) -> dict[str, object]:
    prefix = "left" if side == "cd1" else "right"
    if side == "cd1":
        observed = {
            "role": "source-overlap",
            "start": comparison["search_contract"]["overlap_start"],
            "end": comparison["search_contract"]["overlap_end"],
            "length": comparison["search_contract"]["overlap_length"],
        }
    else:
        observed = {
            "role": "two-fixed-mapped-overlaps",
            "mapping_count": 2,
            "length_each": comparison["search_contract"]["overlap_length"],
            "mapped_offsets_published": False,
        }
    return {
        "schema": "phoenix-mmi.run-gap-topology-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "artifact": {
            "sha256": comparison[f"{prefix}_artifact_sha256"],
            "source_path_included": False,
        },
        "observed_region": observed,
        "search_contract": comparison["search_contract"],
        "summary": comparison["summary"],
        "classification": comparison["classification"],
        "limits": comparison["limits"],
        "publication_safety": comparison["publication_safety"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Bridge exact runs only across fixed one-byte gaps inside "
            "the Session 037 RZ-012 micro-island"
        )
    )
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument(
        "--firmware-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    parser.add_argument(
        "--session003-root",
        type=Path,
        default=Path("research/firmware-5570/session003"),
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
            args.session003_root / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    prior = _load_json(
        args.navigation_root
        / "session037/cd1-cd3.micro-island.comparison.json",
        "phoenix-mmi.micro-island-comparison/v1",
    )
    prior_correlation = _load_json(
        args.navigation_root
        / "session037/micro-island-correlation.json",
        "phoenix-mmi.micro-island-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session038-"
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
            if reader.sha256() != summaries[disc]["artifact"]["sha256"]:
                raise ValueError(
                    f"{disc} principal-image hash differs from Session 003"
                )
            readers[disc] = reader

        comparison = analyze_run_gap_topology(
            readers["cd1"], readers["cd3"], prior
        )

    correlation = correlate_run_gap_topology(
        prior_correlation, comparison
    )
    write_json(
        comparison,
        args.output / "cd1-cd3.run-gap-topology.analysis.json",
    )
    public = build_public_run_gap_report(comparison)
    reports = {
        "cd1-cd3.run-gap-topology.comparison.json": public,
        "cd1-run-gap-topology.public.json": (
            build_public_run_gap_report(_disc_report(public, side="cd1"))
        ),
        "cd3-run-gap-topology.public.json": (
            build_public_run_gap_report(_disc_report(public, side="cd3"))
        ),
        "run-gap-topology-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.public_output / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

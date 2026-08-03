#!/usr/bin/env python3
"""Build publication-safe Session 039 registered-provenance reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.registered_provenance import (
    analyze_registered_provenance,
    build_public_registered_provenance_report,
    correlate_registered_provenance,
)
from phoenix_mmi.report import write_json


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
    key = "left" if side == "cd1" else "right"
    target_key = "left" if side == "cd1" else "rz012_right"
    return {
        "schema": "phoenix-mmi.registered-provenance-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "artifact": {
            "sha256": comparison[f"{key}_artifact_sha256"],
            "source_path_included": False,
        },
        "target": {
            "component_id": comparison["target"]["component_id"],
            "interval": comparison["target"][target_key],
            "span": comparison["target"]["span"],
        },
        "search_contract": comparison["search_contract"],
        "registered_families": comparison["registered_families"],
        "reorder_context": comparison["reorder_context"],
        "classification": comparison["classification"],
        "limits": comparison["limits"],
        "publication_safety": comparison["publication_safety"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Audit only prior registered reference and descriptor families "
            "against the fixed Session 038 component"
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
        "--session007-root",
        type=Path,
        default=Path("research/firmware-5570/session007"),
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
        / "session038/cd1-cd3.run-gap-topology.comparison.json",
        "phoenix-mmi.run-gap-topology-comparison/v1",
    )
    prior_correlation = _load_json(
        args.navigation_root
        / "session038/run-gap-topology-correlation.json",
        "phoenix-mmi.run-gap-topology-correlation/v1",
    )
    registries = {
        "reference_left": _load_json(
            args.session007_root / "cd1-reference-graph.public.json",
            "phoenix-mmi.reference-graph/v1",
        ),
        "reference_right": _load_json(
            args.session007_root / "cd3-reference-graph.public.json",
            "phoenix-mmi.reference-graph/v1",
        ),
        "descriptor_lineage": _load_json(
            args.navigation_root
            / "session017/cd1-cd3.descriptor-lineage.comparison.json",
            "phoenix-mmi.descriptor-producer-lineage-comparison/v1",
        ),
        "literal_pool": _load_json(
            args.navigation_root
            / "session030/cd1-cd3.literal-pool-boundary.comparison.json",
            "phoenix-mmi.literal-pool-boundary-comparison/v1",
        ),
        "breakpoints": _load_json(
            args.navigation_root
            / "session032/cd1-cd3.relocation-breakpoints.comparison.json",
            "phoenix-mmi.relocation-breakpoint-comparison/v1",
        ),
        "descriptors": _load_json(
            args.navigation_root
            / "session033/cd1-cd3.relocation-descriptors.comparison.json",
            "phoenix-mmi.relocation-descriptor-comparison/v1",
        ),
    }

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session039-"
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

        comparison = analyze_registered_provenance(
            readers["cd1"], readers["cd3"], prior, registries
        )

    correlation = correlate_registered_provenance(
        prior_correlation, comparison
    )
    write_json(
        comparison,
        args.output / "cd1-cd3.registered-provenance.analysis.json",
    )
    public = build_public_registered_provenance_report(comparison)
    reports = {
        "cd1-cd3.registered-provenance.comparison.json": public,
        "cd1-registered-provenance.public.json": (
            build_public_registered_provenance_report(
                _disc_report(public, side="cd1")
            )
        ),
        "cd3-registered-provenance.public.json": (
            build_public_registered_provenance_report(
                _disc_report(public, side="cd3")
            )
        ),
        "registered-provenance-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.public_output / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

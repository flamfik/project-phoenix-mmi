#!/usr/bin/env python3
"""Build publication-safe Session 023 continuation-contract reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.continuation_contract import (
    analyze_internal_continuation_contract,
    build_public_internal_continuation_report,
    correlate_internal_continuation_contract,
)
from phoenix_mmi.iso9660 import ISO9660Image
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
    prefix = "left" if side == "cd1" else "right"
    return {
        "schema": "phoenix-mmi.internal-continuation-contract-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "artifact": {
            "sha256": comparison[f"{prefix}_artifact_sha256"],
            "source_path_included": False,
        },
        "selected_internal_address_contract": comparison[
            "selected_internal_address_contracts"
        ][prefix],
        "generic_address_record_family": comparison[
            "generic_address_record_family"
        ],
        "classification": comparison["classification"],
        "publication_safety": comparison["publication_safety"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Trace Session 022 internal-address uses without promoting them "
            "to owner entries"
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
        "--session022-root",
        type=Path,
        default=Path("research/navigation-media/session022"),
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
        args.session022_root
        / "cd1-cd3.owner-ingress-state.comparison.json",
        "phoenix-mmi.owner-ingress-state-comparison/v1",
    )
    prior_correlation = _load_json(
        args.session022_root / "owner-ingress-state-correlation.json",
        "phoenix-mmi.owner-ingress-state-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session023-"
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
                member, Path(temporary) / disc / Path(member.path).name
            )
            reader = BinaryReader(extracted)
            if reader.sha256() != summaries[disc]["artifact"]["sha256"]:
                raise ValueError(
                    f"{disc} principal-image hash differs from Session 003"
                )
            readers[disc] = reader

        comparison = analyze_internal_continuation_contract(
            readers["cd1"], readers["cd3"], prior
        )

    correlation = correlate_internal_continuation_contract(
        prior_correlation, comparison
    )
    reports = {
        "cd1-internal-continuation-contract.public.json": _disc_report(
            comparison, side="cd1"
        ),
        "cd3-internal-continuation-contract.public.json": _disc_report(
            comparison, side="cd3"
        ),
        "cd1-cd3.internal-continuation-contract.comparison.json": comparison,
        "internal-continuation-contract-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.output / name.replace(".public", ".analysis"))
        write_json(
            build_public_internal_continuation_report(report),
            args.public_output / name,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

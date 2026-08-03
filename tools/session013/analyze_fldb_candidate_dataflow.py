#!/usr/bin/env python3
"""Build read-only, publication-safe Session 013 corrected parser reports."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.parser_dataflow import (
    analyze_fldb_candidate_dataflow,
    build_public_fldb_candidate_report,
    compare_fldb_candidate_dataflow,
    correlate_corrected_parser_model,
)
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _firmware_register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["artifact"]: row for row in csv.DictReader(handle)}


def _load_json(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(f"unsupported schema in {path}: {report.get('schema')!r}")
    return report


def _verify_iso(image: ISO9660Image, row: dict[str, str]) -> None:
    if image.path.stat().st_size != int(row["size_bytes"]):
        raise ValueError(f"registered size mismatch for {image.path.name}")
    if image.sha256() != row["sha256"].lower():
        raise ValueError(f"registered SHA-256 mismatch for {image.path.name}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Trace the former FLDB 0x220 candidates through bounded SH register "
            "dataflow and correct the operational graph without executing firmware"
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
        "--firmware-research-root",
        type=Path,
        default=Path("research/firmware-5570"),
    )
    parser.add_argument(
        "--session012-root",
        type=Path,
        default=Path("research/navigation-media/session012"),
    )
    args = parser.parse_args()

    firmware_rows = _firmware_register(args.firmware_register)
    prior_summaries = {
        disc: _load_json(
            args.firmware_research_root
            / "session003"
            / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    constant_reports = {
        disc: _load_json(
            args.session012_root / f"{disc}-parser-constants.public.json",
            "phoenix-mmi.parser-constant-probes/v1",
        )
        for disc in ("cd1", "cd3")
    }
    prior_correlation = _load_json(
        args.session012_root / "firmware-payload-parser.comparison.json",
        "phoenix-mmi.payload-parser-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    reports: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session013-") as temporary:
        temporary_root = Path(temporary)
        for disc, iso_path, member_path in (
            ("cd1", args.firmware_cd1, CD1_MEMBER),
            ("cd3", args.firmware_cd3, CD3_MEMBER),
        ):
            row = firmware_rows.get(iso_path.name)
            if row is None:
                raise ValueError(f"{iso_path.name} is absent from the firmware register")
            image = ISO9660Image(iso_path)
            _verify_iso(image, row)
            member = image.find_path(member_path)
            extracted = image.extract(
                member, temporary_root / disc / Path(member.path).name
            )
            reader = BinaryReader(extracted)
            if reader.sha256() != prior_summaries[disc]["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            if reader.sha256() != constant_reports[disc]["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 012")
            reports[disc] = analyze_fldb_candidate_dataflow(
                reader, constant_reports[disc]
            )

    comparison = compare_fldb_candidate_dataflow(reports["cd1"], reports["cd3"])
    correlation = correlate_corrected_parser_model(prior_correlation, comparison)
    correlation["external_context"] = {
        "used_as_local_artifact_evidence": False,
        "sources": [
            {
                "purpose": "Authoritative SH-3 instruction encodings and semantics",
                "url": (
                    "https://www.renesas.com/en/document/mas/"
                    "sh-3sh-3esh3-dsp-software-manual?language=en"
                ),
            },
            {
                "purpose": (
                    "Authoritative SuperH compiler context for R4-R7 register "
                    "parameter assignment"
                ),
                "url": (
                    "https://www.renesas.com/en/document/apn/"
                    "superh-cc-compiler-package-application-note"
                ),
            },
        ],
    }

    for disc in ("cd1", "cd3"):
        write_json(
            reports[disc], args.output / f"{disc}-fldb-candidate-dataflow.analysis.json"
        )
        write_json(
            build_public_fldb_candidate_report(reports[disc]),
            args.public_output / f"{disc}-fldb-candidate-dataflow.public.json",
        )
    write_json(
        comparison,
        args.output / "cd1-cd3.fldb-candidate-dataflow.comparison.json",
    )
    write_json(
        comparison,
        args.public_output / "cd1-cd3.fldb-candidate-dataflow.comparison.json",
    )
    write_json(
        correlation, args.output / "corrected-parser-correlation.json"
    )
    write_json(
        correlation, args.public_output / "corrected-parser-correlation.json"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build read-only, publication-safe Session 014 global parser reports."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.parser_search import (
    build_public_global_parser_report,
    compare_global_fldb_parser_search,
    correlate_global_fldb_parser_search,
    scan_global_fldb_parser_candidates,
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
            "Globally screen cross-version FLDB parser candidates using role-sensitive "
            "record-stride, header-read, endian and provenance gates"
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
        "--session010-root",
        type=Path,
        default=Path("research/firmware-5570/session010"),
    )
    parser.add_argument(
        "--session013-root",
        type=Path,
        default=Path("research/navigation-media/session013"),
    )
    args = parser.parse_args()

    rows = _register(args.firmware_register)
    summaries = {
        disc: _load_json(
            args.firmware_research_root
            / "session003"
            / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    contract = _load_json(
        args.session010_root / "cd1-cd3.navigation-dataflow.comparison.json",
        "phoenix-mmi.navigation-dataflow-comparison/v1",
    )
    prior_correlation = _load_json(
        args.session013_root / "corrected-parser-correlation.json",
        "phoenix-mmi.corrected-parser-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    reports: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session014-") as temporary:
        temporary_root = Path(temporary)
        for disc, side, iso_path, member_path in (
            ("cd1", "left", args.firmware_cd1, CD1_MEMBER),
            ("cd3", "right", args.firmware_cd3, CD3_MEMBER),
        ):
            row = rows.get(iso_path.name)
            if row is None:
                raise ValueError(f"{iso_path.name} is absent from the firmware register")
            image = ISO9660Image(iso_path)
            _verify_iso(image, row)
            member = image.find_path(member_path)
            extracted = image.extract(
                member, temporary_root / disc / Path(member.path).name
            )
            reader = BinaryReader(extracted)
            if reader.sha256() != summaries[disc]["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            reports[disc] = scan_global_fldb_parser_candidates(
                reader, contract, side=side
            )

    comparison = compare_global_fldb_parser_search(reports["cd1"], reports["cd3"])
    correlation = correlate_global_fldb_parser_search(
        prior_correlation, comparison
    )
    correlation["external_context"] = {
        "used_as_local_artifact_evidence": False,
        "sources": [
            {
                "purpose": "Authoritative SH-3 instruction and delay-slot semantics",
                "url": (
                    "https://www.renesas.com/en/document/mas/"
                    "sh-3sh-3esh3-dsp-software-manual?language=en"
                ),
            },
            {
                "purpose": "Confirmed media-side FLDB grammar comes from Session 011",
                "local_reference": "SPEC-018",
            },
        ],
    }

    for disc in ("cd1", "cd3"):
        write_json(
            reports[disc],
            args.output / f"{disc}-global-fldb-parser-search.analysis.json",
        )
        write_json(
            build_public_global_parser_report(reports[disc]),
            args.public_output / f"{disc}-global-fldb-parser-search.public.json",
        )
    write_json(
        comparison,
        args.output / "cd1-cd3.global-fldb-parser-search.comparison.json",
    )
    write_json(
        comparison,
        args.public_output / "cd1-cd3.global-fldb-parser-search.comparison.json",
    )
    write_json(
        correlation, args.output / "global-fldb-parser-correlation.json"
    )
    write_json(
        correlation,
        args.public_output / "global-fldb-parser-correlation.json",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build read-only, publication-safe Session 012 payload/parser reports."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.map_payload import (
    analyze_navigation_payloads,
    build_public_navigation_payload_report,
)
from phoenix_mmi.parser_contract import (
    compare_parser_constants,
    correlate_payload_parser_contract,
    scan_parser_constants,
)
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _artifact_register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["artifact_id"]: row for row in csv.DictReader(handle)}


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
    actual = image.sha256()
    if actual != row["sha256"].lower():
        raise ValueError(f"registered SHA-256 mismatch for {image.path.name}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate proprietary navigation-payload family structures and "
            "probe exact parser-related constants in two principal firmware images"
        )
    )
    parser.add_argument("map_iso", type=Path)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--firmware-cd1", type=Path, required=True)
    parser.add_argument("--firmware-cd3", type=Path, required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument(
        "--media-register",
        type=Path,
        default=Path("research/navigation-media/manifests/artifacts.csv"),
    )
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
        "--prior-contract",
        type=Path,
        default=Path(
            "research/navigation-media/session011/"
            "firmware-media-contract.comparison.json"
        ),
    )
    args = parser.parse_args()

    media_rows = _artifact_register(args.media_register)
    media_row = media_rows.get(args.artifact_id)
    if media_row is None:
        raise ValueError(f"{args.artifact_id} is absent from the media register")
    firmware_rows = _firmware_register(args.firmware_register)
    prior_contract = _load_json(
        args.prior_contract, "phoenix-mmi.firmware-media-contract/v1"
    )
    prior_summaries = {
        disc: _load_json(
            args.firmware_research_root
            / "session003"
            / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    map_image = ISO9660Image(args.map_iso)
    _verify_iso(map_image, media_row)
    payloads = analyze_navigation_payloads(
        map_image,
        artifact_id=args.artifact_id,
        expected_sha256=media_row["sha256"],
    )

    firmware_reports: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session012-") as temporary:
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
            firmware_reports[disc] = scan_parser_constants(reader)

    constants = compare_parser_constants(
        firmware_reports["cd1"], firmware_reports["cd3"]
    )
    correlation = correlate_payload_parser_contract(
        prior_contract, payloads, constants
    )
    correlation["external_context"] = {
        "used_as_artifact_evidence": False,
        "sources": [
            {
                "purpose": (
                    "General context that vehicle-navigation databases can reside "
                    "on removable CD/DVD media"
                ),
                "url": "https://patents.google.com/patent/US8886599B2/en",
            },
            {
                "purpose": (
                    "General context for database-derived speech-recognition lexicons; "
                    "not evidence for this artifact's speech format"
                ),
                "url": "https://patents.google.com/patent/EP0865014B1/en",
            },
            {
                "purpose": (
                    "Later navigation-database context for partition/tile concepts; "
                    "not evidence that this artifact implements NDS"
                ),
                "url": "https://patents.google.com/patent/US9507808B2/en",
            },
            {
                "purpose": "Authoritative SH-3 instruction semantics",
                "url": (
                    "https://www.renesas.com/en/document/mas/"
                    "sh-3sh-3esh3-dsp-software-manual?language=en"
                ),
            },
        ],
    }

    write_json(payloads, args.output / "navigation-payload-families.analysis.json")
    write_json(
        build_public_navigation_payload_report(payloads),
        args.public_output / "navigation-payload-families.public.json",
    )
    for disc in ("cd1", "cd3"):
        write_json(
            firmware_reports[disc],
            args.output / f"{disc}-parser-constants.analysis.json",
        )
        write_json(
            firmware_reports[disc],
            args.public_output / f"{disc}-parser-constants.public.json",
        )
    write_json(
        constants, args.output / "cd1-cd3.parser-constants.comparison.json"
    )
    write_json(
        constants, args.public_output / "cd1-cd3.parser-constants.comparison.json"
    )
    write_json(
        correlation, args.output / "firmware-payload-parser.comparison.json"
    )
    write_json(
        correlation,
        args.public_output / "firmware-payload-parser.comparison.json",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build read-only, publication-safe Session 011 navigation-media reports."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.map_media import (
    analyze_navigation_media,
    build_public_navigation_media_report,
    correlate_firmware_and_media,
    probe_firmware_media_markers,
)
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _artifact_register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["artifact_id"]: row for row in csv.DictReader(handle)}


def _firmware_hashes(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["artifact"]: row["sha256"].lower() for row in csv.DictReader(handle)
        }


def _load_json(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(f"unsupported schema in {path}: {report.get('schema')!r}")
    return report


def _verify_firmware_iso(
    image: ISO9660Image, register: dict[str, str]
) -> str:
    expected = register.get(image.path.name)
    if expected is None:
        raise ValueError(f"{image.path.name} is absent from the firmware register")
    actual = image.sha256()
    if actual != expected:
        raise ValueError(
            f"SHA-256 mismatch for {image.path.name}: expected {expected}, got {actual}"
        )
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory one navigation ISO, validate FLDB record tables and "
            "correlate fixed format markers with the Session 010 firmware contract"
        )
    )
    parser.add_argument("map_iso", type=Path)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--firmware-cd1", type=Path, required=True)
    parser.add_argument("--firmware-cd3", type=Path, required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument(
        "--firmware-research-root",
        type=Path,
        default=Path("research/firmware-5570"),
    )
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
    args = parser.parse_args()

    media_register = _artifact_register(args.media_register)
    registered_media = media_register.get(args.artifact_id)
    if registered_media is None:
        raise ValueError(f"{args.artifact_id} is absent from the media register")
    expected_size = int(registered_media["size_bytes"])
    if args.map_iso.stat().st_size != expected_size:
        raise ValueError(
            f"media size mismatch: expected {expected_size}, "
            f"got {args.map_iso.stat().st_size}"
        )

    firmware_register = _firmware_hashes(args.firmware_register)
    prior_summaries = {
        disc: _load_json(
            args.firmware_research_root
            / "session003"
            / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    firmware_contract = _load_json(
        args.firmware_research_root
        / "session010"
        / "cd1-cd3.navigation-dataflow.comparison.json",
        "phoenix-mmi.navigation-dataflow-comparison/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    media = analyze_navigation_media(
        ISO9660Image(args.map_iso),
        artifact_id=args.artifact_id,
        expected_sha256=registered_media["sha256"],
    )

    probes: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session011-") as temporary:
        temporary_root = Path(temporary)
        for disc, iso_path, member_path in (
            ("cd1", args.firmware_cd1, CD1_MEMBER),
            ("cd3", args.firmware_cd3, CD3_MEMBER),
        ):
            image = ISO9660Image(iso_path)
            _verify_firmware_iso(image, firmware_register)
            member = image.find_path(member_path)
            binary_path = image.extract(
                member, temporary_root / disc / Path(member.path).name
            )
            reader = BinaryReader(binary_path)
            if reader.sha256() != prior_summaries[disc]["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            probes[disc] = probe_firmware_media_markers(reader)

    comparison = correlate_firmware_and_media(firmware_contract, media, probes)
    comparison["external_context"] = {
        "used_as_artifact_evidence": False,
        "sources": [
            {
                "purpose": (
                    "ECMA-119 defines the ISO descriptor sequence, logical blocks "
                    "and volume-descriptor terminology used by this report"
                ),
                "url": (
                    "https://ecma-international.org/wp-content/uploads/"
                    "ECMA-119_6th_edition_december_2025.pdf"
                ),
            },
            {
                "purpose": (
                    "A Harman Becker patent supplies only general context that "
                    "vehicle-navigation databases may reside on removable CD/DVD media"
                ),
                "url": "https://patents.google.com/patent/US8886599B2/en",
            },
        ],
    }

    write_json(media, args.output / "navigation-media.analysis.json")
    write_json(
        build_public_navigation_media_report(media),
        args.public_output / "navigation-media.public.json",
    )
    write_json(
        comparison,
        args.output / "firmware-media-contract.comparison.json",
    )
    write_json(
        comparison,
        args.public_output / "firmware-media-contract.comparison.json",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

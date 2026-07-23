#!/usr/bin/env python3
"""Analyze CD1/CD3 MMI payloads without retaining extracted firmware files."""

from __future__ import annotations

import argparse
import csv
import tempfile
from pathlib import Path

from phoenix_mmi.analysis import AnalysisConfig, analyze_file, compare_reports
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.report import build_public_summary, write_json, write_markdown


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"
MMI_METAINFO_SECTION = r"MMI Hi\MMI\42\default\Application"


def _registered_hashes(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["artifact"]: row["sha256"].lower() for row in csv.DictReader(handle)}


def _verify_registered(image: ISO9660Image, register: dict[str, str]) -> str:
    expected = register.get(image.path.name)
    if expected is None:
        raise ValueError(f"{image.path.name} is absent from the artifact register")
    actual = image.sha256()
    if actual != expected:
        raise ValueError(
            f"SHA-256 mismatch for {image.path.name}: expected {expected}, got {actual}"
        )
    return actual


def _descriptor_entry(image: ISO9660Image):
    matches = [
        entry
        for entry in image.entries()
        if not entry.is_directory and Path(entry.path).name.upper() in {"METAINFO.TXT", "METAINFO2.TXT"}
    ]
    if len(matches) != 1:
        raise KeyError(f"expected one METAINFO descriptor, found {len(matches)}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run sanitized Session 003 analysis directly from registered CD1/CD3 ISOs"
    )
    parser.add_argument("cd1", type=Path)
    parser.add_argument("cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "--public-output",
        type=Path,
        help="optional tracked directory for compact publication-safe summaries",
    )
    parser.add_argument(
        "--artifact-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    parser.add_argument("--entropy-window", type=lambda value: int(value, 0), default=0x10000)
    parser.add_argument("--entropy-step", type=lambda value: int(value, 0), default=0x10000)
    args = parser.parse_args()

    register = _registered_hashes(args.artifact_register)
    cd1 = ISO9660Image(args.cd1)
    cd3 = ISO9660Image(args.cd3)
    cd1_sha = _verify_registered(cd1, register)
    cd3_sha = _verify_registered(cd3, register)
    config = AnalysisConfig(
        entropy_window=args.entropy_window,
        entropy_step=args.entropy_step,
    )

    args.output.mkdir(parents=True, exist_ok=True)
    if args.public_output:
        args.public_output.mkdir(parents=True, exist_ok=True)
    reports: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session003-") as temporary:
        temporary_root = Path(temporary)
        for disc, image, member_name, iso_sha, label in (
            ("cd1", cd1, CD1_MEMBER, cd1_sha, "CD1 K942 / MMI 5150"),
            ("cd3", cd3, CD3_MEMBER, cd3_sha, "CD3 K1006 / MMI 5570"),
        ):
            member = image.find_path(member_name)
            descriptor = _descriptor_entry(image)
            binary_path = image.extract(member, temporary_root / disc / Path(member.path).name)
            metainfo_path = image.extract(descriptor, temporary_root / disc / Path(descriptor.path).name)
            report = analyze_file(
                binary_path,
                label=label,
                metainfo=metainfo_path,
                metainfo_section=MMI_METAINFO_SECTION,
                config=config,
            )
            report["artifact"].update(
                {
                    "source_iso_filename": image.path.name,
                    "source_iso_sha256": iso_sha,
                    "source_iso_volume": image.volume_identifier,
                    "source_member_path": member.path,
                }
            )
            write_json(report, args.output / f"{disc}-mmi.analysis.json")
            write_markdown(report, args.output / f"{disc}-mmi.analysis.md")
            if args.public_output:
                write_json(
                    build_public_summary(report),
                    args.public_output / f"{disc}-mmi.public-summary.json",
                )
            reports.append(report)

    comparison = compare_reports(reports[0], reports[1])
    write_json(comparison, args.output / "cd1-cd3.comparison.json")
    if args.public_output:
        write_json(comparison, args.public_output / "cd1-cd3.comparison.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

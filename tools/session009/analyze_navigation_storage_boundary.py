#!/usr/bin/env python3
"""Build the read-only Session 009 navigation/storage boundary reports."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.navigation_storage import (
    RUNTIME_BASE,
    analyze_navigation_storage_boundary,
    build_public_navigation_storage_report,
    compare_navigation_storage_boundaries,
    update_operational_graph,
)
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


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


def _load_json(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(f"unsupported schema in {path}: {report.get('schema')!r}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze navigation and storage boundaries without executing firmware"
    )
    parser.add_argument("cd1", type=Path)
    parser.add_argument("cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument(
        "--research-root",
        type=Path,
        default=Path("research/firmware-5570"),
    )
    parser.add_argument(
        "--artifact-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    args = parser.parse_args()

    register = _registered_hashes(args.artifact_register)
    prior_summaries = {
        disc: _load_json(
            args.research_root / "session003" / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    session008 = _load_json(
        args.research_root
        / "session008/cd1-cd3.firmware-operational-model.comparison.json",
        "phoenix-mmi.firmware-operational-model-comparison/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    reports = []
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session009-") as temporary:
        temporary_root = Path(temporary)
        for disc, iso_path, member_path, label in (
            ("cd1", args.cd1, CD1_MEMBER, "CD1 K942 / MMI 5150"),
            ("cd3", args.cd3, CD3_MEMBER, "CD3 K1006 / MMI 5570"),
        ):
            image = ISO9660Image(iso_path)
            iso_sha = _verify_registered(image, register)
            member = image.find_path(member_path)
            binary_path = image.extract(
                member, temporary_root / disc / Path(member.path).name
            )
            reader = BinaryReader(binary_path)
            expected_sha = prior_summaries[disc]["artifact"]["sha256"]
            if reader.sha256() != expected_sha:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")

            report = analyze_navigation_storage_boundary(reader)
            report["artifact"].update(
                {
                    "label": label,
                    "source_iso_filename": image.path.name,
                    "source_iso_sha256": iso_sha,
                    "source_member_path": member.path,
                }
            )
            report["prior_evidence"] = {
                "runtime_base": RUNTIME_BASE,
                "runtime_model_source": "Session 006 confirmed bounded model",
                "operational_graph_schema": session008["operational_graph"]["schema"],
                "principal_image_sha256_verified_against_session003": True,
            }
            reports.append(report)

        comparison = compare_navigation_storage_boundaries(reports[0], reports[1])
        comparison["operational_graph"] = update_operational_graph(
            session008["operational_graph"], comparison
        )
        comparison["external_context"] = {
            "used_as_firmware_evidence": False,
            "sources": [
                {
                    "purpose": "dosFs is a FAT-compatible VxWorks filesystem",
                    "url": "https://www.windriver.com/resource/vxworks-datasheet",
                },
                {
                    "purpose": "TFFS identifies True Flash File System support",
                    "url": (
                        "https://labs.windriver.com/downloads/vxw-sr0620-sdk-lab-release/"
                        "NOTICES/VxWorks7__ThirdPartyNotices_v4.5.pdf"
                    ),
                },
                {
                    "purpose": "ECMA-119 volume descriptors place CD001 at bytes 2-6",
                    "url": (
                        "https://ecma-international.org/wp-content/uploads/"
                        "ECMA-119_5th_edition_december_2024.pdf"
                    ),
                },
            ],
        }

        for disc, report in zip(("cd1", "cd3"), reports):
            write_json(
                report,
                args.output / f"{disc}-navigation-storage-boundary.analysis.json",
            )
            write_json(
                build_public_navigation_storage_report(report),
                args.public_output
                / f"{disc}-navigation-storage-boundary.public.json",
            )
        write_json(
            comparison,
            args.output / "cd1-cd3.navigation-storage-boundary.comparison.json",
        )
        write_json(
            comparison,
            args.public_output / "cd1-cd3.navigation-storage-boundary.comparison.json",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

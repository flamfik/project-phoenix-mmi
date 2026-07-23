#!/usr/bin/env python3
"""Run cautious Session 007 reference-graph analysis from registered ISOs."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.reference_graph import (
    analyze_reference_graph,
    build_public_reference_graph,
    compare_reference_graphs,
)
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _load_json(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(f"unsupported schema in {path}: {report.get('schema')!r}")
    return report


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run read-only Session 007 reference-graph analysis"
    )
    parser.add_argument("cd1", type=Path)
    parser.add_argument("cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument(
        "--session003",
        type=Path,
        default=Path("research/firmware-5570/session003"),
    )
    parser.add_argument(
        "--session005",
        type=Path,
        default=Path("research/firmware-5570/session005"),
    )
    parser.add_argument(
        "--session006",
        type=Path,
        default=Path("research/firmware-5570/session006"),
    )
    parser.add_argument(
        "--artifact-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    args = parser.parse_args()

    register = _registered_hashes(args.artifact_register)
    runtime_comparison = _load_json(
        args.session006 / "cd1-cd3.runtime-address-map.comparison.json",
        "phoenix-mmi.runtime-address-map-comparison/v1",
    )
    blocks = runtime_comparison["relocated_record_blocks"]
    if len(blocks) != 1:
        raise ValueError("Session 007 requires exactly one confirmed Session 006 block")
    block = blocks[0]
    if block.get("evidence_status") not in (None, "CONFIRMED_RELOCATED_RECORD_BLOCK"):
        raise ValueError("Session 006 record block is not confirmed")

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    reports = []
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session007-") as temporary:
        temporary_root = Path(temporary)
        for disc, iso_path, member_path, label, block_key in (
            ("cd1", args.cd1, CD1_MEMBER, "CD1 K942 / MMI 5150", "left_file_offset"),
            ("cd3", args.cd3, CD3_MEMBER, "CD3 K1006 / MMI 5570", "right_file_offset"),
        ):
            image = ISO9660Image(iso_path)
            iso_sha = _verify_registered(image, register)
            member = image.find_path(member_path)
            principal = _load_json(
                args.session003 / f"{disc}-mmi.public-summary.json",
                "phoenix-mmi.public-summary/v1",
            )
            bundle = _load_json(
                args.session005 / f"{disc}-resource-bundle.public.json",
                "phoenix-mmi.resource-bundle/v1",
            )
            binary_path = image.extract(
                member, temporary_root / disc / Path(member.path).name
            )
            reader = BinaryReader(binary_path)
            if reader.sha256() != principal["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            report = analyze_reference_graph(
                reader,
                bundle,
                record_block_offset=int(block[block_key]),
                record_block_length=int(block["block_length"]),
            )
            report["artifact"].update(
                {
                    "label": label,
                    "source_iso_filename": image.path.name,
                    "source_iso_sha256": iso_sha,
                    "source_member_path": member.path,
                }
            )
            reports.append(report)

        comparison = compare_reference_graphs(reports[0], reports[1])
        for disc, report in zip(("cd1", "cd3"), reports):
            write_json(report, args.output / f"{disc}-reference-graph.analysis.json")
            write_json(
                build_public_reference_graph(report),
                args.public_output / f"{disc}-reference-graph.public.json",
            )
        write_json(comparison, args.output / "cd1-cd3.reference-graph.comparison.json")
        write_json(
            comparison,
            args.public_output / "cd1-cd3.reference-graph.comparison.json",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

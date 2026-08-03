#!/usr/bin/env python3
"""Run cautious Session 006 runtime-address mapping from registered ISOs."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.report import write_json
from phoenix_mmi.resource_bundle import analyze_resource_bundle
from phoenix_mmi.runtime_map import (
    analyze_runtime_map,
    build_public_runtime_map,
    compare_runtime_maps,
)


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


def _load_report(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(f"unsupported schema in {path}: {report.get('schema')!r}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run read-only Session 006 runtime-address mapping"
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
        "--session004",
        type=Path,
        default=Path("research/firmware-5570/session004"),
    )
    parser.add_argument(
        "--artifact-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    args = parser.parse_args()

    register = _registered_hashes(args.artifact_register)
    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    reports: list[dict[str, object]] = []
    readers: list[BinaryReader] = []

    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session006-") as temporary:
        temporary_root = Path(temporary)
        for disc, iso_path, member_path, label in (
            ("cd1", args.cd1, CD1_MEMBER, "CD1 K942 / MMI 5150"),
            ("cd3", args.cd3, CD3_MEMBER, "CD3 K1006 / MMI 5570"),
        ):
            image = ISO9660Image(iso_path)
            iso_sha = _verify_registered(image, register)
            member = image.find_path(member_path)
            session003 = _load_report(
                args.session003 / f"{disc}-mmi.public-summary.json",
                "phoenix-mmi.public-summary/v1",
            )
            session004 = _load_report(
                args.session004 / f"{disc}-executable-layout.public.json",
                "phoenix-mmi.executable-layout/v1",
            )
            binary_path = image.extract(
                member, temporary_root / disc / Path(member.path).name
            )
            reader = BinaryReader(binary_path)
            if reader.sha256() != session003["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            bundle = analyze_resource_bundle(
                reader,
                island=session004["resources"]["filler_bounded_island"],
                cluster=session004["resources"]["cluster"],
                resources=session003["fingerprints"]["validated_resources"],
            )
            report = analyze_runtime_map(
                reader,
                bundle,
                filler_runs=session003["filler_runs"],
                flash_base=int(session004["artifact"]["flash_base_from_metainfo"]),
            )
            report["artifact"].update(
                {
                    "label": label,
                    "source_iso_filename": image.path.name,
                    "source_iso_sha256": iso_sha,
                    "source_member_path": member.path,
                }
            )
            readers.append(reader)
            reports.append(report)

        comparison = compare_runtime_maps(
            readers[0], readers[1], reports[0], reports[1]
        )
        for disc, report in zip(("cd1", "cd3"), reports):
            write_json(report, args.output / f"{disc}-runtime-address-map.analysis.json")
            write_json(
                build_public_runtime_map(report),
                args.public_output / f"{disc}-runtime-address-map.public.json",
            )
        write_json(
            comparison,
            args.output / "cd1-cd3.runtime-address-map.comparison.json",
        )
        write_json(
            comparison,
            args.public_output / "cd1-cd3.runtime-address-map.comparison.json",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

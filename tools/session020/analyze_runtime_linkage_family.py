#!/usr/bin/env python3
"""Build publication-safe Session 020 runtime-linkage family reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.report import write_json
from phoenix_mmi.runtime_linkage import (
    analyze_runtime_linkage_family,
    build_public_runtime_linkage_report,
    correlate_runtime_linkage_family,
)


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


def _disc_report(
    comparison: dict[str, object], *, side: str
) -> dict[str, object]:
    prefix = "left" if side == "cd1" else "right"
    report = {
        "schema": "phoenix-mmi.runtime-linkage-family-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "artifact": {
            "sha256": comparison[f"{prefix}_artifact_sha256"],
            "source_path_included": False,
        },
        "disc": comparison[prefix],
        "classification": {
            "cross_version_record_run": comparison["classification"][
                "cross_version_record_run"
            ],
            "runtime_patch_overlay_or_linkage_mechanism": comparison[
                "classification"
            ]["runtime_patch_overlay_or_linkage_mechanism"],
            "specific_writer_or_loader_chain": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
        },
        "publication_safety": comparison["publication_safety"],
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pair the pointer-zero run across MMI releases and test bounded "
            "GBR, helper, coherent copy-table and cache-marker writer models"
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
        "--session019-root",
        type=Path,
        default=Path("research/navigation-media/session019"),
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
        args.session019_root / "cd1-cd3.runtime-slot-lineage.comparison.json",
        "phoenix-mmi.runtime-slot-lineage-comparison/v1",
    )
    prior_correlation = _load_json(
        args.session019_root / "runtime-slot-lineage-correlation.json",
        "phoenix-mmi.runtime-slot-lineage-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session020-") as temporary:
        readers = {}
        for disc, iso_path, member_path in (
            ("cd1", args.firmware_cd1, CD1_MEMBER),
            ("cd3", args.firmware_cd3, CD3_MEMBER),
        ):
            row = rows.get(iso_path.name)
            if row is None:
                raise ValueError(f"{iso_path.name} is absent from the firmware register")
            image = ISO9660Image(iso_path)
            _verify_iso(image, row)
            member = image.find_path(member_path)
            extracted = image.extract(
                member, Path(temporary) / disc / Path(member.path).name
            )
            reader = BinaryReader(extracted)
            if reader.sha256() != summaries[disc]["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            readers[disc] = reader

        comparison = analyze_runtime_linkage_family(
            readers["cd1"], readers["cd3"], prior
        )

    correlation = correlate_runtime_linkage_family(
        prior_correlation, comparison
    )
    correlation["external_context"] = {
        "used_as_local_artifact_evidence": False,
        "sources": [
            {
                "purpose": (
                    "Authoritative SH-3 GBR loads/stores, PC-relative loads "
                    "and indirect-call semantics"
                ),
                "url": (
                    "https://www.renesas.com/en/document/mas/"
                    "sh-3sh-3esh3-dsp-software-manual?language=en"
                ),
            }
        ],
    }
    reports = {
        "cd1-runtime-linkage-family.public.json": _disc_report(
            comparison, side="cd1"
        ),
        "cd3-runtime-linkage-family.public.json": _disc_report(
            comparison, side="cd3"
        ),
        "cd1-cd3.runtime-linkage-family.comparison.json": comparison,
        "runtime-linkage-family-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.output / name.replace(".public", ".analysis"))
        write_json(
            build_public_runtime_linkage_report(report),
            args.public_output / name,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

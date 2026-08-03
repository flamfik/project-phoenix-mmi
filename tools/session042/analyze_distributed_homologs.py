#!/usr/bin/env python3
"""Build publication-safe Session 042 distributed homolog reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.cross_payload_homolog import payload_member_eligible
from phoenix_mmi.distributed_homolog import (
    NearHomologPayloadInput,
    analyze_distributed_homologs,
    build_public_distributed_homolog_report,
    correlate_distributed_homologs,
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


def _payloads(images: dict[str, ISO9660Image]):
    for disc, image in sorted(images.items()):
        entries = sorted(
            (
                entry
                for entry in image.entries()
                if not entry.is_directory
                and payload_member_eligible(entry.path, entry.size)
            ),
            key=lambda row: row.path,
        )
        for entry in entries:
            yield NearHomologPayloadInput(
                disc=disc,
                path=entry.path,
                data=image.read_entry(entry, 0, entry.size),
            )


def _domain_report(
    comparison: dict[str, object],
    *,
    domain: str,
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.distributed-homolog-domain/v1",
        "analysis_mode": comparison["analysis_mode"],
        "domain": domain,
        "constellation_contract": comparison["constellation_contract"],
        "corpus_reproduction": comparison["corpus_reproduction"],
        "domain_summary": comparison["domain_summaries"][domain],
        "summary": comparison["summary"],
        "classification": comparison["classification"],
        "limits": comparison["limits"],
        "publication_safety": comparison["publication_safety"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Search raw and validated record-normalized payload domains with "
            "the fixed distributed Session 042 constellation"
        )
    )
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd2", type=Path)
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
        "--navigation-root",
        type=Path,
        default=Path("research/navigation-media"),
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
    session038 = _load_json(
        args.navigation_root
        / "session038/cd1-cd3.run-gap-topology.comparison.json",
        "phoenix-mmi.run-gap-topology-comparison/v1",
    )
    session039 = _load_json(
        args.navigation_root
        / "session039/cd1-cd3.registered-provenance.comparison.json",
        "phoenix-mmi.registered-provenance-comparison/v1",
    )
    session040 = _load_json(
        args.navigation_root
        / "session040/cross-payload-homolog.comparison.json",
        "phoenix-mmi.cross-payload-homolog-comparison/v1",
    )
    session041 = _load_json(
        args.navigation_root
        / "session041/record-normalized-homolog.comparison.json",
        "phoenix-mmi.record-normalized-homolog-comparison/v1",
    )
    prior_correlation = _load_json(
        args.navigation_root
        / "session041/record-normalized-homolog-correlation.json",
        "phoenix-mmi.record-normalized-homolog-correlation/v1",
    )

    images = {
        "cd1": ISO9660Image(args.firmware_cd1),
        "cd2": ISO9660Image(args.firmware_cd2),
        "cd3": ISO9660Image(args.firmware_cd3),
    }
    for image in images.values():
        row = rows.get(image.path.name)
        if row is None:
            raise ValueError(
                f"{image.path.name} is absent from the firmware register"
            )
        _verify_iso(image, row)

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session042-"
    ) as temporary:
        readers = {}
        for disc, member_path in (
            ("cd1", CD1_MEMBER),
            ("cd3", CD3_MEMBER),
        ):
            member = images[disc].find_path(member_path)
            extracted = images[disc].extract(
                member,
                Path(temporary) / disc / Path(member.path).name,
            )
            reader = BinaryReader(extracted)
            if reader.sha256() != summaries[disc]["artifact"]["sha256"]:
                raise ValueError(
                    f"{disc} principal-image hash differs from Session 003"
                )
            readers[disc] = reader

        comparison = analyze_distributed_homologs(
            readers["cd1"],
            readers["cd3"],
            session038,
            session039,
            session040,
            session041,
            _payloads(images),
        )

    correlation = correlate_distributed_homologs(
        prior_correlation,
        comparison,
    )
    write_json(
        comparison,
        args.output / "distributed-homolog.analysis.json",
    )
    public = build_public_distributed_homolog_report(comparison)
    reports = {
        "distributed-homolog.comparison.json": public,
        "raw-distributed-homolog.public.json": (
            build_public_distributed_homolog_report(
                _domain_report(public, domain="RAW")
            )
        ),
        "record-normalized-distributed-homolog.public.json": (
            build_public_distributed_homolog_report(
                _domain_report(public, domain="RECORD_NORMALIZED")
            )
        ),
        "distributed-homolog-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.public_output / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

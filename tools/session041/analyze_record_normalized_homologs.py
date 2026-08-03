#!/usr/bin/env python3
"""Build publication-safe Session 041 normalized-record reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.record_normalization import (
    RecordPayloadInput,
    analyze_record_normalized_homologs,
    build_public_record_normalized_homolog_report,
    correlate_record_normalized_homologs,
    record_member_eligible,
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
                and record_member_eligible(entry.path, entry.size)
            ),
            key=lambda row: row.path,
        )
        for entry in entries:
            yield RecordPayloadInput(
                disc=disc,
                path=entry.path,
                data=image.read_entry(entry, 0, entry.size),
            )


def _disc_report(
    comparison: dict[str, object],
    *,
    disc: str,
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.record-normalized-homolog-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "disc_id": disc,
        "normalization_contract": comparison["normalization_contract"],
        "signature_contract": comparison["signature_contract"],
        "source_corpus": comparison["source_corpus"],
        "format_summaries": comparison["format_summaries"],
        "disc_summary": comparison["disc_summaries"].get(
            disc,
            {
                "record_candidate_member_count": 0,
                "record_candidate_member_bytes": 0,
                "extension_counts": {},
                "normalized_member_count": 0,
            },
        ),
        "decoded_corpus": comparison["decoded_corpus"],
        "summary": comparison["summary"],
        "classification": comparison["classification"],
        "limits": comparison["limits"],
        "publication_safety": comparison["publication_safety"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Decode validated Intel HEX and Motorola S-record regions, then "
            "repeat the fixed Session 040 homolog search"
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
    prior_correlation = _load_json(
        args.navigation_root
        / "session040/cross-payload-homolog-correlation.json",
        "phoenix-mmi.cross-payload-homolog-correlation/v1",
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
        prefix="phoenix-mmi-session041-"
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

        comparison = analyze_record_normalized_homologs(
            readers["cd1"],
            readers["cd3"],
            session038,
            session039,
            session040,
            _payloads(images),
        )

    correlation = correlate_record_normalized_homologs(
        prior_correlation,
        comparison,
    )
    write_json(
        comparison,
        args.output / "record-normalized-homolog.analysis.json",
    )
    public = build_public_record_normalized_homolog_report(comparison)
    reports = {
        "record-normalized-homolog.comparison.json": public,
        "cd1-record-normalized-homolog.public.json": (
            build_public_record_normalized_homolog_report(
                _disc_report(public, disc="cd1")
            )
        ),
        "cd2-record-normalized-homolog.public.json": (
            build_public_record_normalized_homolog_report(
                _disc_report(public, disc="cd2")
            )
        ),
        "cd3-record-normalized-homolog.public.json": (
            build_public_record_normalized_homolog_report(
                _disc_report(public, disc="cd3")
            )
        ),
        "record-normalized-homolog-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.public_output / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

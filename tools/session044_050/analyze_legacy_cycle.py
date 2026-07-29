#!/usr/bin/env python3
"""Build publication-safe reports for Sessions 044 through 050."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path, PurePosixPath
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.legacy_cycle import (
    LegacyPayloadInput,
    analyze_legacy_corpus,
    analyze_lod_topology,
    analyze_yim_decoded_homolog,
    analyze_yim_envelopes,
    analyze_yim_integrity,
    analyze_yim_rle,
    build_firmware_evidence_map,
    legacy_member_eligible,
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
                and legacy_member_eligible(entry.path, entry.size)
            ),
            key=lambda row: row.path,
        )
        for entry in entries:
            extension = PurePosixPath(entry.path).suffix.upper()
            if extension not in {".LOD", ".YIM"}:
                continue
            yield LegacyPayloadInput(
                disc=disc,
                path=entry.path,
                data=image.read_entry(entry, 0, entry.size),
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the read-only Sessions 044-050 LOD/YIM analysis cycle"
        )
    )
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd2", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
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
    session042 = _load_json(
        args.navigation_root
        / "session042/distributed-homolog.comparison.json",
        "phoenix-mmi.distributed-homolog-comparison/v1",
    )
    prior_correlation = _load_json(
        args.navigation_root
        / "session042/distributed-homolog-correlation.json",
        "phoenix-mmi.distributed-homolog-correlation/v1",
    )
    summaries = {
        disc: _load_json(
            args.session003_root / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }

    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session044-050-"
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

        session044, sources = analyze_legacy_corpus(_payloads(images))
        session045 = analyze_yim_envelopes(sources)
        session046, yim_results = analyze_yim_rle(sources)
        session047 = analyze_yim_integrity(yim_results)
        session048 = analyze_lod_topology(sources)
        session049 = analyze_yim_decoded_homolog(
            readers["cd1"],
            readers["cd3"],
            session038,
            session039,
            session040,
            session042,
            yim_results,
        )
    reports = [
        session044,
        session045,
        session046,
        session047,
        session048,
        session049,
    ]
    session050 = build_firmware_evidence_map(
        prior_correlation,
        reports,
    )
    reports.append(session050)

    names = {
        "044": "lod-yim-corpus.public.json",
        "045": "yim-envelope.public.json",
        "046": "yim-rle.public.json",
        "047": "yim-integrity.public.json",
        "048": "lod-topology.public.json",
        "049": "yim-decoded-homolog.public.json",
        "050": "firmware-evidence-map.json",
    }
    for report in reports:
        session = str(report["session"])
        write_json(
            report,
            args.output / f"session{session}.analysis.json",
        )
        write_json(
            report,
            args.public_root / f"session{session}" / names[session],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

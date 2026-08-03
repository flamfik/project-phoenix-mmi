#!/usr/bin/env python3
"""Build publication-safe reports for Sessions 051 through 060."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path, PurePosixPath
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.evidence_cycle import build_session060_evidence_map
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.legacy_cycle import (
    LegacyPayloadInput,
    analyze_legacy_corpus,
    analyze_yim_rle,
    legacy_member_eligible,
)
from phoenix_mmi.lod_research import (
    analyze_lod_alignment,
    analyze_lod_fill_regions,
    analyze_lod_grid_reuse,
    analyze_lod_record_hypothesis,
    analyze_lod_shared_regions,
)
from phoenix_mmi.report import write_json
from phoenix_mmi.yim_research import (
    analyze_embedded_xim2,
    analyze_yim_field_relations,
    analyze_yim_integrity_catalog,
    build_yim_integrity_decision,
)


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
            "Run the read-only Sessions 051-060 YIM-integrity and LOD cycle"
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

    summaries = {
        disc: _load_json(
            args.session003_root / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    session050 = _load_json(
        args.navigation_root
        / "session050/firmware-evidence-map.json",
        "phoenix-mmi.firmware-evidence-map/v1",
    )
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session051-060-"
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

        _, sources = analyze_legacy_corpus(_payloads(images))
        _, yim_results = analyze_yim_rle(sources)
        session051 = analyze_yim_integrity_catalog(yim_results)
        session052 = analyze_yim_field_relations(yim_results)
        session053 = analyze_embedded_xim2(readers, yim_results)
        session054 = build_yim_integrity_decision(
            session051, session052, session053
        )
        session055 = analyze_lod_alignment(sources)
        session056 = analyze_lod_fill_regions(sources)
        session057 = analyze_lod_grid_reuse(sources)
        session058 = analyze_lod_record_hypothesis(
            sources, session055, session056
        )
        session059 = analyze_lod_shared_regions(sources)

    reports = [
        session051,
        session052,
        session053,
        session054,
        session055,
        session056,
        session057,
        session058,
        session059,
    ]
    session060 = build_session060_evidence_map(session050, reports)
    reports.append(session060)
    names = {
        "051": "yim-integrity-catalog.public.json",
        "052": "yim-field-relations.public.json",
        "053": "embedded-xim2-census.public.json",
        "054": "yim-integrity-decision.json",
        "055": "lod-alignment.public.json",
        "056": "lod-fill-regions.public.json",
        "057": "lod-grid-reuse.public.json",
        "058": "lod-record-hypothesis.public.json",
        "059": "lod-shared-regions.public.json",
        "060": "firmware-evidence-map-v2.json",
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

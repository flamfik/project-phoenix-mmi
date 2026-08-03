#!/usr/bin/env python3
"""Build publication-safe Session 035 dual-delta similarity reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.dual_delta_similarity import (
    analyze_dual_delta_similarity,
    build_public_dual_delta_similarity_report,
    correlate_dual_delta_similarity,
    finalize_dual_delta_similarity,
)
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _integer(value: str) -> int:
    return int(value, 0)


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


def _disc_report(
    comparison: dict[str, object], *, side: str
) -> dict[str, object]:
    prefix = "left" if side == "cd1" else "right"
    contract = comparison["search_contract"]
    if side == "cd1":
        mapped_envelopes = {
            "source": {
                "lower": contract["envelope_lower"],
                "upper": contract["envelope_upper"],
                "width": contract["envelope_width"],
            }
        }
    else:
        mapped_envelopes = {
            "left_delta": {
                "lower": (
                    int(contract["envelope_lower"])
                    + int(contract["left_delta"])
                ),
                "upper": (
                    int(contract["envelope_upper"])
                    + int(contract["left_delta"])
                ),
                "width": contract["envelope_width"],
            },
            "right_delta": {
                "lower": (
                    int(contract["envelope_lower"])
                    + int(contract["right_delta"])
                ),
                "upper": (
                    int(contract["envelope_upper"])
                    + int(contract["right_delta"])
                ),
                "width": contract["envelope_width"],
            },
        }
    compact_profiles = []
    for profile in comparison["profiles"]:
        summary = profile["summary"]
        compact_profiles.append(
            {
                "window_size": profile["window_size"],
                "step": profile["step"],
                "grid_offset": profile["grid_offset"],
                "window_count": summary["window_count"],
                "classification_counts": summary[
                    "classification_counts"
                ],
                "forward_crossing_count": summary[
                    "forward_crossing_count"
                ],
                "reverse_crossing_count": summary[
                    "reverse_crossing_count"
                ],
                "classification": summary["classification"],
            }
        )
    return {
        "schema": "phoenix-mmi.dual-delta-similarity-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "artifact": {
            "sha256": comparison[f"{prefix}_artifact_sha256"],
            "source_path_included": False,
        },
        "search_contract": comparison["search_contract"],
        "mapped_envelopes": mapped_envelopes,
        "profiles": compact_profiles,
        "multiscale": comparison["multiscale"],
        "grid_control": comparison["grid_control"],
        "classification": comparison["classification"],
        "limits": comparison["limits"],
        "publication_safety": comparison["publication_safety"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Profile only the two prior relocation deltas inside the "
            "Session 034 open transition envelope"
        )
    )
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument(
        "--window-sizes",
        type=_integer,
        nargs="+",
        default=(256, 512, 1024),
    )
    parser.add_argument("--step", type=_integer, default=128)
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
    window_sizes = tuple(args.window_sizes)
    if args.step % 2:
        raise ValueError("step must be even for the half-step grid control")

    rows = _register(args.firmware_register)
    summaries = {
        disc: _load_json(
            args.session003_root / f"{disc}-mmi.public-summary.json",
            "phoenix-mmi.public-summary/v1",
        )
        for disc in ("cd1", "cd3")
    }
    prior = _load_json(
        args.navigation_root
        / "session034/cd1-cd3.exact-block-map.comparison.json",
        "phoenix-mmi.exact-block-map-comparison/v1",
    )
    prior_correlation = _load_json(
        args.navigation_root
        / "session034/exact-block-map-correlation.json",
        "phoenix-mmi.exact-block-map-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="phoenix-mmi-session035-"
    ) as temporary:
        readers = {}
        for disc, iso_path, member_path in (
            ("cd1", args.firmware_cd1, CD1_MEMBER),
            ("cd3", args.firmware_cd3, CD3_MEMBER),
        ):
            row = rows.get(iso_path.name)
            if row is None:
                raise ValueError(
                    f"{iso_path.name} is absent from the firmware register"
                )
            image = ISO9660Image(iso_path)
            _verify_iso(image, row)
            member = image.find_path(member_path)
            extracted = image.extract(
                member,
                Path(temporary) / disc / Path(member.path).name,
            )
            reader = BinaryReader(extracted)
            if reader.sha256() != summaries[disc]["artifact"]["sha256"]:
                raise ValueError(
                    f"{disc} principal-image hash differs from Session 003"
                )
            readers[disc] = reader

        comparison = analyze_dual_delta_similarity(
            readers["cd1"],
            readers["cd3"],
            prior,
            window_sizes=window_sizes,
            step=args.step,
        )
        shifted = analyze_dual_delta_similarity(
            readers["cd1"],
            readers["cd3"],
            prior,
            window_sizes=window_sizes,
            step=args.step,
            grid_offset=args.step // 2,
        )
        comparison = finalize_dual_delta_similarity(
            comparison, shifted
        )

    correlation = correlate_dual_delta_similarity(
        prior_correlation, comparison
    )
    write_json(
        comparison,
        args.output / "cd1-cd3.dual-delta-similarity.analysis.json",
    )
    write_json(
        shifted,
        args.output / "shifted-grid.dual-delta-similarity.analysis.json",
    )
    public_comparison = build_public_dual_delta_similarity_report(
        comparison
    )
    reports = {
        "cd1-cd3.dual-delta-similarity.comparison.json": (
            public_comparison
        ),
        "cd1-dual-delta-similarity.public.json": (
            build_public_dual_delta_similarity_report(
                _disc_report(public_comparison, side="cd1")
            )
        ),
        "cd3-dual-delta-similarity.public.json": (
            build_public_dual_delta_similarity_report(
                _disc_report(public_comparison, side="cd3")
            )
        ),
        "dual-delta-similarity-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.public_output / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

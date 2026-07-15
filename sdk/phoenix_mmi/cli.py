"""Command-line interface for sanitized Session 003 reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import AnalysisConfig, analyze_file, compare_reports
from .report import write_json, write_markdown


def _safe_stem(path: Path) -> str:
    return "".join(character if character.isalnum() else "-" for character in path.stem).strip("-").lower()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only static analysis for MMI research artifacts"
    )
    parser.add_argument("images", nargs="+", type=Path, help="extracted binary images")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "--metainfo",
        action="append",
        type=Path,
        default=[],
        help="METAINFO file corresponding to each image (repeat in image order)",
    )
    parser.add_argument(
        "--metainfo-section",
        action="append",
        default=[],
        help="exact METAINFO section for each image (repeat in image order)",
    )
    parser.add_argument("--entropy-window", type=lambda value: int(value, 0), default=0x10000)
    parser.add_argument("--entropy-step", type=lambda value: int(value, 0), default=0x10000)
    parser.add_argument("--entropy-delta", type=float, default=1.25)
    parser.add_argument("--string-min-length", type=int, default=5)
    args = parser.parse_args()

    if args.metainfo and len(args.metainfo) not in (1, len(args.images)):
        parser.error("provide one METAINFO for all images or one per image")
    if args.metainfo_section and len(args.metainfo_section) not in (1, len(args.images)):
        parser.error("provide one METAINFO section for all images or one per image")

    config = AnalysisConfig(
        entropy_window=args.entropy_window,
        entropy_step=args.entropy_step,
        entropy_delta=args.entropy_delta,
        string_min_length=args.string_min_length,
    )
    args.output.mkdir(parents=True, exist_ok=True)

    reports: list[dict[str, object]] = []
    for index, image in enumerate(args.images):
        metainfo = None
        if len(args.metainfo) == 1:
            metainfo = args.metainfo[0]
        elif args.metainfo:
            metainfo = args.metainfo[index]
        metainfo_section = None
        if len(args.metainfo_section) == 1:
            metainfo_section = args.metainfo_section[0]
        elif args.metainfo_section:
            metainfo_section = args.metainfo_section[index]
        report = analyze_file(
            image,
            label=image.name,
            metainfo=metainfo,
            metainfo_section=metainfo_section,
            config=config,
        )
        stem = _safe_stem(image)
        write_json(report, args.output / f"{stem}.analysis.json")
        write_markdown(report, args.output / f"{stem}.analysis.md")
        reports.append(report)

    if len(reports) == 2:
        comparison = compare_reports(reports[0], reports[1])
        write_json(comparison, args.output / "comparison.json")
        (args.output / "comparison-summary.txt").write_text(
            json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

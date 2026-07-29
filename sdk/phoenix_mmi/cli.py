"""Unified read-only command-line interface for Phoenix MMI tooling."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .analysis import AnalysisConfig, analyze_file, compare_reports
from .checksum_experiments import (
    ChecksumExperiment,
    ChecksumRegion,
    checksum_experiment_report,
    run_checksum_experiments,
)
from .format_registry import DEFAULT_FORMAT_REGISTRY
from .manifest import ArtifactManifest, ArtifactRecord, write_manifest
from .parse_result import MAX_PARSE_BYTES, parse_artifact
from .report import write_json, write_markdown
from .schema_registry import DEFAULT_SCHEMA_REGISTRY
from .structural_diff import structural_diff


def _safe_stem(path: Path) -> str:
    return "".join(
        character if character.isalnum() else "-" for character in path.stem
    ).strip("-").lower()


def _json_read(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _bounded_read(path: Path, limit: int = MAX_PARSE_BYTES) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"{path.name} exceeds the {limit}-byte CLI safety bound")
    return path.read_bytes()


def _emit(value: dict[str, object], output: Path | None) -> None:
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")


def _manifest(args: argparse.Namespace) -> int:
    records = [
        ArtifactRecord.from_file(path, logical_id=f"file-{index:04d}")
        for index, path in enumerate(args.files)
    ]
    write_manifest(ArtifactManifest.build(args.manifest_id, records), args.output)
    return 0


def _classify(args: argparse.Namespace) -> int:
    data = _bounded_read(args.file)
    evidence = DEFAULT_FORMAT_REGISTRY.classify(
        data, path=args.file.name, size=len(data)
    )
    _emit(
        {
            "schema": "phoenix-mmi.classification/v1",
            "evidence_count": len(evidence),
            "evidence": [item.to_dict() for item in evidence],
            "raw_artifact_bytes_included": False,
        },
        args.output,
    )
    return 0


def _parse(args: argparse.Namespace) -> int:
    data = _bounded_read(args.file)
    _emit(parse_artifact(data, path=args.file.name).to_dict(), args.output)
    return 0


def _checksum(args: argparse.Namespace) -> int:
    data = _bounded_read(args.file)
    length = len(data) - args.offset if args.length is None else args.length
    expected = None if args.expected is None else int(args.expected, 0)
    experiments = (
        ChecksumExperiment(
            args.experiment_id,
            args.algorithm,
            ChecksumRegion(args.region_id, args.offset, length),
            expected,
        ),
    )
    _emit(
        checksum_experiment_report(
            experiments, run_checksum_experiments(data, experiments)
        ),
        args.output,
    )
    return 0


def _diff(args: argparse.Namespace) -> int:
    _emit(structural_diff(_json_read(args.left), _json_read(args.right)), args.output)
    return 0


def _validate(args: argparse.Namespace) -> int:
    value = _json_read(args.file)
    if not isinstance(value, dict):
        raise TypeError("schema validation requires a JSON object")
    result = DEFAULT_SCHEMA_REGISTRY.validate(value).to_dict()
    _emit(
        {"schema": "phoenix-mmi.validation/v1", "result": result},
        args.output,
    )
    return 0 if result["valid"] else 2


def _analyze(args: argparse.Namespace) -> int:
    if args.metainfo and len(args.metainfo) not in (1, len(args.images)):
        raise ValueError(
            "provide one METAINFO for all images or one per image"
        )
    if args.metainfo_section and len(args.metainfo_section) not in (
        1,
        len(args.images),
    ):
        raise ValueError(
            "provide one METAINFO section for all images or one per image"
        )
    config = AnalysisConfig(
        entropy_window=args.entropy_window,
        entropy_step=args.entropy_step,
        entropy_delta=args.entropy_delta,
        string_min_length=args.string_min_length,
    )
    args.output.mkdir(parents=True, exist_ok=True)
    reports: list[dict[str, object]] = []
    for index, image in enumerate(args.images):
        metainfo = (
            args.metainfo[0]
            if len(args.metainfo) == 1
            else args.metainfo[index]
            if args.metainfo
            else None
        )
        metainfo_section = (
            args.metainfo_section[0]
            if len(args.metainfo_section) == 1
            else args.metainfo_section[index]
            if args.metainfo_section
            else None
        )
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
        write_json(compare_reports(reports[0], reports[1]), args.output / "comparison.json")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only static-analysis toolkit for MMI research artifacts"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    manifest = sub.add_parser("manifest", help="build a strict private manifest")
    manifest.add_argument("files", nargs="+", type=Path)
    manifest.add_argument("-o", "--output", required=True, type=Path)
    manifest.add_argument("--manifest-id", default="phoenix-cli-manifest")
    manifest.set_defaults(handler=_manifest)

    classify = sub.add_parser("classify", help="classify one bounded artifact")
    classify.add_argument("file", type=Path)
    classify.add_argument("-o", "--output", type=Path)
    classify.set_defaults(handler=_classify)

    parse = sub.add_parser("parse", help="parse one supported bounded artifact")
    parse.add_argument("file", type=Path)
    parse.add_argument("-o", "--output", type=Path)
    parse.set_defaults(handler=_parse)

    checksum = sub.add_parser("checksum", help="run one declarative checksum experiment")
    checksum.add_argument("file", type=Path)
    checksum.add_argument("--algorithm", choices=("CRC32/IEEE", "ADLER32", "SUM16"), default="CRC32/IEEE")
    checksum.add_argument("--offset", type=lambda value: int(value, 0), default=0)
    checksum.add_argument("--length", type=lambda value: int(value, 0))
    checksum.add_argument("--expected")
    checksum.add_argument("--experiment-id", default="cli-experiment")
    checksum.add_argument("--region-id", default="cli-region")
    checksum.add_argument("-o", "--output", type=Path)
    checksum.set_defaults(handler=_checksum)

    diff = sub.add_parser("diff", help="diff two JSON structures")
    diff.add_argument("left", type=Path)
    diff.add_argument("right", type=Path)
    diff.add_argument("-o", "--output", type=Path)
    diff.set_defaults(handler=_diff)

    validate = sub.add_parser("validate", help="validate a registered JSON schema")
    validate.add_argument("file", type=Path)
    validate.add_argument("-o", "--output", type=Path)
    validate.set_defaults(handler=_validate)

    analyze = sub.add_parser("analyze", help="run the legacy static image analyzer")
    analyze.add_argument("images", nargs="+", type=Path)
    analyze.add_argument("-o", "--output", type=Path, required=True)
    analyze.add_argument("--metainfo", action="append", type=Path, default=[])
    analyze.add_argument("--metainfo-section", action="append", default=[])
    analyze.add_argument("--entropy-window", type=lambda value: int(value, 0), default=0x10000)
    analyze.add_argument("--entropy-step", type=lambda value: int(value, 0), default=0x10000)
    analyze.add_argument("--entropy-delta", type=float, default=1.25)
    analyze.add_argument("--string-min-length", type=int, default=5)
    analyze.set_defaults(handler=_analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        sys.stderr.write(f"phoenix-mmi: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

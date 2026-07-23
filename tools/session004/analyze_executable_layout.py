#!/usr/bin/env python3
"""Run Session 004 SuperH/VxWorks layout analysis from registered ISOs."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.checksum import parse_metainfo_checksums
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.layout import analyze_executable_layout
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"
MMI_METAINFO_SECTION = r"MMI Hi\MMI\42\default\Application"


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


def _session003_summary(path: Path) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != "phoenix-mmi.public-summary/v1":
        raise ValueError(f"unsupported Session 003 summary schema in {path}")
    return report


def _descriptor_entry(image: ISO9660Image):
    matches = [
        entry
        for entry in image.entries()
        if not entry.is_directory
        and Path(entry.path).name.upper() in {"METAINFO.TXT", "METAINFO2.TXT"}
    ]
    if len(matches) != 1:
        raise KeyError(f"expected one METAINFO descriptor, found {len(matches)}")
    return matches[0]


def _startup_diff(left_path: Path, right_path: Path, length: int) -> dict[str, object]:
    with left_path.open("rb") as handle:
        left = handle.read(length)
    with right_path.open("rb") as handle:
        right = handle.read(length)
    compared = min(len(left), len(right))
    differences = [index for index in range(compared) if left[index] != right[index]]
    return {
        "compared_length": compared,
        "common_prefix_length": differences[0] if differences else compared,
        "different_byte_count": len(differences),
        "first_difference_offset": differences[0] if differences else None,
        "last_difference_offset": differences[-1] if differences else None,
        "bytes_included": False,
    }


def _comparison(
    left: dict[str, object],
    right: dict[str, object],
    startup_diff: dict[str, object],
) -> dict[str, object]:
    left_resources = left["resources"]
    right_resources = right["resources"]
    left_cluster = left_resources["cluster"]
    right_cluster = right_resources["cluster"]
    return {
        "schema": "phoenix-mmi.executable-layout-comparison/v1",
        "left": left["artifact"]["label"],
        "right": right["artifact"]["label"],
        "startup_pattern_confirmed_both": bool(
            left["startup"]["startup_pattern_confirmed"]
            and right["startup"]["startup_pattern_confirmed"]
        ),
        "startup_public_trace_equal": left["startup"]["public_trace"]
        == right["startup"]["public_trace"],
        "startup_traced_region_equal": bool(
            left["startup"]["traced_region_end"] == right["startup"]["traced_region_end"]
            and left["startup"]["traced_region_sha256"]
            == right["startup"]["traced_region_sha256"]
        ),
        "startup_region_diff": startup_diff,
        "reachable_instruction_count_delta": (
            int(right["startup"]["reachable_instruction_count"])
            - int(left["startup"]["reachable_instruction_count"])
        ),
        "resource_cluster_offset_delta": (
            int(right_cluster["offset"]) - int(left_cluster["offset"])
        ),
        "resource_cluster_length_equal": (
            int(right_cluster["length"]) == int(left_cluster["length"])
        ),
        "resource_filler_gaps": {
            "left_before": left_resources["gap_after_preceding_filler"],
            "right_before": right_resources["gap_after_preceding_filler"],
            "left_after": left_resources["gap_before_following_filler"],
            "right_after": right_resources["gap_before_following_filler"],
        },
        "resource_island": {
            "left_length": left_resources["filler_bounded_island"]["length"],
            "right_length": right_resources["filler_bounded_island"]["length"],
            "length_delta": (
                int(right_resources["filler_bounded_island"]["length"])
                - int(left_resources["filler_bounded_island"]["length"])
            ),
            "cluster_offset_within_island_equal": (
                left_resources["filler_bounded_island"]["resource_cluster_offset_within_island"]
                == right_resources["filler_bounded_island"]["resource_cluster_offset_within_island"]
            ),
        },
        "direct_resource_reference_candidates": {
            "left": left_resources["direct_reference_candidate_count"],
            "right": right_resources["direct_reference_candidate_count"],
        },
        "vxworks_symbol_table_status": {
            "left": left["vxworks"]["symbol_or_module_table_status"],
            "right": right["vxworks"]["symbol_or_module_table_status"],
        },
        "publication_safety": {"artifact_bytes_included": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run read-only Session 004 executable-layout analysis"
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
        "--artifact-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    args = parser.parse_args()

    register = _registered_hashes(args.artifact_register)
    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    reports: list[dict[str, object]] = []
    binary_paths: list[Path] = []

    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session004-") as temporary:
        temporary_root = Path(temporary)
        for disc, iso_path, member_path, label in (
            ("cd1", args.cd1, CD1_MEMBER, "CD1 K942 / MMI 5150"),
            ("cd3", args.cd3, CD3_MEMBER, "CD3 K1006 / MMI 5570"),
        ):
            image = ISO9660Image(iso_path)
            iso_sha = _verify_registered(image, register)
            member = image.find_path(member_path)
            summary = _session003_summary(
                args.session003 / f"{disc}-mmi.public-summary.json"
            )
            binary_path = image.extract(member, temporary_root / disc / Path(member.path).name)
            descriptor = _descriptor_entry(image)
            metainfo_path = image.extract(
                descriptor, temporary_root / disc / Path(descriptor.path).name
            )
            reader = BinaryReader(binary_path)
            if reader.sha256() != summary["artifact"]["sha256"]:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            metadata = parse_metainfo_checksums(
                metainfo_path, section_name=MMI_METAINFO_SECTION
            )
            if metadata.flash_start_address is None:
                raise ValueError(f"{disc} METAINFO has no FlashStartAddress")
            flash_base = metadata.flash_start_address
            report = analyze_executable_layout(
                reader,
                flash_base=flash_base,
                resources=list(summary["fingerprints"]["validated_resources"]),
                filler_runs=list(summary["filler_runs"]),
            )
            report["artifact"].update(
                {
                    "label": label,
                    "source_iso_filename": image.path.name,
                    "source_iso_sha256": iso_sha,
                    "source_member_path": member.path,
                }
            )
            write_json(report, args.output / f"{disc}-executable-layout.analysis.json")
            write_json(report, args.public_output / f"{disc}-executable-layout.public.json")
            reports.append(report)
            binary_paths.append(binary_path)

        compared_length = min(
            int(report["startup"]["traced_region_end"]) for report in reports
        )
        startup_diff = _startup_diff(binary_paths[0], binary_paths[1], compared_length)

    comparison = _comparison(reports[0], reports[1], startup_diff)
    write_json(comparison, args.output / "cd1-cd3.executable-layout.comparison.json")
    write_json(comparison, args.public_output / "cd1-cd3.executable-layout.comparison.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

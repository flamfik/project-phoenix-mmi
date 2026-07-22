#!/usr/bin/env python3
"""Build publication-safe Session 016 predecessor/dispatch reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.object_dispatch import (
    analyze_object_dispatch_context,
    build_public_object_dispatch_report,
    correlate_dispatch_context,
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
        raise ValueError(f"unsupported schema in {path}: {report.get('schema')!r}")
    return report


def _verify_iso(image: ISO9660Image, row: dict[str, str]) -> None:
    if image.path.stat().st_size != int(row["size_bytes"]):
        raise ValueError(f"registered size mismatch for {image.path.name}")
    if image.sha256() != row["sha256"].lower():
        raise ValueError(f"registered SHA-256 mismatch for {image.path.name}")


def _disc_report(comparison: dict[str, object], *, side: str) -> dict[str, object]:
    prefix = "left" if side == "cd1" else "right"
    calls = []
    for pair in comparison["dispatch_pairs"]:
        call = pair[prefix]
        calls.append(
            {
                "domain": pair["domain"],
                "call_site_offset": pair[f"{prefix}_call_site_offset"],
                "context_start_reason": pair[f"{prefix}_context_start_reason"],
                "predecessor_bytes_included": pair[
                    f"{prefix}_predecessor_bytes_included"
                ],
                "target_register": call["target_register"],
                "target_path": call["target_path"],
                "target_load_offsets": call["target_load_offsets"],
                "target_static_status": call["target_static_status"],
                **(
                    {"target_file_offset": call["target_file_offset"]}
                    if "target_file_offset" in call
                    else {}
                ),
                "target_code_gate_passed": call["target_code_gate_passed"],
                **(
                    {"target_code_evidence": call["target_code_evidence"]}
                    if "target_code_evidence" in call
                    else {}
                ),
                "arguments": call["arguments"],
                "pair_classification": pair["classification"],
                "function_boundary_asserted": False,
                "path_dominance_asserted": False,
            }
        )
    return {
        "schema": "phoenix-mmi.object-dispatch-context-disc/v1",
        "analysis_mode": comparison["analysis_mode"],
        "artifact": {
            "sha256": comparison[f"{prefix}_artifact_sha256"],
            "source_path_included": False,
        },
        "calls": calls,
        "classification": {
            "callsite_count": len(calls),
            "paired_contextual_static_target_count": comparison["classification"][
                "paired_contextual_static_target_count"
            ],
            "paired_contextual_target_code_gate_count": comparison[
                "classification"
            ]["paired_contextual_target_code_gate_count"],
            "matched_dynamic_descriptor_contract_count": comparison[
                "classification"
            ]["matched_dynamic_descriptor_contract_count"],
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
        },
        "publication_safety": comparison["publication_safety"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recover bounded predecessor literal targets and describe matched "
            "dynamic descriptor paths without resolving runtime dispatch"
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
        "--session010-root",
        type=Path,
        default=Path("research/firmware-5570/session010"),
    )
    parser.add_argument(
        "--session015-root",
        type=Path,
        default=Path("research/navigation-media/session015"),
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
    contract = _load_json(
        args.session010_root / "cd1-cd3.navigation-dataflow.comparison.json",
        "phoenix-mmi.navigation-dataflow-comparison/v1",
    )
    prior = _load_json(
        args.session015_root / "optical-sector-correlation.json",
        "phoenix-mmi.optical-sector-correlation/v1",
    )

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session016-") as temporary:
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

        comparison = analyze_object_dispatch_context(
            readers["cd1"], readers["cd3"], contract
        )

    correlation = correlate_dispatch_context(prior, comparison)
    correlation["external_context"] = {
        "used_as_local_artifact_evidence": False,
        "sources": [
            {
                "purpose": "Authoritative SH-3 call, delay-slot and addressing semantics",
                "url": (
                    "https://www.renesas.com/en/document/mas/"
                    "sh-3sh-3esh3-dsp-software-manual?language=en"
                ),
            },
            {
                "purpose": "Register preservation guidance used only as bounded ABI context",
                "local_reference": "SESSION-013 external technical basis",
            },
        ],
    }
    reports = {
        "cd1-object-dispatch.public.json": _disc_report(comparison, side="cd1"),
        "cd3-object-dispatch.public.json": _disc_report(comparison, side="cd3"),
        "cd1-cd3.object-dispatch.comparison.json": comparison,
        "object-dispatch-correlation.json": correlation,
    }
    for name, report in reports.items():
        write_json(report, args.output / name.replace(".public", ".analysis"))
        write_json(
            build_public_object_dispatch_report(report),
            args.public_output / name,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build the read-only Session 008 firmware operational model."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.operational_model import (
    analyze_relocated_bitmap_atlas,
    build_operational_graph,
    build_public_operational_report,
)
from phoenix_mmi.report import write_json


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _load_json(path: Path, schema: str) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != schema:
        raise ValueError(f"unsupported schema in {path}: {report.get('schema')!r}")
    return report


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the read-only Session 008 firmware operational model"
    )
    parser.add_argument("cd1", type=Path)
    parser.add_argument("cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument(
        "--research-root",
        type=Path,
        default=Path("research/firmware-5570"),
    )
    parser.add_argument(
        "--artifact-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    args = parser.parse_args()

    register = _registered_hashes(args.artifact_register)
    prior = {}
    schemas = {
        "session003": ("mmi.public-summary.json", "phoenix-mmi.public-summary/v1"),
        "session004": (
            "executable-layout.public.json",
            "phoenix-mmi.executable-layout/v1",
        ),
        "session005": (
            "resource-bundle.public.json",
            "phoenix-mmi.resource-bundle/v1",
        ),
        "session006": (
            "runtime-address-map.public.json",
            "phoenix-mmi.runtime-address-map/v1",
        ),
        "session007": (
            "reference-graph.public.json",
            "phoenix-mmi.reference-graph/v1",
        ),
    }
    for disc in ("cd1", "cd3"):
        prior[disc] = {}
        for session, (suffix, schema) in schemas.items():
            prior[disc][session] = _load_json(
                args.research_root / session / f"{disc}-{suffix}", schema
            )
    reference_comparison = _load_json(
        args.research_root / "session007/cd1-cd3.reference-graph.comparison.json",
        "phoenix-mmi.reference-graph-comparison/v1",
    )
    fields = reference_comparison["descriptor_graph"]["common_normalized_fields"]
    if reference_comparison["descriptor_graph"]["status"] != (
        "CONFIRMED_RELOCATED_DESCRIPTOR_GRAPH"
    ):
        raise ValueError("Session 008 requires the confirmed Session 007 graph")

    args.output.mkdir(parents=True, exist_ok=True)
    args.public_output.mkdir(parents=True, exist_ok=True)
    readers = []
    iso_metadata = []
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-session008-") as temporary:
        temporary_root = Path(temporary)
        for disc, iso_path, member_path, label in (
            ("cd1", args.cd1, CD1_MEMBER, "CD1 K942 / MMI 5150"),
            ("cd3", args.cd3, CD3_MEMBER, "CD3 K1006 / MMI 5570"),
        ):
            image = ISO9660Image(iso_path)
            iso_sha = _verify_registered(image, register)
            member = image.find_path(member_path)
            binary_path = image.extract(
                member, temporary_root / disc / Path(member.path).name
            )
            reader = BinaryReader(binary_path)
            expected_sha = prior[disc]["session003"]["artifact"]["sha256"]
            if reader.sha256() != expected_sha:
                raise ValueError(f"{disc} principal-image hash differs from Session 003")
            readers.append(reader)
            iso_metadata.append(
                {
                    "label": label,
                    "source_iso_filename": image.path.name,
                    "source_iso_sha256": iso_sha,
                    "source_member_path": member.path,
                }
            )

        block_offsets = [
            int(prior[disc]["session007"]["record_block"]["file_offset"])
            for disc in ("cd1", "cd3")
        ]
        left_report, right_report, atlas_comparison = analyze_relocated_bitmap_atlas(
            readers[0],
            readers[1],
            left_block_offset=block_offsets[0],
            right_block_offset=block_offsets[1],
            descriptor_fields=fields,
        )
        reports = [left_report, right_report]
        for disc, report, metadata in zip(
            ("cd1", "cd3"), reports, iso_metadata
        ):
            report["schema"] = "phoenix-mmi.firmware-operational-model/v1"
            report["analysis_mode"] = "read-only-static"
            report["artifact"].update(metadata)
            report["prior_evidence"] = {
                "checksum_chunk_count": prior[disc]["session003"]["checksums"][
                    "expected_count"
                ],
                "startup_architecture": prior[disc]["session004"]["startup"][
                    "architecture"
                ],
                "startup_pattern_confirmed": prior[disc]["session004"]["startup"][
                    "startup_pattern_confirmed"
                ],
                "browser_resource_count": prior[disc]["session005"]["resources"][
                    "validated_count"
                ],
                "runtime_base": prior[disc]["session006"]["selected_model"]["base"],
                "runtime_model_status": prior[disc]["session006"]["selected_model"][
                    "status"
                ],
                "source_to_atlas_edge_count": len(
                    prior[disc]["session007"]["source_to_target_edges"]
                ),
            }
            report["classification"] = {
                "structural_status": atlas_comparison["structural_status"],
                "semantic_status": atlas_comparison["semantic_status"],
                "semantic_confirmation": False,
            }
            report["publication_safety"] = atlas_comparison["publication_safety"]

        comparison = {
            "schema": "phoenix-mmi.firmware-operational-model-comparison/v1",
            "analysis_mode": "read-only-static",
            "left": iso_metadata[0]["label"],
            "right": iso_metadata[1]["label"],
            "bitmap_atlas": atlas_comparison,
            "operational_graph": build_operational_graph(
                atlas_comparison=atlas_comparison
            ),
            "external_context": {
                "used_as_firmware_evidence": False,
                "note": (
                    "Wind River documentation confirms that VxWorks/WindML-era SuperH "
                    "platforms could integrate embedded browsers and font engines; this "
                    "does not identify the MMI implementation."
                ),
                "source": "https://www.windriver.com/news/press/news-277",
            },
            "publication_safety": atlas_comparison["publication_safety"],
        }
        for disc, report in zip(("cd1", "cd3"), reports):
            write_json(report, args.output / f"{disc}-firmware-operational-model.analysis.json")
            write_json(
                build_public_operational_report(report),
                args.public_output / f"{disc}-firmware-operational-model.public.json",
            )
        write_json(
            comparison,
            args.output / "cd1-cd3.firmware-operational-model.comparison.json",
        )
        write_json(
            comparison,
            args.public_output / "cd1-cd3.firmware-operational-model.comparison.json",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

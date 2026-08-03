#!/usr/bin/env python3
"""Run the complete read-only Milestone M3 Resource Laboratory cycle."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.legacy_cycle import (
    LegacyPayloadInput,
    analyze_legacy_corpus,
    analyze_yim_rle,
    legacy_member_eligible,
)
from phoenix_mmi.resource_catalog import (
    build_public_resource_catalog,
    build_resource_catalog,
    scan_embedded_xim2,
)
from phoenix_mmi.resource_graphics import (
    build_candidate_previews,
    build_geometry_taxonomy,
    build_public_preview_summary,
    evaluate_pixel_layouts,
)
from phoenix_mmi.resource_lab_audit import (
    advance_m3_progress,
    build_m3_baseline,
)
from phoenix_mmi.resource_lab_integration import run_resource_lab_integration
from phoenix_mmi.resource_text import (
    build_font_catalog,
    build_language_topology,
    build_resource_relationship_graph,
    build_text_catalog,
)


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["artifact"]: row for row in csv.DictReader(handle)}


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
            if extension in {".LOD", ".YIM"}:
                yield LegacyPayloadInput(
                    disc=disc,
                    path=entry.path,
                    data=image.read_entry(entry, 0, entry.size),
                )


def _transition(
    capability_id: str,
    *,
    target: str,
    evidence: str,
    limitation: str,
) -> dict[str, str]:
    return {
        "capability_id": capability_id,
        "from_status": "MISSING",
        "to_status": "IMPLEMENTED",
        "probe_kind": "python-symbol",
        "probe_target": target,
        "evidence": evidence,
        "limitation": limitation,
    }


def _advance(
    repository: Path,
    previous: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph_version: str,
    graph_node_id: str,
    section: str,
    summary: dict[str, object],
) -> dict[str, object]:
    report = advance_m3_progress(
        repository,
        previous,
        session=session,
        transitions=transitions,
        graph_version=graph_version,
        graph_node_id=graph_node_id,
    )
    report[section] = summary
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd2", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument(
        "--firmware-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    args = parser.parse_args()
    repository = args.repository.resolve()
    register_path = (
        args.firmware_register
        if args.firmware_register.is_absolute()
        else repository / args.firmware_register
    )
    rows = _register(register_path)
    images = {
        "cd1": ISO9660Image(args.firmware_cd1),
        "cd2": ISO9660Image(args.firmware_cd2),
        "cd3": ISO9660Image(args.firmware_cd3),
    }
    for image in images.values():
        row = rows.get(image.path.name)
        if row is None:
            raise ValueError(f"{image.path.name} is absent from the register")
        _verify_iso(image, row)

    m2 = json.loads(
        (
            repository
            / "research/milestones/m2/session074/milestone-m2-closure.json"
        ).read_text(encoding="utf-8")
    )
    report075 = build_m3_baseline(repository, m2)
    _write(
        args.public_output / "session075/m3-resource-lab-baseline.json",
        report075,
    )

    args.private_output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-m3-") as temporary:
        readers = {}
        for release, member_path in (
            ("cd1", CD1_MEMBER),
            ("cd3", CD3_MEMBER),
        ):
            entry = images[release].find_path(member_path)
            extracted = images[release].extract(
                entry, Path(temporary) / release / Path(entry.path).name
            )
            readers[release] = BinaryReader(extracted)

        _, sources = analyze_legacy_corpus(_payloads(images))
        _, standalone_results = analyze_yim_rle(sources)
        embedded = {
            release: scan_embedded_xim2(reader, release=release)
            for release, reader in readers.items()
        }
        catalog_private = build_resource_catalog(embedded, standalone_results)
        _write(
            args.private_output / "session076/resource-catalog.private.json",
            catalog_private.to_dict(),
        )
        catalog = build_public_resource_catalog(catalog_private)
        report076 = _advance(
            repository,
            report075,
            session="076",
            transitions=[
                _transition(
                    "M3-CAP-008",
                    target="phoenix_mmi.resource_catalog:ResourceCatalog",
                    evidence="Session 076 and SPEC-084",
                    limitation="semantic resource names and runtime owners remain unknown",
                )
            ],
            graph_version="v68",
            graph_node_id="m3-versioned-resource-catalog",
            section="resource_catalog",
            summary=catalog,
        )
        _write(
            args.public_output / "session076/resource-catalog-summary.json",
            report076,
        )

        geometry = build_geometry_taxonomy(catalog_private)
        report077 = _advance(
            repository,
            report076,
            session="077",
            transitions=[
                _transition(
                    "M3-CAP-009",
                    target="phoenix_mmi.resource_graphics:build_geometry_taxonomy",
                    evidence="Session 077 and SPEC-085",
                    limitation="shape classes do not assign UI purpose",
                )
            ],
            graph_version="v69",
            graph_node_id="m3-resource-geometry-taxonomy",
            section="geometry_taxonomy",
            summary=geometry,
        )
        _write(
            args.public_output / "session077/geometry-taxonomy.json",
            report077,
        )

        pixel_sources = [
            (
                str(source["source_id"]),
                result.raster,
                result.envelope.width,
                result.envelope.height,
            )
            for source, result in standalone_results
        ]
        pixels = evaluate_pixel_layouts(pixel_sources)
        report078 = _advance(
            repository,
            report077,
            session="078",
            transitions=[
                _transition(
                    "M3-CAP-010",
                    target="phoenix_mmi.resource_graphics:evaluate_pixel_layouts",
                    evidence="Session 078 and SPEC-086",
                    limitation="rankings are heuristic; the pixel layout remains unconfirmed",
                )
            ],
            graph_version="v70",
            graph_node_id="m3-pixel-layout-hypotheses",
            section="pixel_layout_hypotheses",
            summary=pixels,
        )
        _write(
            args.public_output / "session078/pixel-layout-hypotheses.json",
            report078,
        )

        _, preview_result = standalone_results[0]
        previews = build_candidate_previews(
            preview_result.raster,
            preview_result.envelope.width,
            preview_result.envelope.height,
        )
        preview_dir = args.private_output / "session079/candidate-previews"
        preview_dir.mkdir(parents=True, exist_ok=True)
        private_preview_manifest = []
        for layout_id, data in sorted(previews.items()):
            filename = f"candidate-{layout_id.casefold()}.ppm"
            destination = preview_dir / filename
            destination.write_bytes(data)
            private_preview_manifest.append(
                {
                    "layout_id": layout_id,
                    "filename": filename,
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        _write(
            args.private_output / "session079/preview-manifest.private.json",
            {
                "schema": "phoenix-mmi.private-preview-manifest/v1",
                "previews": private_preview_manifest,
                "publication_class": "PRIVATE_LOCAL",
            },
        )
        preview = build_public_preview_summary(
            previews,
            width=preview_result.envelope.width,
            height=preview_result.envelope.height,
        )
        report079 = _advance(
            repository,
            report078,
            session="079",
            transitions=[
                _transition(
                    "M3-CAP-011",
                    target="phoenix_mmi.resource_graphics:render_ppm",
                    evidence="Session 079 and SPEC-087",
                    limitation="candidate previews do not select or confirm a pixel layout",
                )
            ],
            graph_version="v71",
            graph_node_id="m3-private-offline-preview",
            section="offline_preview",
            summary=preview,
        )
        _write(
            args.public_output / "session079/offline-preview-summary.json",
            report079,
        )

        text = build_text_catalog(readers)
        report080 = _advance(
            repository,
            report079,
            session="080",
            transitions=[
                _transition(
                    "M3-CAP-012",
                    target="phoenix_mmi.resource_text:build_text_catalog",
                    evidence="Session 080 and SPEC-088",
                    limitation="aggregate strings do not identify renderer ownership",
                )
            ],
            graph_version="v72",
            graph_node_id="m3-resource-text-catalog",
            section="text_catalog",
            summary=text,
        )
        _write(
            args.public_output / "session080/text-catalog-summary.json",
            report080,
        )

        atlas = json.loads(
            (
                repository
                / "research/firmware-5570/session008/"
                "cd1-cd3.firmware-operational-model.comparison.json"
            ).read_text(encoding="utf-8")
        )["bitmap_atlas"]
        fonts = build_font_catalog(readers, atlas)
        report081 = _advance(
            repository,
            report080,
            session="081",
            transitions=[
                _transition(
                    "M3-CAP-013",
                    target="phoenix_mmi.resource_text:build_font_catalog",
                    evidence="Session 081 and SPEC-089",
                    limitation="bitmap-atlas semantics and consumer routine remain unconfirmed",
                )
            ],
            graph_version="v73",
            graph_node_id="m3-font-candidate-catalog",
            section="font_catalog",
            summary=fonts,
        )
        _write(
            args.public_output / "session081/font-candidate-catalog.json",
            report081,
        )

        language = build_language_topology(sources)
        graph = build_resource_relationship_graph(
            catalog, geometry, pixels, preview, text, fonts, language
        )
        report082 = _advance(
            repository,
            report081,
            session="082",
            transitions=[
                _transition(
                    "M3-CAP-014",
                    target="phoenix_mmi.resource_text:build_language_topology",
                    evidence="Session 082 and SPEC-090",
                    limitation="LOD payload semantics and display binding remain unresolved",
                ),
                _transition(
                    "M3-CAP-015",
                    target="phoenix_mmi.resource_text:build_resource_relationship_graph",
                    evidence="Session 082 and SPEC-090",
                    limitation="runtime renderer and resource ownership remain open",
                ),
            ],
            graph_version="v74",
            graph_node_id="m3-language-and-resource-graph",
            section="language_topology",
            summary=language,
        )
        report082["resource_relationship_graph"] = graph
        _write(
            args.public_output
            / "session082/language-topology-resource-graph.json",
            report082,
        )

    integration_first = run_resource_lab_integration()
    integration_second = run_resource_lab_integration()
    deterministic = integration_first == integration_second
    if not integration_first["passed"] or not deterministic:
        raise RuntimeError("M3 deterministic integration failed")
    integration = dict(integration_first)
    integration["repeat_run_equal"] = deterministic
    report083 = _advance(
        repository,
        report082,
        session="083",
        transitions=[
            _transition(
                "M3-CAP-016",
                target=(
                    "phoenix_mmi.resource_lab_integration:"
                    "run_resource_lab_integration"
                ),
                evidence="Session 083 and SPEC-091",
                limitation="integration uses synthetic non-firmware resources",
            )
        ],
        graph_version="v75",
        graph_node_id="m3-deterministic-resource-integration",
        section="integration_gate",
        summary=integration,
    )
    if (
        report083["classification"]["m3_status"] != "COMPLETE"
        or report083["exit_criteria_passed"]
        != report083["exit_criteria_total"]
    ):
        raise RuntimeError("M3 exit criteria did not close")
    report083["milestone_transition"] = {
        "m3": "COMPLETE",
        "m4": "READY",
        "m4_authorized_scope": "read-only runtime research",
        "safe_mutation_ready": False,
        "installable_artifact_ready": False,
    }
    _write(
        args.public_output / "session083/milestone-m3-closure.json",
        report083,
    )
    print(
        json.dumps(
            {
                "sessions": [f"{value:03d}" for value in range(75, 84)],
                "criteria": (
                    f"{report083['exit_criteria_passed']}/"
                    f"{report083['exit_criteria_total']}"
                ),
                "m3": "COMPLETE",
                "m4": "READY",
                "resource_records": catalog["record_count"],
                "integration_repeat_equal": deterministic,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

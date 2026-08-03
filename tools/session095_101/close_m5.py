#!/usr/bin/env python3
"""Run Sessions 095-101 and close Milestone M5 deterministically."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phoenix_mmi.ui_integration import run_ui_prototype_integration
from phoenix_mmi.ui_layout import build_layout_catalog
from phoenix_mmi.ui_model import build_phoenix_information_architecture
from phoenix_mmi.ui_playback import run_ui_playback
from phoenix_mmi.ui_prototype_audit import advance_m5_progress
from phoenix_mmi.ui_quality import audit_ui_quality
from phoenix_mmi.ui_reducer import build_reducer_contract
from phoenix_mmi.ui_renderer import (
    build_preview_set,
    build_public_preview_catalog,
)
from phoenix_mmi.ui_theme import build_public_theme_catalog


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
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
    capability_id: str,
    target: str,
    evidence: str,
    limitation: str,
    graph_version: str,
    graph_node_id: str,
    section: str,
    summary: dict[str, object],
) -> dict[str, object]:
    report = advance_m5_progress(
        repository,
        previous,
        session=session,
        transitions=[
            _transition(
                capability_id,
                target=target,
                evidence=evidence,
                limitation=limitation,
            )
        ],
        graph_version=graph_version,
        graph_node_id=graph_node_id,
    )
    report[section] = summary
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--preview-output", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    previous = json.loads(
        (
            repository
            / "research/milestones/m5/session094/"
            "information-architecture-screen-schema.json"
        ).read_text(encoding="utf-8")
    )
    model = build_phoenix_information_architecture()

    reducer = build_reducer_contract(model)
    report095 = _advance(
        repository,
        previous,
        session="095",
        capability_id="M5-CAP-011",
        target="phoenix_mmi.ui_reducer:reduce_ui_state",
        evidence="Session 095 and SPEC-104",
        limitation="abstract actions are not physical input mappings",
        graph_version="v87",
        graph_node_id="m5-focus-navigation-reducer",
        section="reducer_contract",
        summary=reducer,
    )
    _write_json(
        args.public_output / "session095/focus-navigation-reducer.json",
        report095,
    )

    layout = build_layout_catalog(model)
    report096 = _advance(
        repository,
        report095,
        session="096",
        capability_id="M5-CAP-012",
        target="phoenix_mmi.ui_layout:build_layout_catalog",
        evidence="Session 096 and SPEC-105",
        limitation="fixed host geometry is not the firmware layout",
        graph_version="v88",
        graph_node_id="m5-bounded-layout",
        section="layout_catalog",
        summary=layout,
    )
    _write_json(
        args.public_output / "session096/bounded-layout-catalog.json",
        report096,
    )

    theme = build_public_theme_catalog(model)
    report097 = _advance(
        repository,
        report096,
        session="097",
        capability_id="M5-CAP-013",
        target="phoenix_mmi.ui_theme:build_original_theme_bundle",
        evidence="Session 097 and SPEC-106",
        limitation="firmware renderer compatibility remains unknown",
        graph_version="v89",
        graph_node_id="m5-original-theme-assets",
        section="theme_catalog",
        summary=theme,
    )
    _write_json(
        args.public_output / "session097/original-theme-assets.json",
        report097,
    )

    previews_first = build_preview_set(model)
    previews_second = build_preview_set(model)
    if previews_first != previews_second:
        raise ValueError("Session 098 preview set is not deterministic")
    args.preview_output.mkdir(parents=True, exist_ok=True)
    for preview in previews_first:
        (args.preview_output / f"{preview.screen_id}.svg").write_bytes(
            preview.svg.encode("utf-8")
        )
    preview_catalog = build_public_preview_catalog(previews_first)
    preview_catalog["repeat_run_equal"] = True
    report098 = _advance(
        repository,
        report097,
        session="098",
        capability_id="M5-CAP-014",
        target="phoenix_mmi.ui_renderer:render_screen_svg",
        evidence="Session 098 and SPEC-107",
        limitation="static host SVG is not a firmware renderer",
        graph_version="v90",
        graph_node_id="m5-offline-svg-renderer",
        section="preview_catalog",
        summary=preview_catalog,
    )
    _write_json(
        args.public_output / "session098/offline-preview-renderer.json",
        report098,
    )

    playback_first = run_ui_playback(model=model)
    playback_second = run_ui_playback(model=model)
    if playback_first != playback_second:
        raise ValueError("Session 099 playback is not deterministic")
    playback_first["repeat_run_equal"] = True
    report099 = _advance(
        repository,
        report098,
        session="099",
        capability_id="M5-CAP-015",
        target="phoenix_mmi.ui_playback:run_ui_playback",
        evidence="Session 099 and SPEC-108",
        limitation="host snapshots do not establish target timing",
        graph_version="v91",
        graph_node_id="m5-input-playback",
        section="playback",
        summary=playback_first,
    )
    _write_json(
        args.public_output / "session099/input-playback-snapshots.json",
        report099,
    )

    quality = audit_ui_quality()
    if quality["criteria_passed"] != quality["criteria_total"]:
        raise ValueError("Session 100 UI quality gate failed")
    report100 = _advance(
        repository,
        report099,
        session="100",
        capability_id="M5-CAP-016",
        target="phoenix_mmi.ui_quality:audit_ui_quality",
        evidence="Session 100 and SPEC-109",
        limitation="host quality does not prove MMI hardware suitability",
        graph_version="v92",
        graph_node_id="m5-ui-quality-audit",
        section="quality_audit",
        summary=quality,
    )
    _write_json(
        args.public_output / "session100/ui-quality-audit.json",
        report100,
    )

    integration_first = run_ui_prototype_integration()
    integration_second = run_ui_prototype_integration()
    if integration_first != integration_second:
        raise ValueError("Session 101 integration is not deterministic")
    if not integration_first["passed"]:
        raise ValueError("Session 101 integration gate failed")
    integration_first["repeat_run_equal"] = True
    report101 = _advance(
        repository,
        report100,
        session="101",
        capability_id="M5-CAP-017",
        target="phoenix_mmi.ui_integration:run_ui_prototype_integration",
        evidence="Session 101 and SPEC-110",
        limitation="M6 remains static navigation feasibility research",
        graph_version="v93",
        graph_node_id="milestone-m5-closure",
        section="integration",
        summary=integration_first,
    )
    if (
        report101["classification"]["m5_status"] != "COMPLETE"
        or report101["milestone_transition"]["m6"] != "READY"
        or report101["classification"]["safe_mutation_ready"] is not False
    ):
        raise ValueError("M5 closure gate failed")
    _write_json(
        args.public_output / "session101/milestone-m5-closure.json",
        report101,
    )

    print(
        json.dumps(
            {
                "sessions": [f"{value:03d}" for value in range(95, 102)],
                "criteria": (
                    f"{report101['exit_criteria_passed']}/"
                    f"{report101['exit_criteria_total']}"
                ),
                "m5": report101["classification"]["m5_status"],
                "m6": report101["milestone_transition"]["m6"],
                "previews": preview_catalog["preview_count"],
                "quality": (
                    f"{quality['criteria_passed']}/"
                    f"{quality['criteria_total']}"
                ),
                "integration_repeat_equal": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

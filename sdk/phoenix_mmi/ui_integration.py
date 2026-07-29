"""Synthetic end-to-end integration gate for the M5 Phoenix UI prototype."""

from __future__ import annotations

from hashlib import sha256
import json

from .ui_constraints import (
    build_ui_constraint_contract,
    validate_ui_constraint_contract,
)
from .ui_layout import build_layout_catalog
from .ui_model import (
    build_phoenix_information_architecture,
    build_public_information_architecture,
)
from .ui_playback import run_ui_playback
from .ui_quality import audit_ui_quality
from .ui_reducer import build_reducer_contract
from .ui_renderer import build_preview_set, build_public_preview_catalog
from .ui_theme import build_public_theme_catalog


UI_INTEGRATION_SCHEMA = "phoenix-mmi.ui-integration/v1"


def run_ui_prototype_integration() -> dict[str, object]:
    """Run the complete M5 chain without firmware, files, network or vehicle."""

    constraints = build_ui_constraint_contract()
    validate_ui_constraint_contract(constraints)
    model = build_phoenix_information_architecture()
    architecture = build_public_information_architecture(model)
    reducer = build_reducer_contract(model)
    layout = build_layout_catalog(model)
    theme = build_public_theme_catalog(model)
    previews = build_preview_set(model)
    preview_catalog = build_public_preview_catalog(previews)
    playback = run_ui_playback(model=model)
    quality = audit_ui_quality()
    stages = [
        {
            "stage_id": "M5-I1",
            "name": "constraint contract",
            "passed": constraints["classification"]["offline_prototype_ready"],
        },
        {
            "stage_id": "M5-I2",
            "name": "information architecture",
            "passed": (
                architecture["topology"]["screen_count"] == 5
                and architecture["topology"]["all_screens_reachable"]
            ),
        },
        {
            "stage_id": "M5-I3",
            "name": "focus and navigation reducer",
            "passed": (
                reducer["state_space"]["base_focus_state_count"] == 16
                and reducer["state_space"]["transition_count"] == 80
            ),
        },
        {
            "stage_id": "M5-I4",
            "name": "bounded layout",
            "passed": (
                layout["metrics"]["overflow_count"] == 0
                and layout["metrics"]["overlap_count"] == 0
            ),
        },
        {
            "stage_id": "M5-I5",
            "name": "original theme and assets",
            "passed": (
                theme["metrics_summary"]["external_asset_count"] == 0
                and theme["classification"]["provenance"]
                == "PROJECT_PHOENIX_ORIGINAL"
            ),
        },
        {
            "stage_id": "M5-I6",
            "name": "offline renderer",
            "passed": (
                preview_catalog["preview_count"] == 5
                and preview_catalog["metrics"][
                    "external_reference_count"
                ]
                == 0
            ),
        },
        {
            "stage_id": "M5-I7",
            "name": "deterministic playback",
            "passed": playback["metrics"]["all_model_screens_visited"],
        },
        {
            "stage_id": "M5-I8",
            "name": "quality audit",
            "passed": quality["criteria_passed"] == quality["criteria_total"],
        },
    ]
    summary = {
        "constraint_schema": constraints["schema"],
        "screen_count": architecture["topology"]["screen_count"],
        "focus_state_count": reducer["state_space"][
            "base_focus_state_count"
        ],
        "transition_count": reducer["state_space"]["transition_count"],
        "entry_rectangle_count": layout["metrics"][
            "entry_rectangle_count"
        ],
        "original_icon_count": theme["metrics_summary"]["icon_asset_count"],
        "preview_count": preview_catalog["preview_count"],
        "playback_action_count": playback["metrics"]["action_count"],
        "quality_criteria": (
            f"{quality['criteria_passed']}/{quality['criteria_total']}"
        ),
    }
    fingerprint = sha256(
        json.dumps(
            {
                "stages": stages,
                "summary": summary,
                "preview_manifest": preview_catalog["manifest"],
                "playback_fingerprint": playback["metrics"][
                    "playback_fingerprint"
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    passed = all(stage["passed"] for stage in stages)
    return {
        "schema": UI_INTEGRATION_SCHEMA,
        "integration_version": "m5-session101-v1",
        "stages": stages,
        "stages_passed": sum(int(stage["passed"]) for stage in stages),
        "stages_total": len(stages),
        "summary": summary,
        "integration_fingerprint": fingerprint,
        "passed": passed,
        "classification": {
            "integration_gate": "PASS" if passed else "FAIL",
            "scope": "SYNTHETIC_OFFLINE_HOST_ONLY",
            "firmware_compatibility": "NOT_ESTABLISHED",
            "hardware_suitability": "NOT_ESTABLISHED",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "navigation_media_content_included": False,
            "vehicle_data_included": False,
            "installable_artifacts_included": False,
            "original_or_synthetic_content_only": True,
        },
    }

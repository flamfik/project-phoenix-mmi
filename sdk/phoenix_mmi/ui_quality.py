"""Offline legibility, focus and bounded-complexity audit for Phoenix UI."""

from __future__ import annotations

import re

from .ui_layout import build_layout_catalog
from .ui_model import build_phoenix_information_architecture
from .ui_playback import run_ui_playback
from .ui_reducer import UIState
from .ui_renderer import (
    build_preview_set,
    build_public_preview_catalog,
    render_screen_svg,
)
from .ui_theme import (
    build_original_theme_bundle,
    build_public_theme_catalog,
    color_value,
)


UI_QUALITY_SCHEMA = "phoenix-mmi.ui-quality-audit/v1"
_HEX_COLOR = re.compile(r"^#[0-9A-Fa-f]{6}$")


def _rgb(hex_color: str) -> tuple[int, int, int]:
    if not _HEX_COLOR.fullmatch(hex_color):
        raise ValueError("invalid RGB color")
    return tuple(
        int(hex_color[index : index + 2], 16)
        for index in (1, 3, 5)
    )


def _linear(channel: int) -> float:
    value = channel / 255
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    red, green, blue = _rgb(hex_color)
    return (
        0.2126 * _linear(red)
        + 0.7152 * _linear(green)
        + 0.0722 * _linear(blue)
    )


def contrast_ratio(first: str, second: str) -> float:
    first_luminance = relative_luminance(first)
    second_luminance = relative_luminance(second)
    lighter = max(first_luminance, second_luminance)
    darker = min(first_luminance, second_luminance)
    return (lighter + 0.05) / (darker + 0.05)


def audit_ui_quality() -> dict[str, object]:
    model = build_phoenix_information_architecture()
    layout = build_layout_catalog(model)
    theme = build_original_theme_bundle(model)
    theme_catalog = build_public_theme_catalog(model)
    previews_first = build_preview_set(model)
    previews_second = build_preview_set(model)
    preview_catalog = build_public_preview_catalog(previews_first)
    playback_first = run_ui_playback(model=model)
    playback_second = run_ui_playback(model=model)

    contrasts = {
        "primary_on_surface": contrast_ratio(
            color_value(theme, "text-primary"),
            color_value(theme, "surface"),
        ),
        "primary_on_focused_surface": contrast_ratio(
            color_value(theme, "text-primary"),
            color_value(theme, "surface-focus"),
        ),
        "secondary_on_background": contrast_ratio(
            color_value(theme, "text-secondary"),
            color_value(theme, "background"),
        ),
        "focus_on_focused_surface": contrast_ratio(
            color_value(theme, "focus"),
            color_value(theme, "surface-focus"),
        ),
    }
    contrast_gate = (
        contrasts["primary_on_surface"] >= 4.5
        and contrasts["primary_on_focused_surface"] >= 4.5
        and contrasts["secondary_on_background"] >= 4.5
        and contrasts["focus_on_focused_surface"] >= 3.0
    )

    focus_checks = []
    for screen in model.screens:
        for entry in screen.entries:
            if not entry.focusable:
                continue
            preview = render_screen_svg(
                model, UIState(screen.screen_id, entry.entry_id)
            )
            focus_checks.append(
                {
                    "state_id": f"{screen.screen_id}:{entry.entry_id}",
                    "focus_indicator_count": preview.svg.count(
                        'stroke="#78FFE0"'
                    ),
                    "passed": (
                        preview.svg.count('stroke="#78FFE0"') == 1
                    ),
                }
            )
    focus_gate = all(row["passed"] for row in focus_checks)
    layout_metrics = layout["metrics"]
    preview_metrics = preview_catalog["metrics"]
    theme_metrics = theme_catalog["metrics_summary"]
    criteria = [
        {
            "criterion_id": "UI-Q1",
            "name": "fixed viewport and bounded rectangles",
            "passed": (
                layout["viewport"] == {"width": 480, "height": 240}
                and layout_metrics["overflow_count"] == 0
                and layout_metrics["overlap_count"] == 0
            ),
        },
        {
            "criterion_id": "UI-Q2",
            "name": "one visible focus indicator per focus state",
            "passed": focus_gate and len(focus_checks) == 16,
        },
        {
            "criterion_id": "UI-Q3",
            "name": "host contrast thresholds",
            "passed": contrast_gate,
        },
        {
            "criterion_id": "UI-Q4",
            "name": "minimum focus target height",
            "passed": layout_metrics["minimum_entry_height"] >= 32,
        },
        {
            "criterion_id": "UI-Q5",
            "name": "bounded screen and draw complexity",
            "passed": (
                layout_metrics["maximum_entries_per_screen"] <= 6
                and max(
                    row["draw_command_count"]
                    for row in preview_catalog["manifest"]
                )
                <= 32
            ),
        },
        {
            "criterion_id": "UI-Q6",
            "name": "bounded original asset registry",
            "passed": (
                theme_metrics["synthetic_asset_bytes"] <= 8192
                and theme_metrics["external_asset_count"] == 0
            ),
        },
        {
            "criterion_id": "UI-Q7",
            "name": "static renderer has no external content",
            "passed": (
                preview_metrics["external_reference_count"] == 0
                and preview_metrics["script_count"] == 0
                and preview_metrics["embedded_raster_count"] == 0
            ),
        },
        {
            "criterion_id": "UI-Q8",
            "name": "renderer and playback reproduce exactly",
            "passed": (
                previews_first == previews_second
                and playback_first == playback_second
            ),
        },
    ]
    passed = sum(int(row["passed"]) for row in criteria)
    return {
        "schema": UI_QUALITY_SCHEMA,
        "audit_version": "m5-session100-v1",
        "criteria": criteria,
        "criteria_passed": passed,
        "criteria_total": len(criteria),
        "focus_audit": {
            "state_count": len(focus_checks),
            "all_states_have_one_indicator": focus_gate,
            "checks": focus_checks,
        },
        "contrast_audit": {
            "ratios": {
                key: round(value, 4)
                for key, value in sorted(contrasts.items())
            },
            "primary_text_threshold": 4.5,
            "focus_indicator_threshold": 3.0,
            "passed": contrast_gate,
        },
        "complexity": {
            "screen_count": layout_metrics["screen_layout_count"],
            "focus_state_count": len(focus_checks),
            "maximum_entries_per_screen": layout_metrics[
                "maximum_entries_per_screen"
            ],
            "maximum_draw_commands": max(
                row["draw_command_count"]
                for row in preview_catalog["manifest"]
            ),
            "synthetic_asset_bytes": theme_metrics[
                "synthetic_asset_bytes"
            ],
        },
        "classification": {
            "quality_gate": "PASS" if passed == len(criteria) else "FAIL",
            "measurement_scope": "HOST_PROTOTYPE_ONLY",
            "target_hardware_suitability": "NOT_ESTABLISHED",
            "firmware_renderer_suitability": "NOT_ESTABLISHED",
            "numeric_mmi_cpu_budget_claimed": False,
            "numeric_mmi_memory_budget_claimed": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "navigation_media_content_included": False,
            "vehicle_data_included": False,
            "host_metrics_only": True,
        },
    }

"""Dependency-free SVG renderer for the original offline Phoenix UI."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from html import escape
import xml.etree.ElementTree as ET

from .ui_layout import (
    ScreenLayout,
    build_screen_layout,
    validate_screen_layout,
)
from .ui_model import (
    InformationArchitecture,
    ScreenDefinition,
    UIEntry,
    build_phoenix_information_architecture,
    validate_information_architecture,
)
from .ui_reducer import UIState, validate_ui_state
from .ui_theme import (
    ThemeBundle,
    build_original_theme_bundle,
    color_value,
    icon_asset,
    metric_value,
    text_value,
    validate_theme_bundle,
)


UI_RENDERER_SCHEMA = "phoenix-mmi.ui-renderer/v1"
SVG_NAMESPACE = "http://www.w3.org/2000/svg"


@dataclass(frozen=True)
class RenderedPreview:
    screen_id: str
    focused_entry_id: str
    svg: str
    draw_command_count: int


def _screen(
    model: InformationArchitecture,
    screen_id: str,
) -> ScreenDefinition:
    values = {screen.screen_id: screen for screen in model.screens}
    if screen_id not in values:
        raise ValueError("renderer screen does not exist")
    return values[screen_id]


def _icon_id(screen: ScreenDefinition, entry: UIEntry) -> str:
    if screen.screen_id == "home":
        if entry.target_screen_id is None:
            raise ValueError("home entry has no icon target")
        return entry.target_screen_id
    return screen.screen_id


def _polyline_points(
    points: tuple[tuple[int, int], ...],
) -> str:
    return " ".join(f"{x},{y}" for x, y in points)


def render_screen_svg(
    model: InformationArchitecture,
    state: UIState,
    *,
    layout: ScreenLayout | None = None,
    theme: ThemeBundle | None = None,
) -> RenderedPreview:
    """Render one state without files, firmware, network or external assets."""

    validate_information_architecture(model)
    validate_ui_state(model, state)
    screen = _screen(model, state.screen_id)
    current_layout = layout or build_screen_layout(model, screen.screen_id)
    validate_screen_layout(
        current_layout,
        expected_entry_ids={entry.entry_id for entry in screen.entries},
    )
    current_theme = theme or build_original_theme_bundle(model)
    validate_theme_bundle(current_theme, model)
    layout_by_entry = {
        entry.entry_id: entry.rect for entry in current_layout.entries
    }
    colors = {
        name: color_value(current_theme, name)
        for name in (
            "accent",
            "background",
            "divider",
            "focus",
            "surface",
            "surface-focus",
            "text-primary",
            "text-secondary",
        )
    }
    radius = metric_value(current_theme, "corner-radius")
    focus_stroke = metric_value(current_theme, "focus-stroke")
    title_size = metric_value(current_theme, "title-size")
    body_size = metric_value(current_theme, "body-size")
    footer_size = metric_value(current_theme, "footer-size")
    commands = 0
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="{SVG_NAMESPACE}" width="480" height="240" '
            'viewBox="0 0 480 240" role="img" '
            f'aria-label="{escape(text_value(current_theme, screen.title_token))}">'
        ),
        (
            f'<rect x="0" y="0" width="480" height="240" '
            f'fill="{colors["background"]}"/>'
        ),
    ]
    commands += 1
    lines.append(
        (
            f'<text x="12" y="25" fill="{colors["text-primary"]}" '
            f'font-family="sans-serif" font-size="{title_size}" '
            'font-weight="600">'
            f'{escape(text_value(current_theme, screen.title_token))}</text>'
        )
    )
    commands += 1
    lines.append(
        (
            f'<line x1="12" y1="35" x2="468" y2="35" '
            f'stroke="{colors["divider"]}" stroke-width="1"/>'
        )
    )
    commands += 1

    for entry in screen.entries:
        rect = layout_by_entry[entry.entry_id]
        focused = entry.entry_id == state.focused_entry_id
        fill = colors["surface-focus"] if focused else colors["surface"]
        stroke = colors["focus"] if focused else colors["divider"]
        stroke_width = focus_stroke if focused else 1
        lines.append(
            (
                f'<rect x="{rect.x}" y="{rect.y}" width="{rect.width}" '
                f'height="{rect.height}" rx="{radius}" fill="{fill}" '
                f'stroke="{stroke}" stroke-width="{stroke_width}"/>'
            )
        )
        commands += 1
        asset = icon_asset(current_theme, _icon_id(screen, entry))
        lines.append(
            (
                f'<g transform="translate({rect.x + 10} {rect.y + 9})" '
                f'fill="none" stroke="{colors["accent"]}" '
                'stroke-width="1.5" stroke-linecap="round" '
                'stroke-linejoin="round">'
            )
        )
        for polyline in asset.polylines:
            lines.append(
                f'<polyline points="{_polyline_points(polyline)}"/>'
            )
            commands += 1
        lines.append("</g>")
        lines.append(
            (
                f'<text x="{rect.x + 40}" y="{rect.y + 22}" '
                f'fill="{colors["text-primary"]}" '
                f'font-family="sans-serif" font-size="{body_size}">'
                f'{escape(text_value(current_theme, entry.label_token))}</text>'
            )
        )
        commands += 1

    lines.append(
        (
            f'<line x1="12" y1="215" x2="468" y2="215" '
            f'stroke="{colors["divider"]}" stroke-width="1"/>'
        )
    )
    commands += 1
    lines.append(
        (
            f'<text x="12" y="232" fill="{colors["text-secondary"]}" '
            f'font-family="sans-serif" font-size="{footer_size}">'
            f'{escape(text_value(current_theme, "phoenix.action.back"))}</text>'
        )
    )
    commands += 1
    home_text = escape(text_value(current_theme, "phoenix.action.home"))
    lines.append(
        (
            f'<text x="468" y="232" fill="{colors["text-secondary"]}" '
            f'font-family="sans-serif" font-size="{footer_size}" '
            f'text-anchor="end">{home_text}</text>'
        )
    )
    commands += 1
    lines.append("</svg>")
    svg = "\n".join(lines) + "\n"
    validate_rendered_svg(svg)
    return RenderedPreview(
        screen_id=screen.screen_id,
        focused_entry_id=state.focused_entry_id,
        svg=svg,
        draw_command_count=commands,
    )


def validate_rendered_svg(svg: str) -> None:
    if "<script" in svg.lower() or "<image" in svg.lower():
        raise ValueError("SVG contains an executable or external element")
    if "href=" in svg.lower() or "url(" in svg.lower() or "data:" in svg.lower():
        raise ValueError("SVG contains an external reference")
    try:
        root = ET.fromstring(svg)
    except ET.ParseError as exc:
        raise ValueError("invalid SVG output") from exc
    if (
        root.tag != f"{{{SVG_NAMESPACE}}}svg"
        or root.attrib.get("width") != "480"
        or root.attrib.get("height") != "240"
        or root.attrib.get("viewBox") != "0 0 480 240"
    ):
        raise ValueError("SVG root differs from the 480x240 contract")


def build_preview_set(
    model: InformationArchitecture | None = None,
) -> tuple[RenderedPreview, ...]:
    current = model or build_phoenix_information_architecture()
    validate_information_architecture(current)
    theme = build_original_theme_bundle(current)
    previews = []
    for screen in current.screens:
        first_focus = next(
            entry for entry in screen.entries if entry.focusable
        )
        state = UIState(screen.screen_id, first_focus.entry_id)
        previews.append(
            render_screen_svg(
                current,
                state,
                layout=build_screen_layout(current, screen.screen_id),
                theme=theme,
            )
        )
    return tuple(previews)


def build_public_preview_catalog(
    previews: tuple[RenderedPreview, ...] | None = None,
) -> dict[str, object]:
    current = previews or build_preview_set()
    if not current:
        raise ValueError("preview catalog cannot be empty")
    for preview in current:
        validate_rendered_svg(preview.svg)
    manifest = [
        {
            "preview_id": f"phoenix-{preview.screen_id}",
            "screen_id": preview.screen_id,
            "focused_entry_id": preview.focused_entry_id,
            "file_name": f"{preview.screen_id}.svg",
            "byte_count": len(preview.svg.encode("utf-8")),
            "draw_command_count": preview.draw_command_count,
            "sha256": sha256(preview.svg.encode("utf-8")).hexdigest(),
        }
        for preview in current
    ]
    return {
        "schema": UI_RENDERER_SCHEMA,
        "renderer_version": "m5-session098-v1",
        "format": "SVG_1_1_STATIC_SUBSET",
        "viewport": {"width": 480, "height": 240},
        "preview_count": len(current),
        "manifest": manifest,
        "metrics": {
            "total_svg_bytes": sum(row["byte_count"] for row in manifest),
            "total_draw_commands": sum(
                row["draw_command_count"] for row in manifest
            ),
            "external_reference_count": 0,
            "script_count": 0,
            "embedded_raster_count": 0,
        },
        "classification": {
            "renderer": "ORIGINAL_STATIC_HOST_SVG",
            "deterministic": True,
            "offline_only": True,
            "firmware_renderer_compatibility": "NOT_ESTABLISHED",
            "hardware_performance": "NOT_MEASURED",
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "navigation_media_content_included": False,
            "external_assets_included": False,
            "scripts_included": False,
            "original_content_only": True,
        },
    }

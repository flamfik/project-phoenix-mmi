"""Original Phoenix design tokens, text and normalized vector primitives."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re

from .ui_model import (
    InformationArchitecture,
    build_phoenix_information_architecture,
    validate_information_architecture,
)


UI_THEME_SCHEMA = "phoenix-mmi.ui-theme/v1"
_HEX_COLOR = re.compile(r"^#[0-9A-F]{6}$")


@dataclass(frozen=True)
class ColorToken:
    token_id: str
    value: str
    role: str
    source: str = "ORIGINAL"


@dataclass(frozen=True)
class MetricToken:
    token_id: str
    value: int
    unit: str
    source: str = "ORIGINAL"


@dataclass(frozen=True)
class TextToken:
    token_id: str
    value: str
    source: str = "ORIGINAL"


@dataclass(frozen=True)
class IconAsset:
    asset_id: str
    viewbox_width: int
    viewbox_height: int
    polylines: tuple[tuple[tuple[int, int], ...], ...]
    source: str = "ORIGINAL"
    license_id: str = "PROJECT_PHOENIX_ORIGINAL"


@dataclass(frozen=True)
class ThemeBundle:
    schema: str
    bundle_version: str
    colors: tuple[ColorToken, ...]
    metrics: tuple[MetricToken, ...]
    text: tuple[TextToken, ...]
    icons: tuple[IconAsset, ...]


def _icon(
    asset_id: str,
    *polylines: tuple[tuple[int, int], ...],
) -> IconAsset:
    return IconAsset(asset_id, 16, 16, tuple(polylines))


def build_original_theme_bundle(
    model: InformationArchitecture | None = None,
) -> ThemeBundle:
    current = model or build_phoenix_information_architecture()
    validate_information_architecture(current)
    text_values = {
        "phoenix.screen.home": "Phoenix",
        "phoenix.screen.communication": "Communication",
        "phoenix.screen.media": "Media",
        "phoenix.screen.navigation": "Navigation",
        "phoenix.screen.settings": "Settings",
        "phoenix.entry.home.communication": "Communication",
        "phoenix.entry.home.media": "Media",
        "phoenix.entry.home.navigation": "Navigation",
        "phoenix.entry.home.settings": "Settings",
        "phoenix.entry.communication.contacts": "Contacts",
        "phoenix.entry.communication.devices": "Devices",
        "phoenix.entry.communication.recent": "Recent",
        "phoenix.entry.media.library": "Library",
        "phoenix.entry.media.now-playing": "Now playing",
        "phoenix.entry.media.sources": "Sources",
        "phoenix.entry.navigation.destination": "Destination",
        "phoenix.entry.navigation.route-overview": "Route overview",
        "phoenix.entry.navigation.saved": "Saved",
        "phoenix.entry.settings.display": "Display",
        "phoenix.entry.settings.sound": "Sound",
        "phoenix.entry.settings.system": "System",
        "phoenix.action.back": "Back",
        "phoenix.action.home": "Home",
    }
    bundle = ThemeBundle(
        schema=UI_THEME_SCHEMA,
        bundle_version="m5-session097-v1",
        colors=(
            ColorToken("background", "#07111C", "canvas"),
            ColorToken("surface", "#122334", "entry"),
            ColorToken("surface-focus", "#173447", "focused-entry"),
            ColorToken("text-primary", "#F4F8FB", "primary-text"),
            ColorToken("text-secondary", "#B8C9D8", "secondary-text"),
            ColorToken("accent", "#34E1C1", "brand-accent"),
            ColorToken("focus", "#78FFE0", "focus-indicator"),
            ColorToken("divider", "#2D485E", "separator"),
        ),
        metrics=(
            MetricToken("title-size", 18, "px"),
            MetricToken("body-size", 14, "px"),
            MetricToken("footer-size", 10, "px"),
            MetricToken("corner-radius", 6, "px"),
            MetricToken("focus-stroke", 2, "px"),
            MetricToken("icon-size", 16, "px"),
            MetricToken("icon-text-gap", 10, "px"),
        ),
        text=tuple(
            TextToken(token_id, text_values[token_id])
            for token_id in sorted(text_values)
        ),
        icons=(
            _icon(
                "back",
                ((12, 3), (5, 8), (12, 13)),
                ((5, 8), (15, 8)),
            ),
            _icon(
                "communication",
                ((2, 3), (14, 3), (14, 11), (7, 11), (4, 14), (4, 11), (2, 11), (2, 3)),
                ((5, 7), (11, 7)),
            ),
            _icon(
                "home",
                ((2, 8), (8, 2), (14, 8)),
                ((4, 7), (4, 14), (12, 14), (12, 7)),
            ),
            _icon(
                "media",
                ((4, 2), (13, 8), (4, 14), (4, 2)),
            ),
            _icon(
                "navigation",
                ((8, 1), (14, 8), (8, 15), (2, 8), (8, 1)),
                ((8, 4), (10, 8), (8, 12), (6, 8), (8, 4)),
            ),
            _icon(
                "settings",
                ((8, 1), (10, 4), (14, 4), (12, 8), (14, 12), (10, 12), (8, 15), (6, 12), (2, 12), (4, 8), (2, 4), (6, 4), (8, 1)),
                ((6, 8), (8, 6), (10, 8), (8, 10), (6, 8)),
            ),
        ),
    )
    validate_theme_bundle(bundle, current)
    return bundle


def validate_theme_bundle(
    bundle: ThemeBundle,
    model: InformationArchitecture,
) -> None:
    validate_information_architecture(model)
    if bundle.schema != UI_THEME_SCHEMA:
        raise ValueError("unsupported Phoenix theme schema")
    color_ids = [token.token_id for token in bundle.colors]
    metric_ids = [token.token_id for token in bundle.metrics]
    text_ids = [token.token_id for token in bundle.text]
    asset_ids = [asset.asset_id for asset in bundle.icons]
    for values, label in (
        (color_ids, "color"),
        (metric_ids, "metric"),
        (text_ids, "text"),
        (asset_ids, "asset"),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {label} token")
    if any(
        token.source != "ORIGINAL"
        or not _HEX_COLOR.fullmatch(token.value)
        for token in bundle.colors
    ):
        raise ValueError("theme color is not original uppercase RGB")
    if any(
        token.source != "ORIGINAL"
        or token.value <= 0
        or token.unit != "px"
        for token in bundle.metrics
    ):
        raise ValueError("invalid theme metric")
    required_text = {
        screen.title_token
        for screen in model.screens
    } | {
        entry.label_token
        for screen in model.screens
        for entry in screen.entries
    } | {"phoenix.action.back", "phoenix.action.home"}
    if set(text_ids) != required_text:
        raise ValueError("theme text registry does not cover the UI model")
    if any(
        token.source != "ORIGINAL"
        or not token.value
        or len(token.value) > 32
        for token in bundle.text
    ):
        raise ValueError("invalid original text token")
    for asset in bundle.icons:
        if (
            asset.source != "ORIGINAL"
            or asset.license_id != "PROJECT_PHOENIX_ORIGINAL"
            or asset.viewbox_width != 16
            or asset.viewbox_height != 16
            or not asset.polylines
        ):
            raise ValueError("invalid original icon asset")
        for polyline in asset.polylines:
            if len(polyline) < 2:
                raise ValueError("icon polyline is too short")
            if any(
                x < 0 or y < 0 or x > 16 or y > 16
                for x, y in polyline
            ):
                raise ValueError("icon point exceeds normalized viewbox")


def color_value(bundle: ThemeBundle, token_id: str) -> str:
    values = {
        token.token_id: token.value for token in bundle.colors
    }
    if token_id not in values:
        raise ValueError("unknown color token")
    return values[token_id]


def metric_value(bundle: ThemeBundle, token_id: str) -> int:
    values = {
        token.token_id: token.value for token in bundle.metrics
    }
    if token_id not in values:
        raise ValueError("unknown metric token")
    return values[token_id]


def text_value(bundle: ThemeBundle, token_id: str) -> str:
    values = {token.token_id: token.value for token in bundle.text}
    if token_id not in values:
        raise ValueError("unknown text token")
    return values[token_id]


def icon_asset(bundle: ThemeBundle, asset_id: str) -> IconAsset:
    values = {asset.asset_id: asset for asset in bundle.icons}
    if asset_id not in values:
        raise ValueError("unknown icon asset")
    return values[asset_id]


def build_public_theme_catalog(
    model: InformationArchitecture | None = None,
) -> dict[str, object]:
    current = model or build_phoenix_information_architecture()
    bundle = build_original_theme_bundle(current)
    serialized_assets = json.dumps(
        [asdict(asset) for asset in bundle.icons],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "schema": bundle.schema,
        "bundle_version": bundle.bundle_version,
        "colors": [asdict(token) for token in bundle.colors],
        "metrics": [asdict(token) for token in bundle.metrics],
        "text": [asdict(token) for token in bundle.text],
        "icons": [asdict(asset) for asset in bundle.icons],
        "metrics_summary": {
            "color_token_count": len(bundle.colors),
            "metric_token_count": len(bundle.metrics),
            "text_token_count": len(bundle.text),
            "icon_asset_count": len(bundle.icons),
            "synthetic_asset_bytes": len(serialized_assets),
            "external_asset_count": 0,
        },
        "classification": {
            "provenance": "PROJECT_PHOENIX_ORIGINAL",
            "firmware_asset_reuse": False,
            "navigation_media_asset_reuse": False,
            "external_asset_dependency": False,
            "renderer_compatibility": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "navigation_media_content_included": False,
            "third_party_assets_included": False,
            "original_content_only": True,
        },
    }

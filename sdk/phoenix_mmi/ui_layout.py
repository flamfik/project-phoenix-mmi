"""Deterministic integer-only 480x240 layout for the Phoenix UI prototype."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .ui_model import (
    InformationArchitecture,
    build_phoenix_information_architecture,
    validate_information_architecture,
)


UI_LAYOUT_SCHEMA = "phoenix-mmi.ui-layout/v1"

VIEWPORT_WIDTH = 480
VIEWPORT_HEIGHT = 240
HEADER_HEIGHT = 36
FOOTER_HEIGHT = 24
CONTENT_X = 12
CONTENT_Y = 42
CONTENT_WIDTH = 456
CONTENT_HEIGHT = 166
ENTRY_X = 12
ENTRY_START_Y = 46
ENTRY_WIDTH = 456
ENTRY_HEIGHT = 34
ENTRY_GAP = 6


@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    width: int
    height: int

    @property
    def right(self) -> int:
        return self.x + self.width

    @property
    def bottom(self) -> int:
        return self.y + self.height

    def contains(self, other: "Rect") -> bool:
        return (
            other.x >= self.x
            and other.y >= self.y
            and other.right <= self.right
            and other.bottom <= self.bottom
        )

    def overlaps(self, other: "Rect") -> bool:
        return (
            self.x < other.right
            and self.right > other.x
            and self.y < other.bottom
            and self.bottom > other.y
        )


@dataclass(frozen=True)
class EntryLayout:
    entry_id: str
    rect: Rect


@dataclass(frozen=True)
class ScreenLayout:
    screen_id: str
    viewport: Rect
    header: Rect
    content: Rect
    footer: Rect
    entries: tuple[EntryLayout, ...]


def build_screen_layout(
    model: InformationArchitecture,
    screen_id: str,
) -> ScreenLayout:
    validate_information_architecture(model)
    screens = {screen.screen_id: screen for screen in model.screens}
    if screen_id not in screens:
        raise ValueError("cannot layout an unknown screen")
    screen = screens[screen_id]
    viewport = Rect(0, 0, VIEWPORT_WIDTH, VIEWPORT_HEIGHT)
    layout = ScreenLayout(
        screen_id=screen_id,
        viewport=viewport,
        header=Rect(0, 0, VIEWPORT_WIDTH, HEADER_HEIGHT),
        content=Rect(
            CONTENT_X,
            CONTENT_Y,
            CONTENT_WIDTH,
            CONTENT_HEIGHT,
        ),
        footer=Rect(
            0,
            VIEWPORT_HEIGHT - FOOTER_HEIGHT,
            VIEWPORT_WIDTH,
            FOOTER_HEIGHT,
        ),
        entries=tuple(
            EntryLayout(
                entry_id=entry.entry_id,
                rect=Rect(
                    ENTRY_X,
                    ENTRY_START_Y
                    + entry.order * (ENTRY_HEIGHT + ENTRY_GAP),
                    ENTRY_WIDTH,
                    ENTRY_HEIGHT,
                ),
            )
            for entry in screen.entries
        ),
    )
    validate_screen_layout(layout, expected_entry_ids={
        entry.entry_id for entry in screen.entries
    })
    return layout


def validate_screen_layout(
    layout: ScreenLayout,
    *,
    expected_entry_ids: set[str] | None = None,
) -> None:
    if (
        layout.viewport
        != Rect(0, 0, VIEWPORT_WIDTH, VIEWPORT_HEIGHT)
    ):
        raise ValueError("layout viewport differs from 480x240")
    for region in (layout.header, layout.content, layout.footer):
        if region.width <= 0 or region.height <= 0:
            raise ValueError("layout region has a non-positive extent")
        if not layout.viewport.contains(region):
            raise ValueError("layout region exceeds the viewport")
    if (
        layout.header.overlaps(layout.content)
        or layout.content.overlaps(layout.footer)
        or layout.header.overlaps(layout.footer)
    ):
        raise ValueError("primary layout regions overlap")
    entry_ids = [entry.entry_id for entry in layout.entries]
    if len(entry_ids) != len(set(entry_ids)):
        raise ValueError("duplicate entry rectangle")
    if expected_entry_ids is not None and set(entry_ids) != expected_entry_ids:
        raise ValueError("layout entries differ from screen entries")
    for index, entry in enumerate(layout.entries):
        if not layout.content.contains(entry.rect):
            raise ValueError("entry rectangle exceeds content region")
        if entry.rect.height < 32:
            raise ValueError("entry rectangle is below the focus target floor")
        for previous in layout.entries[:index]:
            if entry.rect.overlaps(previous.rect):
                raise ValueError("entry rectangles overlap")


def build_layout_catalog(
    model: InformationArchitecture | None = None,
) -> dict[str, object]:
    current = model or build_phoenix_information_architecture()
    validate_information_architecture(current)
    layouts = [
        build_screen_layout(current, screen.screen_id)
        for screen in current.screens
    ]
    entry_rectangles = [
        entry.rect
        for layout in layouts
        for entry in layout.entries
    ]
    return {
        "schema": UI_LAYOUT_SCHEMA,
        "catalog_version": "m5-session096-v1",
        "viewport": {
            "width": VIEWPORT_WIDTH,
            "height": VIEWPORT_HEIGHT,
        },
        "layouts": [asdict(layout) for layout in layouts],
        "metrics": {
            "screen_layout_count": len(layouts),
            "entry_rectangle_count": len(entry_rectangles),
            "minimum_entry_height": min(
                rect.height for rect in entry_rectangles
            ),
            "maximum_entries_per_screen": max(
                len(layout.entries) for layout in layouts
            ),
            "overflow_count": 0,
            "overlap_count": 0,
            "integer_coordinates_only": True,
        },
        "classification": {
            "layout_model": "ORIGINAL_PHOENIX_FIXED_GRID",
            "bounded_to_viewport": True,
            "firmware_layout_reconstruction": False,
            "font_metrics_applied": False,
            "renderer_implemented": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "vehicle_data_included": False,
            "original_geometry_only": True,
        },
    }

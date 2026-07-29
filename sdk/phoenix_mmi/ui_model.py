"""Typed, synthetic information architecture for the offline Phoenix UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re

from .ui_constraints import build_ui_constraint_contract


UI_SCREEN_SCHEMA = "phoenix-mmi.ui-screen-schema/v1"

ENTRY_KINDS = ("ACTION", "NAVIGATION")
DATA_SOURCES = ("STATIC_ORIGINAL", "SYNTHETIC")
SCREEN_ROLES = ("ROOT", "SECTION")

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]*$")
_TOKEN = re.compile(r"^phoenix\.[a-z][a-z0-9.-]*$")


@dataclass(frozen=True)
class UIEntry:
    entry_id: str
    order: int
    kind: str
    label_token: str
    focusable: bool
    target_screen_id: str | None
    data_source: str
    service_binding: str


@dataclass(frozen=True)
class ScreenDefinition:
    screen_id: str
    role: str
    title_token: str
    parent_screen_id: str | None
    entries: tuple[UIEntry, ...]


@dataclass(frozen=True)
class InformationArchitecture:
    schema: str
    model_version: str
    root_screen_id: str
    screens: tuple[ScreenDefinition, ...]


def _entry(
    screen_id: str,
    name: str,
    order: int,
    *,
    kind: str,
    target: str | None = None,
    data_source: str,
) -> UIEntry:
    return UIEntry(
        entry_id=f"{screen_id}.{name}",
        order=order,
        kind=kind,
        label_token=f"phoenix.entry.{screen_id}.{name}",
        focusable=True,
        target_screen_id=target,
        data_source=data_source,
        service_binding="NONE",
    )


def build_phoenix_information_architecture() -> InformationArchitecture:
    """Build the independent five-screen Session 094 information model."""

    screens = (
        ScreenDefinition(
            screen_id="home",
            role="ROOT",
            title_token="phoenix.screen.home",
            parent_screen_id=None,
            entries=(
                _entry(
                    "home",
                    "communication",
                    0,
                    kind="NAVIGATION",
                    target="communication",
                    data_source="STATIC_ORIGINAL",
                ),
                _entry(
                    "home",
                    "media",
                    1,
                    kind="NAVIGATION",
                    target="media",
                    data_source="STATIC_ORIGINAL",
                ),
                _entry(
                    "home",
                    "navigation",
                    2,
                    kind="NAVIGATION",
                    target="navigation",
                    data_source="STATIC_ORIGINAL",
                ),
                _entry(
                    "home",
                    "settings",
                    3,
                    kind="NAVIGATION",
                    target="settings",
                    data_source="STATIC_ORIGINAL",
                ),
            ),
        ),
        ScreenDefinition(
            screen_id="communication",
            role="SECTION",
            title_token="phoenix.screen.communication",
            parent_screen_id="home",
            entries=(
                _entry(
                    "communication",
                    "contacts",
                    0,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "communication",
                    "devices",
                    1,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "communication",
                    "recent",
                    2,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
            ),
        ),
        ScreenDefinition(
            screen_id="media",
            role="SECTION",
            title_token="phoenix.screen.media",
            parent_screen_id="home",
            entries=(
                _entry(
                    "media",
                    "library",
                    0,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "media",
                    "now-playing",
                    1,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "media",
                    "sources",
                    2,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
            ),
        ),
        ScreenDefinition(
            screen_id="navigation",
            role="SECTION",
            title_token="phoenix.screen.navigation",
            parent_screen_id="home",
            entries=(
                _entry(
                    "navigation",
                    "destination",
                    0,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "navigation",
                    "route-overview",
                    1,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "navigation",
                    "saved",
                    2,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
            ),
        ),
        ScreenDefinition(
            screen_id="settings",
            role="SECTION",
            title_token="phoenix.screen.settings",
            parent_screen_id="home",
            entries=(
                _entry(
                    "settings",
                    "display",
                    0,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "settings",
                    "sound",
                    1,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
                _entry(
                    "settings",
                    "system",
                    2,
                    kind="ACTION",
                    data_source="SYNTHETIC",
                ),
            ),
        ),
    )
    model = InformationArchitecture(
        schema=UI_SCREEN_SCHEMA,
        model_version="m5-session094-v1",
        root_screen_id="home",
        screens=screens,
    )
    validate_information_architecture(model)
    return model


def validate_information_architecture(model: InformationArchitecture) -> None:
    """Fail closed on ambiguous topology, external data or service bindings."""

    if model.schema != UI_SCREEN_SCHEMA:
        raise ValueError("unsupported UI screen schema")
    if not model.screens:
        raise ValueError("UI model has no screens")
    screen_ids = [screen.screen_id for screen in model.screens]
    if len(screen_ids) != len(set(screen_ids)):
        raise ValueError("duplicate screen identifier")
    if screen_ids[0] != model.root_screen_id:
        raise ValueError("root screen must be first")
    if screen_ids[1:] != sorted(screen_ids[1:]):
        raise ValueError("section screens must have deterministic order")
    if any(not _IDENTIFIER.fullmatch(screen_id) for screen_id in screen_ids):
        raise ValueError("invalid screen identifier")

    by_id = {screen.screen_id: screen for screen in model.screens}
    root = by_id.get(model.root_screen_id)
    if root is None or root.role != "ROOT" or root.parent_screen_id is not None:
        raise ValueError("invalid root screen")
    global_entry_ids: set[str] = set()
    navigation_edges: set[tuple[str, str]] = set()

    for screen in model.screens:
        if screen.role not in SCREEN_ROLES:
            raise ValueError("unsupported screen role")
        if not _TOKEN.fullmatch(screen.title_token):
            raise ValueError("invalid screen title token")
        if screen.screen_id != model.root_screen_id:
            if screen.role != "SECTION" or screen.parent_screen_id not in by_id:
                raise ValueError("invalid section parent")
        if not screen.entries or not any(entry.focusable for entry in screen.entries):
            raise ValueError("every screen requires a focusable entry")
        if [entry.order for entry in screen.entries] != list(
            range(len(screen.entries))
        ):
            raise ValueError("entry order must be contiguous")
        for entry in screen.entries:
            if (
                entry.entry_id in global_entry_ids
                or not entry.entry_id.startswith(f"{screen.screen_id}.")
            ):
                raise ValueError("duplicate or foreign entry identifier")
            global_entry_ids.add(entry.entry_id)
            if entry.kind not in ENTRY_KINDS:
                raise ValueError("unsupported entry kind")
            if not _TOKEN.fullmatch(entry.label_token):
                raise ValueError("invalid entry label token")
            if entry.data_source not in DATA_SOURCES:
                raise ValueError("unsupported UI data source")
            if entry.service_binding != "NONE":
                raise ValueError("Session 094 forbids service bindings")
            if entry.kind == "NAVIGATION":
                if entry.target_screen_id not in by_id:
                    raise ValueError("navigation target does not exist")
                target = by_id[entry.target_screen_id]
                if target.parent_screen_id != screen.screen_id:
                    raise ValueError("navigation edge contradicts hierarchy")
                navigation_edges.add((screen.screen_id, entry.target_screen_id))
            elif entry.target_screen_id is not None:
                raise ValueError("action entry cannot declare a screen target")

    for screen in model.screens[1:]:
        if (screen.parent_screen_id, screen.screen_id) not in navigation_edges:
            raise ValueError("section screen is not reachable from its parent")
        seen = {screen.screen_id}
        parent_id = screen.parent_screen_id
        while parent_id is not None:
            if parent_id in seen:
                raise ValueError("screen hierarchy contains a cycle")
            seen.add(parent_id)
            parent_id = by_id[parent_id].parent_screen_id
        if model.root_screen_id not in seen:
            raise ValueError("section screen is not rooted")


def build_public_information_architecture(
    model: InformationArchitecture | None = None,
) -> dict[str, object]:
    """Return the complete, independently authored publication-safe model."""

    current = model or build_phoenix_information_architecture()
    validate_information_architecture(current)
    contract = build_ui_constraint_contract()
    screens = [asdict(screen) for screen in current.screens]
    entry_count = sum(len(screen.entries) for screen in current.screens)
    focusable_count = sum(
        int(entry.focusable)
        for screen in current.screens
        for entry in screen.entries
    )
    navigation_edges = sorted(
        (
            screen.screen_id,
            entry.target_screen_id,
        )
        for screen in current.screens
        for entry in screen.entries
        if entry.kind == "NAVIGATION"
    )
    return {
        "schema": current.schema,
        "model_version": current.model_version,
        "viewport": {
            "width": contract["viewport"]["width"],
            "height": contract["viewport"]["height"],
        },
        "root_screen_id": current.root_screen_id,
        "screens": screens,
        "topology": {
            "screen_count": len(current.screens),
            "entry_count": entry_count,
            "focusable_entry_count": focusable_count,
            "navigation_edge_count": len(navigation_edges),
            "navigation_edges": navigation_edges,
            "all_screens_reachable": True,
            "hierarchy_acyclic": True,
        },
        "classification": {
            "information_architecture": "ORIGINAL_PHOENIX_PROTOTYPE",
            "firmware_menu_reconstruction": False,
            "layout_geometry_assigned": False,
            "interaction_reducer_implemented": False,
            "service_binding_established": False,
            "navigation_engine_connected": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "raw_firmware_strings_included": False,
            "navigation_media_content_included": False,
            "vehicle_identifiers_included": False,
            "service_bindings_included": False,
            "original_or_synthetic_content_only": True,
        },
    }

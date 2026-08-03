"""Deterministic action playback and host-preview fingerprints."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ui_constraints import ABSTRACT_INPUT_ACTIONS
from .ui_model import (
    InformationArchitecture,
    build_phoenix_information_architecture,
    validate_information_architecture,
)
from .ui_reducer import (
    UIState,
    initial_ui_state,
    reduce_ui_state,
    validate_ui_state,
)
from .ui_renderer import render_screen_svg


UI_PLAYBACK_SCHEMA = "phoenix-mmi.ui-playback/v1"

DEFAULT_PLAYBACK_ACTIONS = (
    "ACTIVATE",
    "FOCUS_NEXT",
    "ACTIVATE",
    "BACK",
    "FOCUS_NEXT",
    "ACTIVATE",
    "FOCUS_NEXT",
    "ACTIVATE",
    "BACK",
    "FOCUS_NEXT",
    "ACTIVATE",
    "FOCUS_NEXT",
    "ACTIVATE",
    "BACK",
    "FOCUS_NEXT",
    "ACTIVATE",
    "FOCUS_NEXT",
    "ACTIVATE",
    "HOME",
)


@dataclass(frozen=True)
class PlaybackStep:
    sequence: int
    action: str
    before: UIState
    after: UIState
    preview_sha256: str
    preview_draw_commands: int


def run_ui_playback(
    actions: tuple[str, ...] | list[str] = DEFAULT_PLAYBACK_ACTIONS,
    *,
    model: InformationArchitecture | None = None,
) -> dict[str, object]:
    current = model or build_phoenix_information_architecture()
    validate_information_architecture(current)
    if any(action not in ABSTRACT_INPUT_ACTIONS for action in actions):
        raise ValueError("playback contains an unsupported action")
    state = initial_ui_state(current)
    steps = []
    visited_screens = {state.screen_id}
    visited_focus = {state.focused_entry_id}
    for sequence, action in enumerate(actions, start=1):
        before = state
        state = reduce_ui_state(current, state, action)
        validate_ui_state(current, state)
        preview = render_screen_svg(current, state)
        step = PlaybackStep(
            sequence=sequence,
            action=action,
            before=before,
            after=state,
            preview_sha256=sha256(
                preview.svg.encode("utf-8")
            ).hexdigest(),
            preview_draw_commands=preview.draw_command_count,
        )
        steps.append(step)
        visited_screens.add(state.screen_id)
        visited_focus.add(state.focused_entry_id)
    serialized_steps = [asdict(step) for step in steps]
    fingerprint = sha256(
        json.dumps(
            serialized_steps,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema": UI_PLAYBACK_SCHEMA,
        "playback_version": "m5-session099-v1",
        "actions": list(actions),
        "initial_state": asdict(initial_ui_state(current)),
        "steps": serialized_steps,
        "final_state": asdict(state),
        "metrics": {
            "action_count": len(actions),
            "snapshot_count": len(steps),
            "visited_screen_count": len(visited_screens),
            "visited_focus_count": len(visited_focus),
            "all_model_screens_visited": (
                visited_screens
                == {screen.screen_id for screen in current.screens}
            ),
            "sequence_monotonic": (
                [step.sequence for step in steps]
                == list(range(1, len(steps) + 1))
            ),
            "playback_fingerprint": fingerprint,
        },
        "classification": {
            "playback": "PURE_DETERMINISTIC",
            "snapshot_kind": "HOST_SVG_SHA256",
            "service_dispatch": False,
            "filesystem_required": False,
            "network_required": False,
            "vehicle_required": False,
            "hardware_timing_claim": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "navigation_media_content_included": False,
            "vehicle_messages_included": False,
            "service_bindings_included": False,
            "original_or_synthetic_content_only": True,
        },
    }

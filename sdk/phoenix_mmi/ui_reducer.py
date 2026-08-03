"""Pure focus and navigation reducer for the synthetic Phoenix UI model."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .ui_constraints import ABSTRACT_INPUT_ACTIONS
from .ui_model import (
    InformationArchitecture,
    ScreenDefinition,
    UIEntry,
    build_phoenix_information_architecture,
    validate_information_architecture,
)


UI_REDUCER_SCHEMA = "phoenix-mmi.ui-reducer/v1"


@dataclass(frozen=True)
class UIState:
    screen_id: str
    focused_entry_id: str
    activation_entry_id: str | None = None


def _screens(model: InformationArchitecture) -> dict[str, ScreenDefinition]:
    return {screen.screen_id: screen for screen in model.screens}


def _focusable(screen: ScreenDefinition) -> tuple[UIEntry, ...]:
    return tuple(entry for entry in screen.entries if entry.focusable)


def initial_ui_state(
    model: InformationArchitecture | None = None,
) -> UIState:
    current = model or build_phoenix_information_architecture()
    validate_information_architecture(current)
    screen = _screens(current)[current.root_screen_id]
    return UIState(
        screen_id=screen.screen_id,
        focused_entry_id=_focusable(screen)[0].entry_id,
    )


def validate_ui_state(
    model: InformationArchitecture,
    state: UIState,
) -> None:
    validate_information_architecture(model)
    screens = _screens(model)
    if state.screen_id not in screens:
        raise ValueError("UI state references an unknown screen")
    screen = screens[state.screen_id]
    entries = {entry.entry_id: entry for entry in screen.entries}
    focused = entries.get(state.focused_entry_id)
    if focused is None or not focused.focusable:
        raise ValueError("UI state has no valid focused entry")
    if state.activation_entry_id is not None:
        all_entries = {
            entry.entry_id
            for candidate in model.screens
            for entry in candidate.entries
        }
        if state.activation_entry_id not in all_entries:
            raise ValueError("UI state has an unknown activation signal")


def _focus_parent_entry(
    parent: ScreenDefinition,
    child_screen_id: str,
) -> str:
    candidates = [
        entry.entry_id
        for entry in parent.entries
        if entry.kind == "NAVIGATION"
        and entry.target_screen_id == child_screen_id
        and entry.focusable
    ]
    if len(candidates) != 1:
        raise ValueError("parent navigation entry is not unique")
    return candidates[0]


def reduce_ui_state(
    model: InformationArchitecture,
    state: UIState,
    action: str,
) -> UIState:
    """Apply one abstract action without I/O, services or external state."""

    validate_ui_state(model, state)
    if action not in ABSTRACT_INPUT_ACTIONS:
        raise ValueError("unsupported abstract UI action")
    screens = _screens(model)
    screen = screens[state.screen_id]
    focusable = _focusable(screen)
    focus_index = next(
        index
        for index, entry in enumerate(focusable)
        if entry.entry_id == state.focused_entry_id
    )

    if action == "FOCUS_NEXT":
        target = focusable[(focus_index + 1) % len(focusable)]
        result = UIState(screen.screen_id, target.entry_id)
    elif action == "FOCUS_PREVIOUS":
        target = focusable[(focus_index - 1) % len(focusable)]
        result = UIState(screen.screen_id, target.entry_id)
    elif action == "HOME":
        result = initial_ui_state(model)
    elif action == "BACK":
        if screen.parent_screen_id is None:
            result = UIState(screen.screen_id, state.focused_entry_id)
        else:
            parent = screens[screen.parent_screen_id]
            result = UIState(
                parent.screen_id,
                _focus_parent_entry(parent, screen.screen_id),
            )
    else:
        entry = focusable[focus_index]
        if entry.kind == "NAVIGATION":
            target_screen = screens[entry.target_screen_id]
            result = UIState(
                target_screen.screen_id,
                _focusable(target_screen)[0].entry_id,
                entry.entry_id,
            )
        else:
            result = UIState(
                screen.screen_id,
                entry.entry_id,
                entry.entry_id,
            )
    validate_ui_state(model, result)
    return result


def play_ui_actions(
    actions: tuple[str, ...] | list[str],
    *,
    model: InformationArchitecture | None = None,
    start: UIState | None = None,
) -> tuple[UIState, ...]:
    """Return the initial state followed by every deterministic transition."""

    current_model = model or build_phoenix_information_architecture()
    state = start or initial_ui_state(current_model)
    validate_ui_state(current_model, state)
    states = [state]
    for action in actions:
        state = reduce_ui_state(current_model, state, action)
        states.append(state)
    return tuple(states)


def build_reducer_contract(
    model: InformationArchitecture | None = None,
) -> dict[str, object]:
    """Summarize the complete finite focus-state transition matrix."""

    current = model or build_phoenix_information_architecture()
    validate_information_architecture(current)
    base_states = [
        UIState(screen.screen_id, entry.entry_id)
        for screen in current.screens
        for entry in screen.entries
        if entry.focusable
    ]
    transitions = []
    for state in base_states:
        for action in ABSTRACT_INPUT_ACTIONS:
            result = reduce_ui_state(current, state, action)
            transitions.append(
                {
                    "source": f"{state.screen_id}:{state.focused_entry_id}",
                    "action": action,
                    "target": (
                        f"{result.screen_id}:{result.focused_entry_id}"
                    ),
                    "screen_changed": result.screen_id != state.screen_id,
                    "activation_signalled": (
                        result.activation_entry_id is not None
                    ),
                }
            )
    action_counts = {
        action: sum(int(row["action"] == action) for row in transitions)
        for action in ABSTRACT_INPUT_ACTIONS
    }
    return {
        "schema": UI_REDUCER_SCHEMA,
        "contract_version": "m5-session095-v1",
        "abstract_actions": list(ABSTRACT_INPUT_ACTIONS),
        "state_space": {
            "base_focus_state_count": len(base_states),
            "transition_count": len(transitions),
            "action_transition_counts": action_counts,
            "screen_change_count": sum(
                int(row["screen_changed"]) for row in transitions
            ),
            "activation_signal_count": sum(
                int(row["activation_signalled"]) for row in transitions
            ),
        },
        "transition_fingerprint_input": transitions,
        "classification": {
            "transition_function": "PURE_DETERMINISTIC",
            "focus_wrap": "CYCLIC_WITHIN_SCREEN",
            "back_behavior": "DECLARED_PARENT",
            "home_behavior": "ROOT_FIRST_ENTRY",
            "action_side_effects": "NONE",
            "hardware_input_mapping": "NOT_ESTABLISHED",
            "service_dispatch": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "vehicle_messages_included": False,
            "service_bindings_included": False,
            "original_or_synthetic_content_only": True,
        },
    }

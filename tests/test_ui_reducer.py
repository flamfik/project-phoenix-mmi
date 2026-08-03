from dataclasses import replace
import unittest

from phoenix_mmi.ui_model import build_phoenix_information_architecture
from phoenix_mmi.ui_reducer import (
    UIState,
    build_reducer_contract,
    initial_ui_state,
    play_ui_actions,
    reduce_ui_state,
    validate_ui_state,
)


class UIReducerTests(unittest.TestCase):
    def setUp(self):
        self.model = build_phoenix_information_architecture()

    def test_initial_state_is_first_home_entry(self):
        state = initial_ui_state(self.model)
        self.assertEqual(state.screen_id, "home")
        self.assertEqual(state.focused_entry_id, "home.communication")
        self.assertIsNone(state.activation_entry_id)

    def test_focus_next_and_previous_wrap(self):
        state = initial_ui_state(self.model)
        previous = reduce_ui_state(self.model, state, "FOCUS_PREVIOUS")
        self.assertEqual(previous.focused_entry_id, "home.settings")
        wrapped = reduce_ui_state(self.model, previous, "FOCUS_NEXT")
        self.assertEqual(wrapped, state)

    def test_activate_navigation_enters_section(self):
        state = reduce_ui_state(
            self.model, initial_ui_state(self.model), "ACTIVATE"
        )
        self.assertEqual(state.screen_id, "communication")
        self.assertEqual(state.focused_entry_id, "communication.contacts")
        self.assertEqual(state.activation_entry_id, "home.communication")

    def test_activate_action_only_emits_local_signal(self):
        section = reduce_ui_state(
            self.model, initial_ui_state(self.model), "ACTIVATE"
        )
        result = reduce_ui_state(self.model, section, "ACTIVATE")
        self.assertEqual(result.screen_id, "communication")
        self.assertEqual(result.focused_entry_id, "communication.contacts")
        self.assertEqual(
            result.activation_entry_id, "communication.contacts"
        )

    def test_back_restores_parent_entry(self):
        section = reduce_ui_state(
            self.model, initial_ui_state(self.model), "ACTIVATE"
        )
        result = reduce_ui_state(self.model, section, "BACK")
        self.assertEqual(result.screen_id, "home")
        self.assertEqual(result.focused_entry_id, "home.communication")

    def test_back_at_root_is_noop_and_clears_signal(self):
        state = replace(
            initial_ui_state(self.model),
            activation_entry_id="home.communication",
        )
        result = reduce_ui_state(self.model, state, "BACK")
        self.assertEqual(result, initial_ui_state(self.model))

    def test_home_returns_root_from_every_section(self):
        state = reduce_ui_state(
            self.model, initial_ui_state(self.model), "ACTIVATE"
        )
        result = reduce_ui_state(self.model, state, "HOME")
        self.assertEqual(result, initial_ui_state(self.model))

    def test_playback_is_repeatable(self):
        actions = (
            "FOCUS_NEXT",
            "ACTIVATE",
            "FOCUS_NEXT",
            "ACTIVATE",
            "BACK",
            "HOME",
        )
        self.assertEqual(
            play_ui_actions(actions, model=self.model),
            play_ui_actions(actions, model=self.model),
        )

    def test_reducer_rejects_unknown_action(self):
        with self.assertRaises(ValueError):
            reduce_ui_state(
                self.model, initial_ui_state(self.model), "VEHICLE_WRITE"
            )

    def test_state_validator_rejects_unknown_focus(self):
        with self.assertRaises(ValueError):
            validate_ui_state(
                self.model, UIState("home", "home.missing")
            )

    def test_contract_covers_all_actions_and_focus_states(self):
        contract = build_reducer_contract(self.model)
        self.assertEqual(
            contract["state_space"]["base_focus_state_count"], 16
        )
        self.assertEqual(contract["state_space"]["transition_count"], 80)
        self.assertEqual(
            set(contract["state_space"]["action_transition_counts"].values()),
            {16},
        )
        self.assertFalse(contract["classification"]["service_dispatch"])

    def test_contract_is_deterministic(self):
        self.assertEqual(
            build_reducer_contract(self.model),
            build_reducer_contract(self.model),
        )


if __name__ == "__main__":
    unittest.main()

# SPEC-104 - UI focus and navigation reducer

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 095
- Related questions: RQ-371-RQ-374

`UIState` contains the current screen, focused entry and optional activation
signal. `reduce_ui_state` is a pure function over five abstract actions.
Sixteen base states multiplied by five actions form an exhaustive matrix of
80 deterministic transitions.

Focus wraps within a screen. Activation follows declared navigation edges or
emits a host signal. Back restores the parent entry and home selects the root
screen. No transition may dispatch a service or perform I/O. Abstract actions
must not be interpreted as recovered hardware mappings.

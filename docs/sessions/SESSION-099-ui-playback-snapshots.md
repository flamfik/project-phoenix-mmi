# Session 099 - Deterministic input playback and snapshots

- Date: 2026-07-29
- Objective: exercise the reducer and renderer as one offline workflow.
- Status: COMPLETE; M5-X6 PASS; M5 6/8; operational graph v91.

A fixed sequence of 19 abstract actions produces 19 ordered SVG-state hashes.
The playback visits all five model screens and 12 focus positions, ends in a
defined state and has a stable SHA-256 fingerprint. A second run is exactly
equal.

The snapshots exercise host logic only. They do not reproduce hardware timing,
physical button codes, firmware scheduling, service dispatch or vehicle state.

Authoritative report:
`research/milestones/m5/session099/input-playback-snapshots.json`.

"""Pure synthetic rehearsal of the M7 bench control sequence."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json


BENCH_STATE_SCHEMA = "phoenix-mmi.bench-state-machine/v1"
INITIAL_STATE = "DRAFT"
TERMINAL_STATES = {"EVIDENCE_SEALED", "ABORT_LOCKED"}

TRANSITIONS = {
    ("DRAFT", "VERIFY_IDENTITY"): "IDENTITY_VERIFIED",
    ("IDENTITY_VERIFIED", "VERIFY_ELECTRICAL"): "ELECTRICAL_VERIFIED",
    ("ELECTRICAL_VERIFIED", "VERIFY_RECOVERY"): "RECOVERY_VERIFIED",
    ("RECOVERY_VERIFIED", "APPROVE_RISK"): "RISK_APPROVED",
    ("RISK_APPROVED", "ARM_CAPTURE"): "CAPTURE_ARMED",
    ("CAPTURE_ARMED", "AUTHORIZE_POWER"): "POWER_AUTHORIZED",
    ("POWER_AUTHORIZED", "BEGIN_OBSERVATION"): "OBSERVING",
    ("OBSERVING", "NORMAL_SHUTDOWN"): "SAFE_SHUTDOWN",
    ("SAFE_SHUTDOWN", "SEAL_EVIDENCE"): "EVIDENCE_SEALED",
}

ABORTABLE_STATES = {
    "IDENTITY_VERIFIED",
    "ELECTRICAL_VERIFIED",
    "RECOVERY_VERIFIED",
    "RISK_APPROVED",
    "CAPTURE_ARMED",
    "POWER_AUTHORIZED",
    "OBSERVING",
    "SAFE_SHUTDOWN",
}


@dataclass(frozen=True)
class BenchState:
    state: str = INITIAL_STATE
    sequence: int = 0
    power_candidate: bool = False
    evidence_sealed: bool = False
    aborted: bool = False


def transition_bench_state(state: BenchState, event: str) -> BenchState:
    """Advance a pure model; no hardware or external I/O is performed."""

    validate_bench_state(state)
    if state.state in TERMINAL_STATES:
        raise ValueError("terminal bench state cannot transition")
    if event == "ABORT":
        if state.state not in ABORTABLE_STATES:
            raise ValueError("abort is not valid in current bench state")
        return BenchState(
            state="ABORT_LOCKED",
            sequence=state.sequence + 1,
            power_candidate=False,
            evidence_sealed=True,
            aborted=True,
        )
    target = TRANSITIONS.get((state.state, event))
    if target is None:
        raise ValueError("invalid bench state transition")
    result = BenchState(
        state=target,
        sequence=state.sequence + 1,
        power_candidate=target in {"POWER_AUTHORIZED", "OBSERVING"},
        evidence_sealed=target == "EVIDENCE_SEALED",
        aborted=False,
    )
    validate_bench_state(result)
    return result


def validate_bench_state(state: BenchState) -> None:
    """Validate state invariants that prevent implied physical execution."""

    known = (
        {INITIAL_STATE}
        | {source for source, _event in TRANSITIONS}
        | set(TRANSITIONS.values())
        | {"ABORT_LOCKED"}
    )
    if state.state not in known or state.sequence < 0:
        raise ValueError("invalid bench state")
    if state.power_candidate != (
        state.state in {"POWER_AUTHORIZED", "OBSERVING"}
    ):
        raise ValueError("bench power-candidate invariant differs")
    if state.evidence_sealed != (
        state.state in {"EVIDENCE_SEALED", "ABORT_LOCKED"}
    ):
        raise ValueError("bench evidence-seal invariant differs")
    if state.aborted != (state.state == "ABORT_LOCKED"):
        raise ValueError("bench abort invariant differs")


def run_synthetic_bench_rehearsal() -> dict[str, object]:
    """Exercise normal and emergency paths using state objects only."""

    normal_events = [
        "VERIFY_IDENTITY",
        "VERIFY_ELECTRICAL",
        "VERIFY_RECOVERY",
        "APPROVE_RISK",
        "ARM_CAPTURE",
        "AUTHORIZE_POWER",
        "BEGIN_OBSERVATION",
        "NORMAL_SHUTDOWN",
        "SEAL_EVIDENCE",
    ]
    normal = BenchState()
    normal_states = [normal.state]
    for event in normal_events:
        normal = transition_bench_state(normal, event)
        normal_states.append(normal.state)

    abort = BenchState()
    abort_events = [
        "VERIFY_IDENTITY",
        "VERIFY_ELECTRICAL",
        "VERIFY_RECOVERY",
        "APPROVE_RISK",
        "ARM_CAPTURE",
        "AUTHORIZE_POWER",
        "BEGIN_OBSERVATION",
        "ABORT",
    ]
    abort_states = [abort.state]
    for event in abort_events:
        abort = transition_bench_state(abort, event)
        abort_states.append(abort.state)

    fingerprint = sha256(
        json.dumps(
            {
                "normal_events": normal_events,
                "normal_states": normal_states,
                "abort_events": abort_events,
                "abort_states": abort_states,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema": BENCH_STATE_SCHEMA,
        "rehearsal_version": "m7-session117-v1",
        "normal_path": {
            "event_count": len(normal_events),
            "terminal_state": normal.state,
            "evidence_sealed": normal.evidence_sealed,
        },
        "abort_path": {
            "event_count": len(abort_events),
            "terminal_state": abort.state,
            "evidence_sealed": abort.evidence_sealed,
            "power_candidate_after_abort": abort.power_candidate,
        },
        "rehearsal_fingerprint": fingerprint,
        "passed": bool(
            normal.state == "EVIDENCE_SEALED"
            and abort.state == "ABORT_LOCKED"
            and abort.evidence_sealed
            and not abort.power_candidate
        ),
        "classification": {
            "synthetic_state_rehearsal": "PASS",
            "hardware_controller": False,
            "hardware_powered": False,
            "physical_validation_performed": False,
        },
        "publication_safety": {
            "hardware_identifiers_included": False,
            "raw_measurements_included": False,
            "hardware_powered": False,
            "target_firmware_execution_performed": False,
        },
    }

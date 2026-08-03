"""M7 capability registry, preparation gates and progress transitions."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
import importlib
from pathlib import Path

from .hardware_validation_contract import (
    build_hardware_validation_contract,
    validate_hardware_validation_contract,
)


M7_PROGRESS_SCHEMA = "phoenix-mmi.m7-hardware-validation-progress/v1"


@dataclass(frozen=True)
class HardwareValidationCapability:
    capability_id: str
    workstream: str
    name: str
    status: str
    probe_kind: str
    probe_target: str | None
    evidence: str
    limitation: str
    target_session: str | None


M7_CAPABILITIES = (
    HardwareValidationCapability(
        "M7-CAP-001",
        "contract",
        "fail-closed M7 safety and evidence contract",
        "IMPLEMENTED",
        "python-symbol",
        (
            "phoenix_mmi.hardware_validation_contract:"
            "build_hardware_validation_contract"
        ),
        "Session 111",
        "contract authorizes preparation only",
        None,
    ),
    HardwareValidationCapability(
        "M7-CAP-002",
        "identity",
        "private bench manifest and public identity summary",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no identity template or isolation manifest",
        "112",
    ),
    HardwareValidationCapability(
        "M7-CAP-003",
        "electrical",
        "authoritative-reference electrical safety plan",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no fail-closed power and isolation plan",
        "113",
    ),
    HardwareValidationCapability(
        "M7-CAP-004",
        "recovery",
        "abort and non-writing recovery plan",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no recovery rehearsal contract",
        "114",
    ),
    HardwareValidationCapability(
        "M7-CAP-005",
        "observation",
        "read-only observation and aggregate capture contract",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no passive observation allowlist",
        "115",
    ),
    HardwareValidationCapability(
        "M7-CAP-006",
        "risk",
        "hazard register and signed approval schema",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no machine-checkable risk review",
        "116",
    ),
    HardwareValidationCapability(
        "M7-CAP-007",
        "rehearsal",
        "pure normal and emergency state-machine rehearsal",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no deterministic bench sequence rehearsal",
        "117",
    ),
    HardwareValidationCapability(
        "M7-CAP-008",
        "evidence",
        "private evidence intake and public summary validator",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no fail-closed physical evidence gate",
        "118",
    ),
    HardwareValidationCapability(
        "M7-CAP-009",
        "integration",
        "deterministic M7 preparation integration",
        "MISSING",
        "none",
        None,
        "M7 requirement",
        "no complete preparation-package verdict",
        "119",
    ),
    HardwareValidationCapability(
        "M7-CAP-010",
        "physical",
        "real isolated read-only bench evidence",
        "BLOCKED",
        "external-evidence",
        None,
        "M7 physical gate",
        "requires private hardware evidence and signed approval",
        "120",
    ),
)


M7_EXIT_CRITERIA = (
    {
        "criterion_id": "M7-X1",
        "target_session": "112",
        "description": "private identity manifest and safe public summary",
        "capability_id": "M7-CAP-002",
    },
    {
        "criterion_id": "M7-X2",
        "target_session": "113",
        "description": "power and isolation plan without guessed limits",
        "capability_id": "M7-CAP-003",
    },
    {
        "criterion_id": "M7-X3",
        "target_session": "114",
        "description": "abort and recovery plan rehearsable without hardware",
        "capability_id": "M7-CAP-004",
    },
    {
        "criterion_id": "M7-X4",
        "target_session": "115",
        "description": "passive observation and aggregate capture contract",
        "capability_id": "M7-CAP-005",
    },
    {
        "criterion_id": "M7-X5",
        "target_session": "116",
        "description": "complete risk register and unsigned approval gate",
        "capability_id": "M7-CAP-006",
    },
    {
        "criterion_id": "M7-X6",
        "target_session": "117",
        "description": "deterministic normal and abort rehearsal",
        "capability_id": "M7-CAP-007",
    },
    {
        "criterion_id": "M7-X7",
        "target_session": "118",
        "description": "private evidence intake rejects incomplete claims",
        "capability_id": "M7-CAP-008",
    },
    {
        "criterion_id": "M7-X8",
        "target_session": "119",
        "description": "deterministic preparation integration",
        "capability_id": "M7-CAP-009",
    },
    {
        "criterion_id": "M7-X9",
        "target_session": "120",
        "description": "accepted real isolated bench evidence",
        "capability_id": "M7-CAP-010",
    },
)


def build_m7_baseline(
    repository_root: str | Path,
    m6_closure: dict[str, object],
) -> dict[str, object]:
    """Build the deterministic Session 111 baseline from M6 closure."""

    repository = Path(repository_root)
    if (
        m6_closure.get("classification", {}).get("m6_status") != "COMPLETE"
        or m6_closure.get("exit_criteria_passed") != 8
        or m6_closure.get("milestone_transition", {}).get("m7") != "READY"
    ):
        raise ValueError("M7 entry gate requires complete M6 closure")
    contract = build_hardware_validation_contract()
    capabilities = [asdict(row) for row in M7_CAPABILITIES]
    _probe_capabilities(repository, capabilities)
    report: dict[str, object] = {
        "schema": M7_PROGRESS_SCHEMA,
        "session": "111",
        "analysis_mode": "OFFLINE_PREPARATION_ONLY",
        "operational_graph_version": "v103",
        "operational_graph_delta": {
            "node_id": "m7-hardware-validation-baseline",
            "change": "ADD",
        },
        "m7_contract": contract,
        "entry_gate": {
            "m6_complete": True,
            "m6_exit_criteria": "8/8",
            "m7_ready": True,
            "physical_observation_authorized": False,
        },
        "capabilities": capabilities,
        "applied_transition_count": 0,
        "exit_criteria": _criteria(capabilities),
        "ordered_session_backlog": [str(value) for value in range(112, 121)],
        "classification": {},
        "milestone_transition": {},
        "publication_safety": contract["publication_safety"],
    }
    _finalize(report)
    return report


def advance_m7_progress(
    repository_root: str | Path,
    previous: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph_version: str,
    graph_node_id: str,
) -> dict[str, object]:
    """Apply explicit MISSING-to-IMPLEMENTED preparation transitions."""

    expected = int(previous["session"]) + 1
    if int(session) != expected:
        raise ValueError("M7 sessions must advance sequentially")
    report = deepcopy(previous)
    report["previous_state"] = {
        "session": previous["session"],
        "operational_graph_version": previous["operational_graph_version"],
        "preparation_criteria_passed": previous["classification"][
            "preparation_criteria_passed"
        ],
    }
    report["session"] = session
    report["operational_graph_version"] = graph_version
    report["operational_graph_delta"] = {
        "node_id": graph_node_id,
        "change": "ADD",
    }
    by_id = {row["capability_id"]: row for row in report["capabilities"]}
    for transition in transitions:
        row = by_id.get(transition["capability_id"])
        if row is None or row["status"] != transition["from_status"]:
            raise ValueError("invalid M7 capability transition")
        if (
            transition["from_status"] != "MISSING"
            or transition["to_status"] != "IMPLEMENTED"
        ):
            raise ValueError("M7 preparation transitions must implement gaps")
        row.update(
            {
                "status": "IMPLEMENTED",
                "probe_kind": transition["probe_kind"],
                "probe_target": transition["probe_target"],
                "evidence": transition["evidence"],
                "limitation": transition["limitation"],
            }
        )
    _probe_capabilities(Path(repository_root), report["capabilities"])
    report["applied_transition_count"] = (
        previous["applied_transition_count"] + len(transitions)
    )
    report["exit_criteria"] = _criteria(report["capabilities"])
    _finalize(report)
    return report


def _criteria(capabilities: list[dict[str, object]]) -> list[dict[str, object]]:
    by_id = {row["capability_id"]: row for row in capabilities}
    return [
        {
            **criterion,
            "passed": by_id[criterion["capability_id"]]["status"]
            == "IMPLEMENTED",
        }
        for criterion in M7_EXIT_CRITERIA
    ]


def _probe_capabilities(
    repository: Path,
    capabilities: list[dict[str, object]],
) -> None:
    for row in capabilities:
        if row["status"] != "IMPLEMENTED":
            continue
        if row["probe_kind"] == "python-symbol":
            module_name, symbol = str(row["probe_target"]).split(":", 1)
            if not hasattr(importlib.import_module(module_name), symbol):
                raise ValueError(f"missing M7 symbol {row['probe_target']}")
        elif row["probe_kind"] == "repository-file":
            if not (repository / str(row["probe_target"])).is_file():
                raise ValueError(f"missing M7 file {row['probe_target']}")
        else:
            raise ValueError("implemented M7 capability has invalid probe")


def _finalize(report: dict[str, object]) -> None:
    validate_hardware_validation_contract(report["m7_contract"])
    counts = Counter(row["status"] for row in report["capabilities"])
    criteria = report["exit_criteria"]
    preparation = criteria[:8]
    physical = criteria[8]
    prep_passed = sum(int(row["passed"]) for row in preparation)
    total_passed = sum(int(row["passed"]) for row in criteria)
    m7_complete = bool(prep_passed == 8 and physical["passed"])
    report["capability_audit"] = {
        "total": len(report["capabilities"]),
        "status_counts": dict(sorted(counts.items())),
        "implemented_probe_failures": 0,
    }
    report["exit_criteria_passed"] = total_passed
    report["exit_criteria_total"] = len(criteria)
    report["classification"] = {
        "m7_entry": "PASS",
        "m7_status": (
            "COMPLETE"
            if m7_complete
            else (
                "AWAITING_BENCH_EVIDENCE"
                if prep_passed == 8
                else "IN_PROGRESS"
            )
        ),
        "preparation_criteria_passed": prep_passed,
        "preparation_criteria_total": 8,
        "physical_criteria_passed": int(physical["passed"]),
        "physical_criteria_total": 1,
        "physical_bench_validation_performed": bool(physical["passed"]),
        "vehicle_operations_authorized": False,
        "safe_mutation_ready": False,
        "installable_artifact_ready": False,
    }
    report["milestone_transition"] = {
        "m7": report["classification"]["m7_status"],
        "m8": "NOT_READY",
        "next_session": "120" if not physical["passed"] else None,
        "required_external_evidence": (
            "PRIVATE_SIGNED_ISOLATED_BENCH_BUNDLE"
            if not physical["passed"]
            else None
        ),
    }

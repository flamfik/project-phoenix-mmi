"""Milestone M5 capability registry, gates and explicit progress transitions."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
import importlib
from pathlib import Path

from .ui_constraints import (
    build_ui_constraint_contract,
    validate_ui_constraint_contract,
)


M5_PROGRESS_SCHEMA = "phoenix-mmi.m5-ui-prototype-progress/v1"


@dataclass(frozen=True)
class UICapability:
    capability_id: str
    workstream: str
    name: str
    status: str
    probe_kind: str
    probe_target: str | None
    evidence: str
    limitation: str
    target_session: str | None


M5_CAPABILITIES = (
    UICapability(
        "M5-CAP-001",
        "viewport",
        "validated 480x240 resource geometry",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.resource_graphics:geometry_class",
        "Sessions 077-079",
        "display controller, safe area and pixel layout remain unknown",
        None,
    ),
    UICapability(
        "M5-CAP-002",
        "preview",
        "format-explicit offline resource preview",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.resource_graphics:render_ppm",
        "Session 079",
        "candidate pixel layouts are not confirmed",
        None,
    ),
    UICapability(
        "M5-CAP-003",
        "interaction",
        "isolated host event harness",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.runtime_harness:HostRuntimeHarness",
        "Session 090",
        "host events are not MMI runtime or physical-control events",
        None,
    ),
    UICapability(
        "M5-CAP-004",
        "evidence",
        "runtime and resource evidence graph",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.runtime_objects:build_runtime_evidence_graph",
        "Session 091",
        "actual menu, renderer and lifecycle behavior remain unknown",
        None,
    ),
    UICapability(
        "M5-CAP-005",
        "constraints",
        "frozen offline UI constraint contract",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.ui_constraints:build_ui_constraint_contract",
        "Session 093",
        "physical key mapping and hardware budgets remain unknown",
        None,
    ),
    UICapability(
        "M5-CAP-006",
        "integration",
        "firmware renderer integration",
        "BLOCKED",
        "none",
        None,
        "M5 safety boundary",
        "renderer compatibility is not established",
        None,
    ),
    UICapability(
        "M5-CAP-007",
        "mutation",
        "firmware resource replacement",
        "BLOCKED",
        "none",
        None,
        "M5 safety boundary",
        "integrity, lifecycle and recovery requirements are unresolved",
        None,
    ),
    UICapability(
        "M5-CAP-008",
        "vehicle",
        "vehicle and protected-service integration",
        "BLOCKED",
        "none",
        None,
        "M5 safety boundary",
        "vehicle communication is outside the offline prototype",
        None,
    ),
    UICapability(
        "M5-CAP-009",
        "delivery",
        "installable artifact generation",
        "BLOCKED",
        "none",
        None,
        "M5 safety boundary",
        "M5 produces no update media or vehicle-loadable artifacts",
        None,
    ),
    UICapability(
        "M5-CAP-010",
        "architecture",
        "typed information architecture and screen schema",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "no deterministic screen tree or state schema",
        "094",
    ),
    UICapability(
        "M5-CAP-011",
        "interaction",
        "focus and navigation reducer",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "abstract actions do not yet produce UI state transitions",
        "095",
    ),
    UICapability(
        "M5-CAP-012",
        "layout",
        "bounded 480x240 layout engine",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "no deterministic rectangle allocation or overflow gate",
        "096",
    ),
    UICapability(
        "M5-CAP-013",
        "visual",
        "original design tokens and synthetic asset registry",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "no provenance-checked theme or asset model",
        "097",
    ),
    UICapability(
        "M5-CAP-014",
        "preview",
        "offline Phoenix UI renderer",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "no complete screen preview from the typed UI model",
        "098",
    ),
    UICapability(
        "M5-CAP-015",
        "playback",
        "deterministic input playback and snapshots",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "no reproducible interaction trace",
        "099",
    ),
    UICapability(
        "M5-CAP-016",
        "quality",
        "legibility, focus and complexity audit",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "no explicit quality or host-metric gate",
        "100",
    ),
    UICapability(
        "M5-CAP-017",
        "integration",
        "deterministic M5 integration gate",
        "MISSING",
        "none",
        None,
        "M5 requirement",
        "no complete synthetic Phoenix UI workflow",
        "101",
    ),
)


M5_EXIT_CRITERIA = (
    {
        "criterion_id": "M5-X1",
        "name": "typed information architecture and screen schema",
        "required_capabilities": ["M5-CAP-010"],
        "target_session": "094",
    },
    {
        "criterion_id": "M5-X2",
        "name": "deterministic focus and navigation reducer",
        "required_capabilities": ["M5-CAP-011"],
        "target_session": "095",
    },
    {
        "criterion_id": "M5-X3",
        "name": "bounded 480x240 layout engine",
        "required_capabilities": ["M5-CAP-012"],
        "target_session": "096",
    },
    {
        "criterion_id": "M5-X4",
        "name": "original token and synthetic asset registry",
        "required_capabilities": ["M5-CAP-013"],
        "target_session": "097",
    },
    {
        "criterion_id": "M5-X5",
        "name": "offline Phoenix UI preview renderer",
        "required_capabilities": ["M5-CAP-014"],
        "target_session": "098",
    },
    {
        "criterion_id": "M5-X6",
        "name": "deterministic input playback and snapshots",
        "required_capabilities": ["M5-CAP-015"],
        "target_session": "099",
    },
    {
        "criterion_id": "M5-X7",
        "name": "legibility, focus and complexity audit",
        "required_capabilities": ["M5-CAP-016"],
        "target_session": "100",
    },
    {
        "criterion_id": "M5-X8",
        "name": "deterministic sanitized UI integration gate",
        "required_capabilities": ["M5-CAP-017"],
        "target_session": "101",
    },
)


def _probe(row: dict[str, object], root: Path) -> bool:
    kind = row["probe_kind"]
    target = row["probe_target"]
    if kind == "none":
        return False
    if kind == "repository-file":
        return isinstance(target, str) and (root / target).is_file()
    if kind != "python-symbol" or not isinstance(target, str) or ":" not in target:
        return False
    module_name, symbol = target.split(":", 1)
    try:
        module = importlib.import_module(module_name)
    except (ImportError, OSError):
        return False
    return hasattr(module, symbol)


def _refresh(row: dict[str, object], root: Path) -> None:
    observed = _probe(row, root)
    expected = row["status"] in {"IMPLEMENTED", "PARTIAL"}
    row["probe_observed"] = observed
    row["probe_matches_declaration"] = observed == expected


def _summarize(rows: list[dict[str, object]], version: str) -> dict[str, object]:
    return {
        "registry_version": version,
        "capability_count": len(rows),
        "status_counts": dict(
            sorted(Counter(str(row["status"]) for row in rows).items())
        ),
        "capabilities": rows,
        "probe_integrity": all(
            bool(row["probe_matches_declaration"]) for row in rows
        ),
    }


def _criteria(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_id = {row["capability_id"]: row for row in rows}
    return [
        {
            **criterion,
            "passed": all(
                by_id[item]["status"] == "IMPLEMENTED"
                for item in criterion["required_capabilities"]
            ),
        }
        for criterion in M5_EXIT_CRITERIA
    ]


def _validate_m4_closure(m4_closure: dict[str, object]) -> None:
    if m4_closure.get("schema") != "phoenix-mmi.m4-runtime-research-progress/v1":
        raise ValueError("unsupported M4 closure schema")
    classification = m4_closure.get("classification")
    transition = m4_closure.get("milestone_transition")
    if not isinstance(classification, dict) or not isinstance(transition, dict):
        raise ValueError("incomplete M4 closure")
    if (
        classification.get("m4_status") != "COMPLETE"
        or classification.get("m4_exit") != "PASS"
        or transition.get("m5") != "READY"
        or transition.get("m5_authorized_scope")
        != "offline Phoenix UI prototype"
        or classification.get("safe_mutation_ready") is not False
        or classification.get("installable_artifact_ready") is not False
    ):
        raise ValueError("M5 entry gate is not satisfied")


def build_m5_baseline(
    repository_root: str | Path,
    m4_closure: dict[str, object],
) -> dict[str, object]:
    """Build the deterministic Session 093 capability baseline."""

    _validate_m4_closure(m4_closure)
    root = Path(repository_root)
    constraint_contract = build_ui_constraint_contract()
    validate_ui_constraint_contract(constraint_contract)
    rows = [asdict(item) for item in M5_CAPABILITIES]
    for row in rows:
        _refresh(row, root)
    criteria = _criteria(rows)
    audit = _summarize(rows, "m5-session093-v1")
    return {
        "schema": M5_PROGRESS_SCHEMA,
        "analysis_mode": "repository-symbol-capability-and-ux-constraint-audit",
        "session": "093",
        "m4_entry_gate": {
            "m4": "COMPLETE",
            "m5": "READY",
            "authorized_scope": "offline Phoenix UI prototype",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
            "passed": True,
        },
        "ui_constraint_contract": constraint_contract,
        "capability_audit": audit,
        "exit_criteria": criteria,
        "exit_criteria_passed": sum(int(row["passed"]) for row in criteria),
        "exit_criteria_total": len(criteria),
        "ordered_session_backlog": [
            {
                "session": row["target_session"],
                "criterion_id": row["criterion_id"],
                "objective": row["name"],
            }
            for row in criteria
        ],
        "classification": {
            "m5_entry": "PASS",
            "m5_status": "IN_PROGRESS",
            "m5_exit": "OPEN",
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
            "prototype_scope": "OFFLINE_ONLY",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph_version": "v85",
        "publication_safety": _publication_safety(),
    }


def advance_m5_progress(
    repository_root: str | Path,
    previous: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph_version: str,
    graph_node_id: str,
) -> dict[str, object]:
    """Apply explicit future M5 transitions without implicit promotion."""

    if previous.get("schema") != M5_PROGRESS_SCHEMA:
        raise ValueError("unsupported previous M5 progress schema")
    previous_session = str(previous.get("session", ""))
    if not (
        session.isdigit()
        and previous_session.isdigit()
        and int(session) > int(previous_session)
    ):
        raise ValueError("M5 session must advance monotonically")
    rows = deepcopy(previous["capability_audit"]["capabilities"])
    by_id = {str(row["capability_id"]): row for row in rows}
    required = {
        "capability_id",
        "from_status",
        "to_status",
        "probe_kind",
        "probe_target",
        "evidence",
        "limitation",
    }
    seen: set[str] = set()
    for transition in transitions:
        if set(transition) != required:
            raise ValueError("M5 transition fields differ")
        capability_id = transition["capability_id"]
        if capability_id in seen or capability_id not in by_id:
            raise ValueError("duplicate or unknown M5 transition")
        seen.add(capability_id)
        row = by_id[capability_id]
        if row["status"] != transition["from_status"]:
            raise ValueError("stale M5 transition")
        row.update(
            {
                "status": transition["to_status"],
                "probe_kind": transition["probe_kind"],
                "probe_target": transition["probe_target"],
                "evidence": transition["evidence"],
                "limitation": transition["limitation"],
            }
        )
    root = Path(repository_root)
    for row in rows:
        _refresh(row, root)
    criteria = _criteria(rows)
    passed = sum(int(row["passed"]) for row in criteria)
    complete = passed == len(criteria)
    audit = _summarize(rows, f"m5-session{session}-v1")
    report = {
        "schema": M5_PROGRESS_SCHEMA,
        "analysis_mode": "explicit-ui-capability-transition-and-probe-audit",
        "session": session,
        "previous_state": {
            "session": previous_session,
            "operational_graph_version": previous["operational_graph_version"],
        },
        "applied_transition_count": len(transitions),
        "ui_constraint_contract": deepcopy(previous["ui_constraint_contract"]),
        "capability_audit": audit,
        "exit_criteria": criteria,
        "exit_criteria_passed": passed,
        "exit_criteria_total": len(criteria),
        "ordered_session_backlog": previous["ordered_session_backlog"],
        "classification": {
            "m5_entry": "PASS",
            "m5_status": "COMPLETE" if complete else "IN_PROGRESS",
            "m5_exit": "PASS" if complete else "OPEN",
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
            "prototype_scope": "OFFLINE_ONLY",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph_version": graph_version,
        "operational_graph_delta": {
            "base": previous["operational_graph_version"],
            "node": {
                "id": graph_node_id,
                "status": "CONFIRMED",
                "evidence_session": session,
            },
        },
        "publication_safety": _publication_safety(),
    }
    if complete:
        report["milestone_transition"] = {
            "m5": "COMPLETE",
            "m6": "READY",
            "m6_authorized_scope": "static navigation feasibility research",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        }
    return report


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "extracted_resources_included": False,
        "raw_firmware_strings_included": False,
        "navigation_media_content_included": False,
        "vehicle_identifiers_included": False,
        "installable_artifacts_included": False,
        "firmware_execution_performed": False,
        "vehicle_communication_performed": False,
        "original_or_synthetic_assets_only": True,
        "offline_only": True,
    }

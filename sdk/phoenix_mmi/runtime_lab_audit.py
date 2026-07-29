"""Milestone M4 capability registry, gates and explicit progress transitions."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
import importlib
from pathlib import Path


M4_PROGRESS_SCHEMA = "phoenix-mmi.m4-runtime-research-progress/v1"


@dataclass(frozen=True)
class RuntimeCapability:
    capability_id: str
    workstream: str
    name: str
    status: str
    probe_kind: str
    probe_target: str | None
    evidence: str
    limitation: str
    target_session: str | None


M4_CAPABILITIES = (
    RuntimeCapability(
        "M4-CAP-001",
        "platform",
        "VxWorks and SuperH static layout",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.layout:analyze_vxworks_layout",
        "Sessions 003-004",
        "symbol table and scheduled task set remain unknown",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-002",
        "addressing",
        "bounded runtime address model",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.runtime_map:analyze_runtime_map",
        "Session 006",
        "static mapping is not runtime observation",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-003",
        "services",
        "optical and navigation service evidence",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.navigation_dataflow:analyze_navigation_dataflow",
        "Sessions 009-015",
        "sector ABI and end-to-end parser edge remain open",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-004",
        "resources",
        "strict resource identity catalog",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.resource_catalog:ResourceCatalog",
        "Sessions 076-077",
        "runtime consumer remains open",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-005",
        "objects",
        "runtime linkage and owner lineage",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.runtime_linkage:analyze_runtime_linkage_family",
        "Sessions 018-033",
        "object identity and dynamic behavior remain unknown",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-006",
        "resources",
        "resource relationship evidence",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.resource_text:build_resource_relationship_graph",
        "Session 082",
        "renderer consumer is not identified",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-007",
        "devices",
        "navigation and storage boundary evidence",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.navigation_storage:analyze_navigation_storage_boundary",
        "Session 009",
        "driver entries and hardware registers remain unknown",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-008",
        "execution",
        "firmware execution",
        "BLOCKED",
        "none",
        None,
        "Project safety boundary",
        "untrusted firmware execution is outside M4",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-009",
        "vehicle",
        "vehicle-side runtime observation",
        "BLOCKED",
        "none",
        None,
        "Project safety boundary",
        "bench and vehicle communication require M7 controls",
        None,
    ),
    RuntimeCapability(
        "M4-CAP-010",
        "platform",
        "publication-safe task and service inventory",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "no cross-release runtime inventory",
        "085",
    ),
    RuntimeCapability(
        "M4-CAP-011",
        "ipc",
        "bounded IPC primitive contract",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "message payload and producer/consumer models remain unknown",
        "086",
    ),
    RuntimeCapability(
        "M4-CAP-012",
        "resources",
        "resource consumer matrix",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "no exact-address consumer census",
        "087",
    ),
    RuntimeCapability(
        "M4-CAP-013",
        "devices",
        "device boundary catalog",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "no unified device-family topology",
        "088",
    ),
    RuntimeCapability(
        "M4-CAP-014",
        "objects",
        "anonymous runtime object topology",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "no cross-release pointer-shaped topology",
        "089",
    ),
    RuntimeCapability(
        "M4-CAP-015",
        "emulation",
        "isolated host contract harness",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "no deterministic I/O-free runtime abstraction",
        "090",
    ),
    RuntimeCapability(
        "M4-CAP-016",
        "synthesis",
        "confidence-graded runtime evidence graph",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "runtime evidence remains distributed",
        "091",
    ),
    RuntimeCapability(
        "M4-CAP-017",
        "integration",
        "deterministic M4 integration gate",
        "MISSING",
        "none",
        None,
        "M4 requirement",
        "no complete synthetic runtime workflow",
        "092",
    ),
)

M4_EXIT_CRITERIA = (
    {
        "criterion_id": "M4-X1",
        "name": "publication-safe task and service inventory",
        "required_capabilities": ["M4-CAP-010"],
        "target_session": "085",
    },
    {
        "criterion_id": "M4-X2",
        "name": "bounded IPC primitive contract",
        "required_capabilities": ["M4-CAP-011"],
        "target_session": "086",
    },
    {
        "criterion_id": "M4-X3",
        "name": "static resource consumer matrix",
        "required_capabilities": ["M4-CAP-012"],
        "target_session": "087",
    },
    {
        "criterion_id": "M4-X4",
        "name": "cross-release device boundary catalog",
        "required_capabilities": ["M4-CAP-013"],
        "target_session": "088",
    },
    {
        "criterion_id": "M4-X5",
        "name": "anonymous runtime object topology",
        "required_capabilities": ["M4-CAP-014"],
        "target_session": "089",
    },
    {
        "criterion_id": "M4-X6",
        "name": "isolated deterministic host contract harness",
        "required_capabilities": ["M4-CAP-015"],
        "target_session": "090",
    },
    {
        "criterion_id": "M4-X7",
        "name": "confidence-graded runtime evidence graph",
        "required_capabilities": ["M4-CAP-016"],
        "target_session": "091",
    },
    {
        "criterion_id": "M4-X8",
        "name": "deterministic sanitized integration gate",
        "required_capabilities": ["M4-CAP-017"],
        "target_session": "092",
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
        for criterion in M4_EXIT_CRITERIA
    ]


def build_m4_baseline(
    repository_root: str | Path, m3_closure: dict[str, object]
) -> dict[str, object]:
    if m3_closure.get("schema") != "phoenix-mmi.m3-resource-lab-progress/v1":
        raise ValueError("unsupported M3 closure schema")
    classification = m3_closure.get("classification", {})
    transition = m3_closure.get("milestone_transition", {})
    if (
        classification.get("m3_status") != "COMPLETE"
        or classification.get("m3_exit") != "PASS"
        or transition.get("m4") != "READY"
        or classification.get("safe_mutation_ready") is not False
    ):
        raise ValueError("M4 entry gate is not satisfied")
    root = Path(repository_root)
    rows = [asdict(item) for item in M4_CAPABILITIES]
    for row in rows:
        _refresh(row, root)
    criteria = _criteria(rows)
    audit = _summarize(rows, "m4-session084-v1")
    return {
        "schema": M4_PROGRESS_SCHEMA,
        "analysis_mode": "repository-symbol-capability-audit",
        "session": "084",
        "m3_entry_gate": {
            "m3": "COMPLETE",
            "m4": "READY",
            "safe_mutation_ready": False,
            "passed": True,
        },
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
            "m4_entry": "PASS",
            "m4_status": "IN_PROGRESS",
            "m4_exit": "OPEN",
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph_version": "v76",
        "publication_safety": _publication_safety(),
    }


def advance_m4_progress(
    repository_root: str | Path,
    previous: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph_version: str,
    graph_node_id: str,
) -> dict[str, object]:
    if previous.get("schema") != M4_PROGRESS_SCHEMA:
        raise ValueError("unsupported previous M4 progress schema")
    previous_session = str(previous.get("session", ""))
    if not (
        session.isdigit()
        and previous_session.isdigit()
        and int(session) > int(previous_session)
    ):
        raise ValueError("M4 session must advance monotonically")
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
            raise ValueError("M4 transition fields differ")
        capability_id = transition["capability_id"]
        if capability_id in seen or capability_id not in by_id:
            raise ValueError("duplicate or unknown M4 transition")
        seen.add(capability_id)
        row = by_id[capability_id]
        if row["status"] != transition["from_status"]:
            raise ValueError("stale M4 transition")
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
    audit = _summarize(rows, f"m4-session{session}-v1")
    report = {
        "schema": M4_PROGRESS_SCHEMA,
        "analysis_mode": "explicit-capability-transition-and-probe-audit",
        "session": session,
        "previous_state": {
            "session": previous_session,
            "operational_graph_version": previous["operational_graph_version"],
        },
        "applied_transition_count": len(transitions),
        "capability_audit": audit,
        "exit_criteria": criteria,
        "exit_criteria_passed": passed,
        "exit_criteria_total": len(criteria),
        "ordered_session_backlog": previous["ordered_session_backlog"],
        "classification": {
            "m4_entry": "PASS",
            "m4_status": "COMPLETE" if complete else "IN_PROGRESS",
            "m4_exit": "PASS" if complete else "OPEN",
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
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
            "m4": "COMPLETE",
            "m5": "READY",
            "m5_authorized_scope": "offline Phoenix UI prototype",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        }
    return report


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "raw_strings_included": False,
        "runtime_addresses_included": False,
        "vehicle_identifiers_included": False,
        "extracted_resources_included": False,
        "installable_artifacts_included": False,
        "runtime_execution_observed": False,
        "vehicle_communication_performed": False,
    }

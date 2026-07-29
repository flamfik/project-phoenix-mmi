"""Milestone M6 capability registry, gates and explicit progress transitions."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
import importlib
from pathlib import Path

from .navigation_feasibility_contract import (
    build_navigation_feasibility_contract,
    validate_navigation_feasibility_contract,
)


M6_PROGRESS_SCHEMA = "phoenix-mmi.m6-navigation-feasibility-progress/v1"


@dataclass(frozen=True)
class NavigationCapability:
    capability_id: str
    workstream: str
    name: str
    status: str
    probe_kind: str
    probe_target: str | None
    evidence: str
    limitation: str
    target_session: str | None


M6_CAPABILITIES = (
    NavigationCapability(
        "M6-CAP-001",
        "media",
        "registered ISO/Joliet and FLDB structural analyzer",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.map_media:analyze_navigation_media",
        "Session 011",
        "image provenance and inner payload semantics remain open",
        None,
    ),
    NavigationCapability(
        "M6-CAP-002",
        "payload",
        "bounded navigation payload family analyzer",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.map_payload:analyze_navigation_payloads",
        "Session 012",
        "family structure does not decode routing or coordinates",
        None,
    ),
    NavigationCapability(
        "M6-CAP-003",
        "firmware",
        "static navigation and optical boundary evidence",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.navigation_dataflow:analyze_navigation_dataflow",
        "Sessions 009-042",
        "consumer ABI and dynamic dataflow remain unresolved",
        None,
    ),
    NavigationCapability(
        "M6-CAP-004",
        "evidence",
        "publication-safe firmware evidence graph",
        "PARTIAL",
        "repository-file",
        "research/navigation-media/session060/firmware-evidence-map-v2.json",
        "Session 060",
        "graph records bounded static evidence only",
        None,
    ),
    NavigationCapability(
        "M6-CAP-005",
        "writer",
        "proprietary navigation writer",
        "BLOCKED",
        "none",
        None,
        "M6 safety boundary",
        "inner grammar and write model are not established",
        None,
    ),
    NavigationCapability(
        "M6-CAP-006",
        "integrity",
        "proprietary navigation integrity generator",
        "BLOCKED",
        "none",
        None,
        "M6 safety boundary",
        "opaque fields and integrity algorithms remain unresolved",
        None,
    ),
    NavigationCapability(
        "M6-CAP-007",
        "runtime",
        "target navigation consumer integration",
        "BLOCKED",
        "none",
        None,
        "M6 safety boundary",
        "runtime ownership, ABI and budgets remain unresolved",
        None,
    ),
    NavigationCapability(
        "M6-CAP-008",
        "delivery",
        "installable or vehicle-loadable navigation media",
        "BLOCKED",
        "none",
        None,
        "M6 safety boundary",
        "M6 produces no target-loadable artifacts",
        None,
    ),
    NavigationCapability(
        "M6-CAP-009",
        "constraints",
        "frozen navigation feasibility and provenance contract",
        "IMPLEMENTED",
        "python-symbol",
        (
            "phoenix_mmi.navigation_feasibility_contract:"
            "build_navigation_feasibility_contract"
        ),
        "Session 102",
        "contract authorizes static host research only",
        None,
    ),
    NavigationCapability(
        "M6-CAP-010",
        "evidence",
        "registered navigation evidence ledger",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "no normalized milestone evidence ledger",
        "103",
    ),
    NavigationCapability(
        "M6-CAP-011",
        "format",
        "confidence-graded map knowledge matrix",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "known structure and blocked semantics are not normalized",
        "104",
    ),
    NavigationCapability(
        "M6-CAP-012",
        "runtime",
        "navigation consumer boundary graph",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "media-to-runtime path is not represented as a closed graph",
        "105",
    ),
    NavigationCapability(
        "M6-CAP-013",
        "provenance",
        "OSM source and attribution policy",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "no machine-checkable open-data provenance gate",
        "106",
    ),
    NavigationCapability(
        "M6-CAP-014",
        "model",
        "neutral navigation graph model",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "no target-independent graph representation",
        "107",
    ),
    NavigationCapability(
        "M6-CAP-015",
        "adapter",
        "bounded authorized OSM XML adapter",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "no validated open-data ingestion boundary",
        "108",
    ),
    NavigationCapability(
        "M6-CAP-016",
        "routing",
        "deterministic synthetic routing feasibility lab",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "no end-to-end neutral graph route proof",
        "109",
    ),
    NavigationCapability(
        "M6-CAP-017",
        "integration",
        "deterministic M6 decision and integration gate",
        "MISSING",
        "none",
        None,
        "M6 requirement",
        "no complete dual-track feasibility verdict",
        "110",
    ),
)


M6_EXIT_CRITERIA = tuple(
    {
        "criterion_id": f"M6-X{index}",
        "name": name,
        "required_capabilities": [capability],
        "target_session": session,
    }
    for index, (name, capability, session) in enumerate(
        (
            ("registered navigation evidence ledger", "M6-CAP-010", "103"),
            ("confidence-graded map knowledge matrix", "M6-CAP-011", "104"),
            ("navigation consumer boundary graph", "M6-CAP-012", "105"),
            ("OSM source and attribution policy", "M6-CAP-013", "106"),
            ("neutral navigation graph model", "M6-CAP-014", "107"),
            ("bounded authorized OSM XML adapter", "M6-CAP-015", "108"),
            ("deterministic synthetic routing lab", "M6-CAP-016", "109"),
            ("deterministic M6 integration and verdict", "M6-CAP-017", "110"),
        ),
        start=1,
    )
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
        for criterion in M6_EXIT_CRITERIA
    ]


def _validate_m5_closure(m5_closure: dict[str, object]) -> None:
    if m5_closure.get("schema") != "phoenix-mmi.m5-ui-prototype-progress/v1":
        raise ValueError("unsupported M5 closure schema")
    classification = m5_closure.get("classification")
    transition = m5_closure.get("milestone_transition")
    if not isinstance(classification, dict) or not isinstance(transition, dict):
        raise ValueError("incomplete M5 closure")
    if (
        classification.get("m5_status") != "COMPLETE"
        or classification.get("m5_exit") != "PASS"
        or transition.get("m6") != "READY"
        or transition.get("m6_authorized_scope")
        != "static navigation feasibility research"
        or classification.get("safe_mutation_ready") is not False
        or classification.get("installable_artifact_ready") is not False
    ):
        raise ValueError("M6 entry gate is not satisfied")


def build_m6_baseline(
    repository_root: str | Path,
    m5_closure: dict[str, object],
) -> dict[str, object]:
    """Build the deterministic Session 102 M6 capability baseline."""

    _validate_m5_closure(m5_closure)
    root = Path(repository_root)
    contract = build_navigation_feasibility_contract()
    validate_navigation_feasibility_contract(contract)
    rows = [asdict(item) for item in M6_CAPABILITIES]
    for row in rows:
        _refresh(row, root)
    criteria = _criteria(rows)
    audit = _summarize(rows, "m6-session102-v1")
    return {
        "schema": M6_PROGRESS_SCHEMA,
        "analysis_mode": "repository-capability-and-navigation-safety-audit",
        "session": "102",
        "m5_entry_gate": {
            "m5": "COMPLETE",
            "m6": "READY",
            "authorized_scope": "static navigation feasibility research",
            "passed": True,
        },
        "navigation_feasibility_contract": contract,
        "capability_audit": audit,
        "exit_criteria": criteria,
        "exit_criteria_passed": 0,
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
            "m6_entry": "PASS",
            "m6_status": "IN_PROGRESS",
            "m6_exit": "OPEN",
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
            "direct_mmi_media_replacement": "BLOCKED",
            "independent_osm_host_pipeline": "OPEN",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph_version": "v94",
        "publication_safety": _publication_safety(),
    }


def advance_m6_progress(
    repository_root: str | Path,
    previous: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph_version: str,
    graph_node_id: str,
) -> dict[str, object]:
    """Apply explicit M6 transitions without implicit capability promotion."""

    if previous.get("schema") != M6_PROGRESS_SCHEMA:
        raise ValueError("unsupported previous M6 progress schema")
    previous_session = str(previous.get("session", ""))
    if not (
        session.isdigit()
        and previous_session.isdigit()
        and int(session) > int(previous_session)
    ):
        raise ValueError("M6 session must advance monotonically")
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
            raise ValueError("M6 transition fields differ")
        capability_id = transition["capability_id"]
        if capability_id in seen or capability_id not in by_id:
            raise ValueError("duplicate or unknown M6 transition")
        seen.add(capability_id)
        row = by_id[capability_id]
        if row["status"] != transition["from_status"]:
            raise ValueError("stale M6 transition")
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
    audit = _summarize(rows, f"m6-session{session}-v1")
    report = {
        "schema": M6_PROGRESS_SCHEMA,
        "analysis_mode": "explicit-navigation-capability-transition-audit",
        "session": session,
        "previous_state": {
            "session": previous_session,
            "operational_graph_version": previous["operational_graph_version"],
        },
        "applied_transition_count": len(transitions),
        "navigation_feasibility_contract": deepcopy(
            previous["navigation_feasibility_contract"]
        ),
        "capability_audit": audit,
        "exit_criteria": criteria,
        "exit_criteria_passed": passed,
        "exit_criteria_total": len(criteria),
        "ordered_session_backlog": previous["ordered_session_backlog"],
        "classification": {
            "m6_entry": "PASS",
            "m6_status": "COMPLETE" if complete else "IN_PROGRESS",
            "m6_exit": "PASS" if complete else "OPEN",
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
            "direct_mmi_media_replacement": "BLOCKED",
            "independent_osm_host_pipeline": (
                "PROTOTYPE_FEASIBLE" if complete else "IN_PROGRESS"
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
            "m6": "COMPLETE",
            "m7": "READY",
            "m7_authorized_scope": (
                "controlled read-only bench planning and signed risk review"
            ),
            "direct_mmi_media_replacement": "BLOCKED",
            "independent_osm_host_pipeline": "PROTOTYPE_FEASIBLE",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        }
    return report


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "map_payload_bytes_included": False,
        "extracted_resources_included": False,
        "raw_proprietary_names_included": False,
        "navigation_media_content_included": False,
        "osm_source_data_included": False,
        "vehicle_identifiers_included": False,
        "installable_artifacts_included": False,
        "firmware_execution_performed": False,
        "vehicle_communication_performed": False,
        "offline_only": True,
    }

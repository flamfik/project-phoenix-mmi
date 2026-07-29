"""Milestone M3 Resource Laboratory capability and exit-gate audit."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
import importlib
from pathlib import Path


M3_PROGRESS_SCHEMA = "phoenix-mmi.m3-resource-lab-progress/v1"


@dataclass(frozen=True)
class ResourceCapability:
    capability_id: str
    workstream: str
    name: str
    status: str
    probe_kind: str
    probe_target: str | None
    evidence: str
    limitation: str
    target_session: str | None = None


M3_CAPABILITIES = (
    ResourceCapability(
        "M3-CAP-001",
        "graphics",
        "strict YIM/XIM2 envelope reader",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.yim:parse_yim_envelope",
        "Sessions 045 and 053",
        "integrity fields remain unresolved",
    ),
    ResourceCapability(
        "M3-CAP-002",
        "graphics",
        "bounded XIM2 RLE decoder",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.yim:decode_yim_rle",
        "Sessions 046 and 053",
        "two-byte units have no confirmed color semantics",
    ),
    ResourceCapability(
        "M3-CAP-003",
        "catalog",
        "embedded XIM2 census",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.yim_research:analyze_embedded_xim2",
        "Session 053",
        "consumer routine and resource names are not identified",
    ),
    ResourceCapability(
        "M3-CAP-004",
        "text",
        "printable-string extractor",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.strings:extract_strings",
        "Sessions 003-010",
        "raw extraction is local and lacks a resource-specific catalog",
    ),
    ResourceCapability(
        "M3-CAP-005",
        "font",
        "sparse bitmap-atlas evidence",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.operational_model:analyze_relocated_bitmap_atlas",
        "Session 008",
        "font header and renderer consumer remain unresolved",
    ),
    ResourceCapability(
        "M3-CAP-006",
        "safety",
        "YIM integrity writer",
        "BLOCKED",
        "none",
        None,
        "Sessions 047 and 051-054",
        "32-bit and 16-bit integrity algorithms are unresolved",
    ),
    ResourceCapability(
        "M3-CAP-007",
        "language",
        "LOD semantic decoder",
        "BLOCKED",
        "none",
        None,
        "Sessions 048 and 055-060",
        "record, address and integrity semantics are unresolved",
    ),
    ResourceCapability(
        "M3-CAP-008",
        "catalog",
        "versioned resource catalog",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "no shared standalone/embedded identity and provenance model",
        "076",
    ),
    ResourceCapability(
        "M3-CAP-009",
        "graphics",
        "geometry taxonomy",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "validated dimensions are not grouped into neutral shape classes",
        "077",
    ),
    ResourceCapability(
        "M3-CAP-010",
        "graphics",
        "pixel-layout hypothesis evaluator",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "16-bit unit layouts are not compared under one fixed metric",
        "078",
    ),
    ResourceCapability(
        "M3-CAP-011",
        "preview",
        "offline candidate preview renderer",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "no bounded format-explicit preview API",
        "079",
    ),
    ResourceCapability(
        "M3-CAP-012",
        "text",
        "publication-safe text catalog",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "no cross-release resource-text comparison",
        "080",
    ),
    ResourceCapability(
        "M3-CAP-013",
        "font",
        "font candidate catalog",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "standard font containers and bitmap evidence are not unified",
        "081",
    ),
    ResourceCapability(
        "M3-CAP-014",
        "language",
        "language-pack topology",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "locale membership and release reuse are not normalized",
        "082",
    ),
    ResourceCapability(
        "M3-CAP-015",
        "graph",
        "resource relationship graph",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "resource evidence is distributed across earlier session graphs",
        "082",
    ),
    ResourceCapability(
        "M3-CAP-016",
        "integration",
        "M3 deterministic integration gate",
        "MISSING",
        "none",
        None,
        "M3 requirement",
        "no complete sanitized Resource Laboratory workflow",
        "083",
    ),
)


M3_EXIT_CRITERIA = (
    {
        "criterion_id": "M3-X1",
        "name": "versioned resource identity and provenance catalog",
        "required_capabilities": ["M3-CAP-008"],
        "target_session": "076",
    },
    {
        "criterion_id": "M3-X2",
        "name": "neutral geometry taxonomy",
        "required_capabilities": ["M3-CAP-009"],
        "target_session": "077",
    },
    {
        "criterion_id": "M3-X3",
        "name": "bounded pixel-layout hypothesis evaluation",
        "required_capabilities": ["M3-CAP-010"],
        "target_session": "078",
    },
    {
        "criterion_id": "M3-X4",
        "name": "format-explicit offline preview",
        "required_capabilities": ["M3-CAP-011"],
        "target_session": "079",
    },
    {
        "criterion_id": "M3-X5",
        "name": "publication-safe cross-release text catalog",
        "required_capabilities": ["M3-CAP-012"],
        "target_session": "080",
    },
    {
        "criterion_id": "M3-X6",
        "name": "font candidate catalog",
        "required_capabilities": ["M3-CAP-013"],
        "target_session": "081",
    },
    {
        "criterion_id": "M3-X7",
        "name": "language topology and resource relationship graph",
        "required_capabilities": ["M3-CAP-014", "M3-CAP-015"],
        "target_session": "082",
    },
    {
        "criterion_id": "M3-X8",
        "name": "deterministic sanitized-fixture integration gate",
        "required_capabilities": ["M3-CAP-016"],
        "target_session": "083",
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


def _summarize(rows: list[dict[str, object]], version: str) -> dict[str, object]:
    status_counts = Counter(str(row["status"]) for row in rows)
    workstreams = []
    for workstream in sorted({str(row["workstream"]) for row in rows}):
        selected = [row for row in rows if row["workstream"] == workstream]
        workstreams.append(
            {
                "workstream": workstream,
                "capability_count": len(selected),
                "status_counts": dict(
                    sorted(Counter(str(row["status"]) for row in selected).items())
                ),
            }
        )
    return {
        "registry_version": version,
        "capability_count": len(rows),
        "status_counts": dict(sorted(status_counts.items())),
        "capabilities": rows,
        "workstreams": workstreams,
        "probe_integrity": all(
            bool(row["probe_matches_declaration"]) for row in rows
        ),
    }


def _refresh(row: dict[str, object], root: Path) -> None:
    observed = _probe(row, root)
    expected = row["status"] in {"IMPLEMENTED", "PARTIAL"}
    row["probe_observed"] = observed
    row["probe_matches_declaration"] = observed == expected


def build_m3_baseline(
    repository_root: str | Path, m2_closure: dict[str, object]
) -> dict[str, object]:
    if m2_closure.get("schema") != "phoenix-mmi.m2-toolkit-progress/v1":
        raise ValueError("unsupported M2 closure schema")
    classification = m2_closure.get("classification", {})
    transition = m2_closure.get("milestone_transition", {})
    if (
        classification.get("m2_status") != "COMPLETE"
        or classification.get("m2_exit") != "PASS"
        or transition.get("m3") != "READY"
        or classification.get("safe_mutation_ready") is not False
    ):
        raise ValueError("M3 entry gate is not satisfied")
    root = Path(repository_root)
    rows = [asdict(item) for item in M3_CAPABILITIES]
    for row in rows:
        _refresh(row, root)
    audit = _summarize(rows, "m3-session075-v1")
    criteria = []
    by_id = {row["capability_id"]: row for row in rows}
    for criterion in M3_EXIT_CRITERIA:
        criteria.append(
            {
                **criterion,
                "passed": all(
                    by_id[item]["status"] == "IMPLEMENTED"
                    for item in criterion["required_capabilities"]
                ),
            }
        )
    return {
        "schema": M3_PROGRESS_SCHEMA,
        "analysis_mode": "repository-symbol-capability-audit",
        "session": "075",
        "m2_entry_gate": {
            "source_schema": m2_closure["schema"],
            "m2": "COMPLETE",
            "m3": "READY",
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
            "m3_entry": "PASS",
            "m3_status": "IN_PROGRESS",
            "m3_exit": "OPEN",
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph_version": "v67",
        "publication_safety": _publication_safety(),
    }


def advance_m3_progress(
    repository_root: str | Path,
    previous: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph_version: str,
    graph_node_id: str,
) -> dict[str, object]:
    if previous.get("schema") != M3_PROGRESS_SCHEMA:
        raise ValueError("unsupported previous M3 progress schema")
    previous_session = str(previous.get("session", ""))
    if not (
        session.isdigit()
        and previous_session.isdigit()
        and int(session) > int(previous_session)
    ):
        raise ValueError("M3 session must advance monotonically")
    if previous.get("classification", {}).get("safe_mutation_ready") is not False:
        raise ValueError("M3 mutation gate must remain false")
    rows = deepcopy(previous["capability_audit"]["capabilities"])
    by_id = {str(row["capability_id"]): row for row in rows}
    seen: set[str] = set()
    required_fields = {
        "capability_id",
        "from_status",
        "to_status",
        "probe_kind",
        "probe_target",
        "evidence",
        "limitation",
    }
    for transition in transitions:
        if set(transition) != required_fields:
            raise ValueError("M3 transition fields differ")
        capability_id = transition["capability_id"]
        if capability_id in seen or capability_id not in by_id:
            raise ValueError(f"invalid duplicate/unknown transition {capability_id}")
        seen.add(capability_id)
        row = by_id[capability_id]
        if row["status"] != transition["from_status"]:
            raise ValueError(f"stale transition for {capability_id}")
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
    audit = _summarize(rows, f"m3-session{session}-v1")
    by_id = {row["capability_id"]: row for row in rows}
    criteria = [
        {
            **criterion,
            "passed": all(
                by_id[item]["status"] == "IMPLEMENTED"
                for item in criterion["required_capabilities"]
            ),
        }
        for criterion in M3_EXIT_CRITERIA
    ]
    passed = sum(int(row["passed"]) for row in criteria)
    complete = passed == len(criteria)
    return {
        "schema": M3_PROGRESS_SCHEMA,
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
            "m3_entry": "PASS",
            "m3_status": "COMPLETE" if complete else "IN_PROGRESS",
            "m3_exit": "PASS" if complete else "OPEN",
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


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "decoded_raster_bytes_included": False,
        "decoded_raster_hashes_included": False,
        "raw_strings_included": False,
        "local_paths_included": False,
        "extracted_resources_included": False,
        "installable_artifacts_included": False,
        "runtime_execution_observed": False,
    }

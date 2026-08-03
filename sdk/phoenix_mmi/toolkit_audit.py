"""M2 Analysis Toolkit capability registry and entry audit.

The audit probes only Python symbols and repository files. It does not open
firmware artifacts, execute target code or create update media.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
import importlib
from pathlib import Path


@dataclass(frozen=True)
class Capability:
    capability_id: str
    workstream: str
    name: str
    status: str
    probe_kind: str
    probe_target: str | None
    evidence: str
    limitation: str
    target_session: str | None = None


CAPABILITIES = (
    Capability(
        "M2-CAP-001",
        "core",
        "bounded binary reader",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.binary:BinaryReader",
        "Sessions 003-065",
        "read-only bounded access only",
    ),
    Capability(
        "M2-CAP-002",
        "manifest",
        "artifact hash inventory",
        "PARTIAL",
        "repository-file",
        "tools/inventory/verify_artifacts.py",
        "Phase 0 and Session 061",
        "tool output has no versioned SDK manifest model",
    ),
    Capability(
        "M2-CAP-003",
        "manifest",
        "registered-media identity verifier",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.m1_closure:audit_m1_media",
        "Session 061",
        "currently specialized to the registered MMI 5570 set",
    ),
    Capability(
        "M2-CAP-004",
        "classifier",
        "validated static fingerprint scanner",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.fingerprint:scan_fingerprints",
        "Sessions 003-065",
        "fixed signatures do not constitute a declarative format registry",
    ),
    Capability(
        "M2-CAP-005",
        "classifier",
        "update-member family router",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.m1_closure:classify_m1_members",
        "Session 062",
        "routing rules are embedded in the M1 closure module",
    ),
    Capability(
        "M2-CAP-006",
        "parser",
        "ISO 9660 reader",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.iso9660:ISO9660Image",
        "Sessions 001 and 061",
        "read-only primary-directory model",
    ),
    Capability(
        "M2-CAP-007",
        "parser",
        "METAINFO structural parser",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.m1_closure:parse_metainfo_text",
        "Sessions 002 and 063",
        "multiple historical parser implementations remain",
    ),
    Capability(
        "M2-CAP-008",
        "parser",
        "Intel HEX decoder",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.record_normalization:decode_intel_hex",
        "Session 041",
        "vendor records remain bounded opaque metadata",
    ),
    Capability(
        "M2-CAP-009",
        "parser",
        "Motorola S-record decoder",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.record_normalization:decode_srecord_envelope",
        "Session 041",
        "invalid and opaque envelope material remains isolated",
    ),
    Capability(
        "M2-CAP-010",
        "parser",
        "YIM/XIM2 read model",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.yim:parse_yim_envelope",
        "Sessions 045-054",
        "write integrity and encoding remain blocked",
    ),
    Capability(
        "M2-CAP-011",
        "parser",
        "FLDB container read model",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.map_media:parse_fldb_container",
        "Sessions 011-014",
        "payload semantics and runtime parser remain open",
    ),
    Capability(
        "M2-CAP-012",
        "parser",
        "LOD bounded parser",
        "MISSING",
        "none",
        None,
        "Sessions 048 and 055-060",
        "only opaque topology is established",
        "069",
    ),
    Capability(
        "M2-CAP-013",
        "checksum",
        "CRC32/IEEE engine",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.checksum:crc32_region",
        "Sessions 002-003",
        "one algorithm does not identify protected ranges",
    ),
    Capability(
        "M2-CAP-014",
        "checksum",
        "candidate-region checksum mapper",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.checksum:map_crc32_expectations",
        "Session 003",
        "region and algorithm experiments are hard-coded",
    ),
    Capability(
        "M2-CAP-015",
        "checksum",
        "YIM integrity algorithm",
        "BLOCKED",
        "none",
        None,
        "Sessions 047 and 051-054",
        "tested catalogues produce no match",
        "070",
    ),
    Capability(
        "M2-CAP-016",
        "checksum",
        "METAINFO metafile checksum algorithm",
        "BLOCKED",
        "none",
        None,
        "Sessions 002 and 063",
        "declared field exists but its algorithm is unresolved",
        "070",
    ),
    Capability(
        "M2-CAP-017",
        "diff",
        "sanitized analysis-report comparison",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.analysis:compare_reports",
        "Session 003",
        "specialized report comparison, not a generic structure diff",
    ),
    Capability(
        "M2-CAP-018",
        "diff",
        "generic structural diff",
        "MISSING",
        "none",
        None,
        "M2 requirement",
        "no normalized field/list/set comparison contract",
        "071",
    ),
    Capability(
        "M2-CAP-019",
        "report",
        "deterministic JSON writer",
        "IMPLEMENTED",
        "python-symbol",
        "phoenix_mmi.report:write_json",
        "Sessions 003-065",
        "schemas are named but not centrally registered",
    ),
    Capability(
        "M2-CAP-020",
        "report",
        "schema registry and validator",
        "MISSING",
        "none",
        None,
        "M2 requirement",
        "no central validation API",
        "072",
    ),
    Capability(
        "M2-CAP-021",
        "cli",
        "static-analysis CLI",
        "PARTIAL",
        "python-symbol",
        "phoenix_mmi.cli:main",
        "Session 003",
        "single legacy command surface",
    ),
    Capability(
        "M2-CAP-022",
        "cli",
        "unified toolkit subcommands",
        "MISSING",
        "none",
        None,
        "M2 requirement",
        "manifest, classify, parse, checksum and diff are not unified",
        "073",
    ),
    Capability(
        "M2-CAP-023",
        "manifest",
        "versioned SDK manifest schema",
        "MISSING",
        "none",
        None,
        "M2 exit criterion",
        "identity, origin and member selection lack one shared model",
        "067",
    ),
    Capability(
        "M2-CAP-024",
        "classifier",
        "declarative format registry",
        "MISSING",
        "none",
        None,
        "M2 exit criterion",
        "detectors and confidence rules are distributed across modules",
        "068",
    ),
    Capability(
        "M2-CAP-025",
        "parser",
        "normalized parse-result contract",
        "MISSING",
        "none",
        None,
        "M2 exit criterion",
        "parser outputs do not share status, bounds and diagnostic fields",
        "069",
    ),
    Capability(
        "M2-CAP-026",
        "checksum",
        "declarative checksum experiment registry",
        "MISSING",
        "none",
        None,
        "M2 exit criterion",
        "algorithms, ranges and negative results lack one model",
        "070",
    ),
    Capability(
        "M2-CAP-027",
        "integration",
        "M2 deterministic integration gate",
        "MISSING",
        "none",
        None,
        "M2 exit criterion",
        "end-to-end sanitized-fixture workflow does not yet exist",
        "074",
    ),
)


EXIT_CRITERIA = (
    {
        "criterion_id": "M2-X1",
        "name": "versioned manifest and identity model",
        "required_capabilities": ["M2-CAP-023"],
        "target_session": "067",
    },
    {
        "criterion_id": "M2-X2",
        "name": "declarative format registry",
        "required_capabilities": ["M2-CAP-024"],
        "target_session": "068",
    },
    {
        "criterion_id": "M2-X3",
        "name": "normalized parser results and bounded LOD handling",
        "required_capabilities": ["M2-CAP-012", "M2-CAP-025"],
        "target_session": "069",
    },
    {
        "criterion_id": "M2-X4",
        "name": "declarative checksum experiment framework",
        "required_capabilities": ["M2-CAP-026"],
        "target_session": "070",
    },
    {
        "criterion_id": "M2-X5",
        "name": "generic structural diff engine",
        "required_capabilities": ["M2-CAP-018"],
        "target_session": "071",
    },
    {
        "criterion_id": "M2-X6",
        "name": "schema registry and validation",
        "required_capabilities": ["M2-CAP-020"],
        "target_session": "072",
    },
    {
        "criterion_id": "M2-X7",
        "name": "unified toolkit CLI",
        "required_capabilities": ["M2-CAP-022"],
        "target_session": "073",
    },
    {
        "criterion_id": "M2-X8",
        "name": "deterministic sanitized-fixture integration gate",
        "required_capabilities": ["M2-CAP-027"],
        "target_session": "074",
    },
)


def _probe(capability: Capability, root: Path) -> bool:
    if capability.probe_kind == "none":
        return False
    if capability.probe_kind == "repository-file":
        return bool(
            capability.probe_target
            and (root / capability.probe_target).is_file()
        )
    if capability.probe_kind == "python-symbol":
        if not capability.probe_target:
            return False
        module_name, symbol_name = capability.probe_target.split(":", 1)
        module = importlib.import_module(module_name)
        return hasattr(module, symbol_name)
    raise ValueError(f"unsupported probe kind: {capability.probe_kind}")


def audit_toolkit_capabilities(
    repository_root: str | Path,
) -> dict[str, object]:
    """Probe the frozen Session 066 capability registry."""

    root = Path(repository_root)
    rows = []
    for capability in CAPABILITIES:
        observed = _probe(capability, root)
        expected = capability.status in {"IMPLEMENTED", "PARTIAL"}
        row = asdict(capability)
        row["probe_observed"] = observed
        row["probe_matches_declaration"] = observed == expected
        rows.append(row)

    status_counts = Counter(row["status"] for row in rows)
    workstreams = []
    for workstream in sorted({row["workstream"] for row in rows}):
        selected = [
            row for row in rows if row["workstream"] == workstream
        ]
        counts = Counter(row["status"] for row in selected)
        workstreams.append(
            {
                "workstream": workstream,
                "capability_count": len(selected),
                "status_counts": dict(sorted(counts.items())),
                "open_capability_count": sum(
                    counts[value]
                    for value in ("MISSING", "BLOCKED")
                ),
            }
        )
    return {
        "registry_version": "m2-session066-v1",
        "capability_count": len(rows),
        "capabilities": rows,
        "status_counts": dict(sorted(status_counts.items())),
        "workstreams": workstreams,
        "probe_integrity": all(
            row["probe_matches_declaration"] for row in rows
        ),
    }


def _summarize_capability_rows(
    rows: list[dict[str, object]],
    *,
    registry_version: str,
) -> dict[str, object]:
    status_counts = Counter(str(row["status"]) for row in rows)
    workstreams = []
    for workstream in sorted({str(row["workstream"]) for row in rows}):
        selected = [
            row for row in rows if row["workstream"] == workstream
        ]
        counts = Counter(str(row["status"]) for row in selected)
        workstreams.append(
            {
                "workstream": workstream,
                "capability_count": len(selected),
                "status_counts": dict(sorted(counts.items())),
                "open_capability_count": sum(
                    counts[value] for value in ("MISSING", "BLOCKED")
                ),
            }
        )
    return {
        "registry_version": registry_version,
        "capability_count": len(rows),
        "capabilities": rows,
        "status_counts": dict(sorted(status_counts.items())),
        "workstreams": workstreams,
        "probe_integrity": all(
            bool(row["probe_matches_declaration"]) for row in rows
        ),
    }


def _refresh_capability_probe(
    row: dict[str, object], root: Path
) -> None:
    capability = Capability(
        capability_id=str(row["capability_id"]),
        workstream=str(row["workstream"]),
        name=str(row["name"]),
        status=str(row["status"]),
        probe_kind=str(row["probe_kind"]),
        probe_target=(
            None
            if row["probe_target"] is None
            else str(row["probe_target"])
        ),
        evidence=str(row["evidence"]),
        limitation=str(row["limitation"]),
        target_session=(
            None
            if row["target_session"] is None
            else str(row["target_session"])
        ),
    )
    observed = _probe(capability, root)
    expected = capability.status in {"IMPLEMENTED", "PARTIAL"}
    row["probe_observed"] = observed
    row["probe_matches_declaration"] = observed == expected


def advance_m2_progress(
    repository_root: str | Path,
    previous_report: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph_version: str,
    graph_node_id: str,
) -> dict[str, object]:
    """Apply explicit capability transitions to a frozen M2 state.

    The function consumes the prior machine-readable state instead of
    mutating ``CAPABILITIES``. Historical Session 066 reproduction therefore
    remains byte-stable while later sessions can advance the M2 gate.
    """

    allowed_schemas = {
        "phoenix-mmi.m2-toolkit-foundation/v1",
        "phoenix-mmi.m2-toolkit-progress/v1",
    }
    if previous_report.get("schema") not in allowed_schemas:
        raise ValueError("unsupported previous M2 progress schema")
    previous_session = str(previous_report.get("session", ""))
    if not (
        session.isdigit()
        and previous_session.isdigit()
        and int(session) > int(previous_session)
    ):
        raise ValueError("M2 progress session must advance monotonically")
    if previous_report.get("classification", {}).get(
        "safe_mutation_ready"
    ) is not False:
        raise ValueError("M2 progress requires the mutation gate to remain false")

    root = Path(repository_root)
    rows = deepcopy(
        previous_report["capability_audit"]["capabilities"]
    )
    by_id = {str(row["capability_id"]): row for row in rows}
    seen: set[str] = set()
    for transition in transitions:
        required_fields = {
            "capability_id",
            "from_status",
            "to_status",
            "probe_kind",
            "probe_target",
            "evidence",
            "limitation",
        }
        if set(transition) != required_fields:
            raise ValueError("capability transition fields do not match contract")
        capability_id = transition["capability_id"]
        if capability_id in seen:
            raise ValueError(f"duplicate transition: {capability_id}")
        seen.add(capability_id)
        if capability_id not in by_id:
            raise ValueError(f"unknown capability: {capability_id}")
        row = by_id[capability_id]
        if row["status"] != transition["from_status"]:
            raise ValueError(
                f"stale transition for {capability_id}: {row['status']}"
            )
        if transition["to_status"] not in {
            "IMPLEMENTED",
            "PARTIAL",
            "MISSING",
            "BLOCKED",
        }:
            raise ValueError("unsupported capability status")
        row.update(
            {
                "status": transition["to_status"],
                "probe_kind": transition["probe_kind"],
                "probe_target": transition["probe_target"],
                "evidence": transition["evidence"],
                "limitation": transition["limitation"],
            }
        )

    # Re-probe the complete carried state, not only changed rows. A later
    # session must detect regressions in capabilities implemented earlier.
    for row in rows:
        _refresh_capability_probe(row, root)

    audit = _summarize_capability_rows(
        rows, registry_version=f"m2-session{session}-v1"
    )
    capability_by_id = {
        str(row["capability_id"]): row
        for row in audit["capabilities"]
    }
    criteria = []
    for criterion in EXIT_CRITERIA:
        required = [
            capability_by_id[value]
            for value in criterion["required_capabilities"]
        ]
        criteria.append(
            {
                **criterion,
                "passed": all(
                    row["status"] == "IMPLEMENTED" for row in required
                ),
            }
        )
    passed_count = sum(int(row["passed"]) for row in criteria)
    return {
        "schema": "phoenix-mmi.m2-toolkit-progress/v1",
        "analysis_mode": "explicit-capability-transition-and-probe-audit",
        "session": session,
        "previous_state": {
            "schema": previous_report["schema"],
            "session": previous_session,
            "operational_graph_version": previous_report[
                "operational_graph_version"
            ],
        },
        "applied_transition_count": len(transitions),
        "capability_audit": audit,
        "exit_criteria": criteria,
        "exit_criteria_passed": passed_count,
        "exit_criteria_total": len(criteria),
        "ordered_session_backlog": previous_report[
            "ordered_session_backlog"
        ],
        "classification": {
            "m2_entry": "PASS",
            "m2_status": (
                "COMPLETE" if passed_count == len(criteria) else "IN_PROGRESS"
            ),
            "capability_state": (
                "CONFIRMED" if audit["probe_integrity"] else "INCONSISTENT"
            ),
            "m2_exit": (
                "PASS" if passed_count == len(criteria) else "OPEN"
            ),
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph_version": graph_version,
        "operational_graph_delta": {
            "base": (
                "phoenix-mmi.operational-graph/"
                + str(previous_report["operational_graph_version"])
            ),
            "nodes": [
                {
                    "id": graph_node_id,
                    "status": "CONFIRMED",
                    "evidence_session": session,
                }
            ],
            "edges": [
                {
                    "source": "m2-analysis-toolkit",
                    "target": graph_node_id,
                    "status": "CONFIRMED",
                    "relation": "implements-ordered-exit-criterion",
                }
            ],
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "source_content_hashes_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
            "installable_artifacts_included": False,
            "runtime_execution_observed": False,
        },
    }


def build_m2_foundation_report(
    repository_root: str | Path,
    m1_closure: dict[str, object],
) -> dict[str, object]:
    """Apply the M2 entry gate and produce the ordered toolkit backlog."""

    if m1_closure.get("schema") != (
        "phoenix-mmi.milestone-m1-closure/v1"
    ):
        raise ValueError("unsupported M1 closure schema")
    classification = m1_closure.get("classification", {})
    if classification.get("milestone_m1") != "COMPLETE":
        raise ValueError("M1 must be complete before M2 begins")
    if classification.get("safe_mutation_ready") is not False:
        raise ValueError("M2 entry requires the mutation gate to remain false")

    audit = audit_toolkit_capabilities(repository_root)
    by_id = {
        row["capability_id"]: row for row in audit["capabilities"]
    }
    criteria = []
    for criterion in EXIT_CRITERIA:
        required = [
            by_id[value] for value in criterion["required_capabilities"]
        ]
        passed = all(row["status"] == "IMPLEMENTED" for row in required)
        criteria.append({**criterion, "passed": passed})

    return {
        "schema": "phoenix-mmi.m2-toolkit-foundation/v1",
        "analysis_mode": "repository-symbol-and-file-capability-audit",
        "session": "066",
        "m1_entry_gate": {
            "source_schema": m1_closure["schema"],
            "milestone_m1": classification["milestone_m1"],
            "safe_mutation_ready": False,
            "passed": True,
        },
        "capability_audit": audit,
        "exit_criteria": criteria,
        "exit_criteria_passed": sum(
            int(row["passed"]) for row in criteria
        ),
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
            "m2_entry": (
                "PASS" if audit["probe_integrity"] else "FAIL"
            ),
            "m2_status": "IN_PROGRESS",
            "capability_baseline": (
                "CONFIRMED"
                if audit["probe_integrity"]
                else "INCONSISTENT"
            ),
            "m2_exit": "OPEN",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph_version": "v58",
        "operational_graph_delta": {
            "base": "phoenix-mmi.operational-graph/v57",
            "nodes": [
                {
                    "id": "m2-analysis-toolkit",
                    "status": "IN_PROGRESS",
                    "evidence_session": "066",
                },
                {
                    "id": "m2-capability-baseline",
                    "status": "CONFIRMED",
                    "evidence_session": "066",
                },
            ],
            "edges": [
                {
                    "source": "milestone-m1",
                    "target": "m2-analysis-toolkit",
                    "status": "CONFIRMED_TRANSITION",
                    "relation": "authorizes-read-only-toolkit-development",
                },
                {
                    "source": "m2-analysis-toolkit",
                    "target": "m2-capability-baseline",
                    "status": "CONFIRMED",
                    "relation": "freezes-capability-and-exit-registry",
                },
            ],
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "source_content_hashes_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
            "installable_artifacts_included": False,
            "runtime_execution_observed": False,
        },
    }

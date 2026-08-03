"""Deterministic dual-track integration and feasibility verdict for M6."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from .navigation_boundaries import build_navigation_boundary_graph
from .navigation_evidence import build_navigation_evidence_ledger
from .navigation_feasibility_contract import (
    build_navigation_feasibility_contract,
)
from .navigation_knowledge import build_navigation_knowledge_matrix
from .navigation_provenance import build_navigation_provenance_policy
from .navigation_routing import build_synthetic_routing_lab


NAVIGATION_INTEGRATION_SCHEMA = "phoenix-mmi.navigation-integration/v1"


def run_navigation_feasibility_integration(
    repository_root: str | Path,
) -> dict[str, object]:
    """Run the complete M6 chain without proprietary content or target output."""

    contract = build_navigation_feasibility_contract()
    evidence = build_navigation_evidence_ledger(repository_root)
    knowledge = build_navigation_knowledge_matrix(evidence)
    boundaries = build_navigation_boundary_graph(knowledge)
    provenance = build_navigation_provenance_policy()
    first_lab = build_synthetic_routing_lab()
    second_lab = build_synthetic_routing_lab()
    repeat_equal = first_lab == second_lab
    stages = [
        _stage("M6-I1", "safety and decision contract", True),
        _stage(
            "M6-I2",
            "registered evidence ledger",
            evidence["classification"]["evidence_chain"]
            == "CONSISTENT_PUBLIC_AGGREGATES",
        ),
        _stage(
            "M6-I3",
            "knowledge and blocker matrix",
            knowledge["direct_replacement_gate"]["passed"] is False,
        ),
        _stage(
            "M6-I4",
            "media-to-runtime boundary graph",
            boundaries["metrics"]["confirmed_media_to_runtime_path"] is False,
        ),
        _stage(
            "M6-I5",
            "open-data provenance policy",
            provenance["distribution_gate"]["provenance_record_required"],
        ),
        _stage(
            "M6-I6",
            "neutral navigation graph",
            first_lab["adapter"]["neutral_graph"]["metrics"]["node_count"] == 5,
        ),
        _stage(
            "M6-I7",
            "bounded OSM XML adapter",
            first_lab["adapter"]["classification"]["bounded_xml_adapter"]
            == "CONFIRMED",
        ),
        _stage(
            "M6-I8",
            "deterministic synthetic route proof",
            first_lab["passed"] and repeat_equal,
        ),
    ]
    passed = all(row["passed"] for row in stages)
    decision = {
        "direct_mmi_media_replacement": {
            "status": "BLOCKED",
            "reason": "FORMAT_INTEGRITY_RUNTIME_AND_RECOVERY_GAPS",
            "installable_output_authorized": False,
        },
        "independent_osm_host_pipeline": {
            "status": "PROTOTYPE_FEASIBLE" if passed else "NOT_DEMONSTRATED",
            "scope": "BOUNDED_HOST_ONLY",
            "target_compatibility": "NOT_ESTABLISHED",
        },
        "sidecar_or_replacement_hardware": {
            "status": "NOT_EVALUATED",
            "reason": "OUTSIDE_M6",
        },
    }
    summary = {
        "registered_media_size_bytes": evidence["registered_artifact"][
            "size_bytes"
        ],
        "validated_fldb_container_count": evidence["structural_summary"][
            "validated_container_count"
        ],
        "internal_record_count": evidence["structural_summary"][
            "internal_record_count"
        ],
        "partition_count": evidence["structural_summary"]["partition_count"],
        "knowledge_row_count": knowledge["summary"]["row_count"],
        "direct_replacement_blocker_count": knowledge["summary"][
            "direct_replacement_blocker_count"
        ],
        "boundary_node_count": boundaries["metrics"]["node_count"],
        "synthetic_route_checks": sum(first_lab["checks"].values()),
    }
    fingerprint = sha256(
        json.dumps(
            {
                "stages": stages,
                "decision": decision,
                "summary": summary,
                "lab_fingerprint": first_lab["lab_fingerprint"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema": NAVIGATION_INTEGRATION_SCHEMA,
        "integration_version": "m6-session110-v1",
        "stages": stages,
        "stages_passed": sum(int(row["passed"]) for row in stages),
        "stages_total": len(stages),
        "passed": passed,
        "repeat_run_equal": repeat_equal,
        "decision": decision,
        "summary": summary,
        "integration_fingerprint": fingerprint,
        "classification": {
            "m6_gate": "PASS" if passed else "FAIL",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
            "vehicle_validation_performed": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "map_payload_bytes_included": False,
            "navigation_media_content_included": False,
            "osm_source_data_included": False,
            "vehicle_data_included": False,
            "installable_artifacts_included": False,
            "synthetic_fixture_only": True,
        },
    }


def _stage(stage_id: str, name: str, passed: bool) -> dict[str, object]:
    return {"stage_id": stage_id, "name": name, "passed": bool(passed)}

#!/usr/bin/env python3
"""Run Sessions 102-110 and close Milestone M6 deterministically."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from phoenix_mmi.navigation_boundaries import build_navigation_boundary_graph
from phoenix_mmi.navigation_evidence import build_navigation_evidence_ledger
from phoenix_mmi.navigation_feasibility_audit import (
    advance_m6_progress,
    build_m6_baseline,
)
from phoenix_mmi.navigation_integration import (
    run_navigation_feasibility_integration,
)
from phoenix_mmi.navigation_knowledge import build_navigation_knowledge_matrix
from phoenix_mmi.navigation_model import (
    NavigationEdge,
    NavigationNode,
    build_neutral_navigation_graph,
    build_public_navigation_graph_summary,
)
from phoenix_mmi.navigation_provenance import (
    NavigationSource,
    build_navigation_provenance_policy,
)
from phoenix_mmi.navigation_routing import build_synthetic_routing_lab
from phoenix_mmi.osm_adapter import adapt_osm_xml, synthetic_osm_fixture


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _transition(
    capability_id: str,
    *,
    target: str,
    evidence: str,
    limitation: str,
) -> dict[str, str]:
    return {
        "capability_id": capability_id,
        "from_status": "MISSING",
        "to_status": "IMPLEMENTED",
        "probe_kind": "python-symbol",
        "probe_target": target,
        "evidence": evidence,
        "limitation": limitation,
    }


def _advance(
    repository: Path,
    previous: dict[str, object],
    *,
    session: str,
    capability_id: str,
    target: str,
    evidence: str,
    limitation: str,
    graph_version: str,
    graph_node_id: str,
    section: str,
    summary: dict[str, object],
) -> dict[str, object]:
    report = advance_m6_progress(
        repository,
        previous,
        session=session,
        transitions=[
            _transition(
                capability_id,
                target=target,
                evidence=evidence,
                limitation=limitation,
            )
        ],
        graph_version=graph_version,
        graph_node_id=graph_node_id,
    )
    report[section] = summary
    return report


def _synthetic_source(payload: bytes) -> NavigationSource:
    return NavigationSource(
        source_id="project-phoenix-m6-synthetic",
        source_kind="SYNTHETIC",
        license_id="PROJECT_PHOENIX_ORIGINAL",
        attribution="Project Phoenix synthetic fixture",
        source_uri="synthetic://project-phoenix/m6",
        snapshot_sha256=sha256(payload).hexdigest(),
    )


def _neutral_model_summary() -> dict[str, object]:
    payload = b"project-phoenix-neutral-model-session107"
    source = _synthetic_source(payload)
    nodes = [
        NavigationNode("node-a", 500_000_000, 200_000_000),
        NavigationNode("node-b", 500_001_000, 200_001_000),
        NavigationNode("node-c", 500_002_000, 200_002_000),
    ]
    edges = [
        NavigationEdge("edge-a-b", "node-a", "node-b", 1000, "synthetic", False),
        NavigationEdge("edge-b-a", "node-b", "node-a", 1000, "synthetic", False),
        NavigationEdge("edge-b-c", "node-b", "node-c", 1500, "synthetic", True),
    ]
    graph = build_neutral_navigation_graph(nodes, edges, source)
    return build_public_navigation_graph_summary(graph)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    closure_path = (
        repository
        / "research/milestones/m5/session101/milestone-m5-closure.json"
    )
    m5_closure = json.loads(closure_path.read_text(encoding="utf-8"))

    baseline_first = build_m6_baseline(repository, m5_closure)
    baseline_second = build_m6_baseline(repository, m5_closure)
    if baseline_first != baseline_second:
        raise ValueError("Session 102 baseline is not deterministic")
    _write_json(
        args.public_output / "session102/m6-capability-baseline.json",
        baseline_first,
    )

    evidence = build_navigation_evidence_ledger(repository)
    report103 = _advance(
        repository,
        baseline_first,
        session="103",
        capability_id="M6-CAP-010",
        target=(
            "phoenix_mmi.navigation_evidence:"
            "build_navigation_evidence_ledger"
        ),
        evidence="Session 103 and SPEC-112",
        limitation="ledger contains public aggregates, not map payloads",
        graph_version="v95",
        graph_node_id="m6-navigation-evidence-ledger",
        section="navigation_evidence_ledger",
        summary=evidence,
    )
    _write_json(
        args.public_output / "session103/navigation-evidence-ledger.json",
        report103,
    )

    knowledge = build_navigation_knowledge_matrix(evidence)
    report104 = _advance(
        repository,
        report103,
        session="104",
        capability_id="M6-CAP-011",
        target=(
            "phoenix_mmi.navigation_knowledge:"
            "build_navigation_knowledge_matrix"
        ),
        evidence="Session 104 and SPEC-113",
        limitation="open semantics remain explicit blockers",
        graph_version="v96",
        graph_node_id="m6-navigation-knowledge-matrix",
        section="navigation_knowledge_matrix",
        summary=knowledge,
    )
    _write_json(
        args.public_output / "session104/navigation-knowledge-matrix.json",
        report104,
    )

    boundaries = build_navigation_boundary_graph(knowledge)
    report105 = _advance(
        repository,
        report104,
        session="105",
        capability_id="M6-CAP-012",
        target=(
            "phoenix_mmi.navigation_boundaries:"
            "build_navigation_boundary_graph"
        ),
        evidence="Session 105 and SPEC-114",
        limitation="graph is static evidence, not a runtime trace",
        graph_version="v97",
        graph_node_id="m6-navigation-boundary-graph",
        section="navigation_boundary_graph",
        summary=boundaries,
    )
    _write_json(
        args.public_output / "session105/navigation-boundary-graph.json",
        report105,
    )

    provenance = build_navigation_provenance_policy()
    report106 = _advance(
        repository,
        report105,
        session="106",
        capability_id="M6-CAP-013",
        target=(
            "phoenix_mmi.navigation_provenance:"
            "build_navigation_provenance_policy"
        ),
        evidence="Session 106 and SPEC-115",
        limitation="policy is not legal advice or automatic clearance",
        graph_version="v98",
        graph_node_id="m6-open-data-provenance-policy",
        section="navigation_provenance_policy",
        summary=provenance,
    )
    _write_json(
        args.public_output / "session106/navigation-provenance-policy.json",
        report106,
    )

    neutral = _neutral_model_summary()
    report107 = _advance(
        repository,
        report106,
        session="107",
        capability_id="M6-CAP-014",
        target=(
            "phoenix_mmi.navigation_model:"
            "build_neutral_navigation_graph"
        ),
        evidence="Session 107 and SPEC-116",
        limitation="neutral graph has no proprietary target serialization",
        graph_version="v99",
        graph_node_id="m6-neutral-navigation-model",
        section="neutral_navigation_model",
        summary=neutral,
    )
    _write_json(
        args.public_output / "session107/neutral-navigation-model.json",
        report107,
    )

    osm_payload = synthetic_osm_fixture()
    _, adapter = adapt_osm_xml(osm_payload, _synthetic_source(osm_payload))
    report108 = _advance(
        repository,
        report107,
        session="108",
        capability_id="M6-CAP-015",
        target="phoenix_mmi.osm_adapter:adapt_osm_xml",
        evidence="Session 108 and SPEC-117",
        limitation="adapter excludes relations and target output",
        graph_version="v100",
        graph_node_id="m6-bounded-osm-adapter",
        section="osm_adapter",
        summary=adapter,
    )
    _write_json(
        args.public_output / "session108/bounded-osm-adapter.json",
        report108,
    )

    lab_first = build_synthetic_routing_lab()
    lab_second = build_synthetic_routing_lab()
    if lab_first != lab_second or not lab_first["passed"]:
        raise ValueError("Session 109 routing lab failed")
    lab_first["repeat_run_equal"] = True
    report109 = _advance(
        repository,
        report108,
        session="109",
        capability_id="M6-CAP-016",
        target=(
            "phoenix_mmi.navigation_routing:"
            "build_synthetic_routing_lab"
        ),
        evidence="Session 109 and SPEC-118",
        limitation="synthetic host route proof is not target compatibility",
        graph_version="v101",
        graph_node_id="m6-synthetic-routing-lab",
        section="synthetic_routing_lab",
        summary=lab_first,
    )
    _write_json(
        args.public_output / "session109/synthetic-routing-lab.json",
        report109,
    )

    integration_first = run_navigation_feasibility_integration(repository)
    integration_second = run_navigation_feasibility_integration(repository)
    if integration_first != integration_second or not integration_first["passed"]:
        raise ValueError("Session 110 M6 integration gate failed")
    report110 = _advance(
        repository,
        report109,
        session="110",
        capability_id="M6-CAP-017",
        target=(
            "phoenix_mmi.navigation_integration:"
            "run_navigation_feasibility_integration"
        ),
        evidence="Session 110 and SPEC-119",
        limitation="M7 remains controlled read-only bench planning",
        graph_version="v102",
        graph_node_id="milestone-m6-closure",
        section="integration",
        summary=integration_first,
    )
    if (
        report110["classification"]["m6_status"] != "COMPLETE"
        or report110["milestone_transition"]["m7"] != "READY"
        or report110["classification"]["safe_mutation_ready"] is not False
    ):
        raise ValueError("M6 closure transition failed")
    _write_json(
        args.public_output / "session110/milestone-m6-closure.json",
        report110,
    )

    print(
        json.dumps(
            {
                "sessions": [f"{value:03d}" for value in range(102, 111)],
                "criteria": (
                    f"{report110['exit_criteria_passed']}/"
                    f"{report110['exit_criteria_total']}"
                ),
                "m6": report110["classification"]["m6_status"],
                "m7": report110["milestone_transition"]["m7"],
                "direct_mmi_media_replacement": "BLOCKED",
                "independent_osm_host_pipeline": "PROTOTYPE_FEASIBLE",
                "integration_repeat_equal": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

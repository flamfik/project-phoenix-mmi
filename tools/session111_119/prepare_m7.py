#!/usr/bin/env python3
"""Run Sessions 111-119 and prepare the fail-closed M7 bench package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phoenix_mmi.bench_evidence import (
    build_bench_evidence_template,
    evaluate_bench_evidence_bundle,
)
from phoenix_mmi.bench_manifest import (
    build_bench_manifest_template,
    build_public_bench_manifest_summary,
)
from phoenix_mmi.bench_observation import build_bench_observation_contract
from phoenix_mmi.bench_power import build_bench_power_plan
from phoenix_mmi.bench_recovery import build_bench_recovery_plan
from phoenix_mmi.bench_risk import (
    bench_risk_fingerprint,
    build_bench_risk_register,
)
from phoenix_mmi.bench_state_machine import run_synthetic_bench_rehearsal
from phoenix_mmi.hardware_validation_audit import (
    advance_m7_progress,
    build_m7_baseline,
)
from phoenix_mmi.hardware_validation_integration import (
    run_hardware_validation_preparation_integration,
)


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
    node_id: str,
    section: str,
    summary: dict[str, object],
) -> dict[str, object]:
    report = advance_m7_progress(
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
        graph_node_id=node_id,
    )
    report[section] = summary
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    m6_path = (
        repository
        / "research/milestones/m6/session110/milestone-m6-closure.json"
    )
    m6_closure = json.loads(m6_path.read_text(encoding="utf-8"))

    baseline_first = build_m7_baseline(repository, m6_closure)
    baseline_second = build_m7_baseline(repository, m6_closure)
    if baseline_first != baseline_second:
        raise ValueError("Session 111 baseline is not deterministic")
    _write_json(
        args.public_output / "session111/m7-capability-baseline.json",
        baseline_first,
    )

    manifest = build_public_bench_manifest_summary(
        build_bench_manifest_template()
    )
    report112 = _advance(
        repository,
        baseline_first,
        session="112",
        capability_id="M7-CAP-002",
        target=(
            "phoenix_mmi.bench_manifest:"
            "build_public_bench_manifest_summary"
        ),
        evidence="Session 112 and SPEC-121",
        limitation="committed template contains no hardware identity",
        graph_version="v104",
        node_id="m7-bench-manifest",
        section="bench_manifest_summary",
        summary=manifest,
    )
    _write_json(
        args.public_output / "session112/bench-manifest-summary.json",
        report112,
    )

    power = build_bench_power_plan()
    report113 = _advance(
        repository,
        report112,
        session="113",
        capability_id="M7-CAP-003",
        target="phoenix_mmi.bench_power:build_bench_power_plan",
        evidence="Session 113 and SPEC-122",
        limitation="device limits require authoritative private references",
        graph_version="v105",
        node_id="m7-electrical-safety-plan",
        section="bench_power_plan",
        summary=power,
    )
    _write_json(
        args.public_output / "session113/bench-power-plan.json",
        report113,
    )

    recovery = build_bench_recovery_plan()
    report114 = _advance(
        repository,
        report113,
        session="114",
        capability_id="M7-CAP-004",
        target="phoenix_mmi.bench_recovery:build_bench_recovery_plan",
        evidence="Session 114 and SPEC-123",
        limitation="physical dummy-load rehearsal remains external",
        graph_version="v106",
        node_id="m7-recovery-plan",
        section="bench_recovery_plan",
        summary=recovery,
    )
    _write_json(
        args.public_output / "session114/bench-recovery-plan.json",
        report114,
    )

    observation = build_bench_observation_contract()
    report115 = _advance(
        repository,
        report114,
        session="115",
        capability_id="M7-CAP-005",
        target=(
            "phoenix_mmi.bench_observation:"
            "build_bench_observation_contract"
        ),
        evidence="Session 115 and SPEC-124",
        limitation="physical observation remains gated and unperformed",
        graph_version="v107",
        node_id="m7-observation-contract",
        section="bench_observation_contract",
        summary=observation,
    )
    _write_json(
        args.public_output / "session115/bench-observation-contract.json",
        report115,
    )

    risk = build_bench_risk_register()
    risk_summary = {
        **risk,
        "risk_register_fingerprint": bench_risk_fingerprint(risk),
    }
    report116 = _advance(
        repository,
        report115,
        session="116",
        capability_id="M7-CAP-006",
        target="phoenix_mmi.bench_risk:build_bench_risk_register",
        evidence="Session 116 and SPEC-125",
        limitation="operator and reviewer approval remains unsigned",
        graph_version="v108",
        node_id="m7-risk-register",
        section="bench_risk_register",
        summary=risk_summary,
    )
    _write_json(
        args.public_output / "session116/bench-risk-register.json",
        report116,
    )

    rehearsal_first = run_synthetic_bench_rehearsal()
    rehearsal_second = run_synthetic_bench_rehearsal()
    if rehearsal_first != rehearsal_second or not rehearsal_first["passed"]:
        raise ValueError("Session 117 synthetic rehearsal failed")
    report117 = _advance(
        repository,
        report116,
        session="117",
        capability_id="M7-CAP-007",
        target=(
            "phoenix_mmi.bench_state_machine:"
            "run_synthetic_bench_rehearsal"
        ),
        evidence="Session 117 and SPEC-126",
        limitation="pure state rehearsal is not physical hardware evidence",
        graph_version="v109",
        node_id="m7-synthetic-bench-rehearsal",
        section="synthetic_bench_rehearsal",
        summary=rehearsal_first,
    )
    _write_json(
        args.public_output / "session117/synthetic-bench-rehearsal.json",
        report117,
    )

    evidence = evaluate_bench_evidence_bundle(
        build_bench_evidence_template()
    )
    if evidence["classification"]["m7_physical_gate"] != "BLOCKED":
        raise ValueError("Session 118 empty evidence gate did not fail closed")
    report118 = _advance(
        repository,
        report117,
        session="118",
        capability_id="M7-CAP-008",
        target=(
            "phoenix_mmi.bench_evidence:"
            "evaluate_bench_evidence_bundle"
        ),
        evidence="Session 118 and SPEC-127",
        limitation="real private evidence is absent",
        graph_version="v110",
        node_id="m7-evidence-intake",
        section="bench_evidence_intake",
        summary=evidence,
    )
    _write_json(
        args.public_output / "session118/bench-evidence-intake.json",
        report118,
    )

    integration_first = run_hardware_validation_preparation_integration()
    integration_second = run_hardware_validation_preparation_integration()
    if (
        integration_first != integration_second
        or not integration_first["preparation_passed"]
        or integration_first["classification"]["m7_physical_gate"]
        != "BLOCKED"
    ):
        raise ValueError("Session 119 M7 preparation integration failed")
    report119 = _advance(
        repository,
        report118,
        session="119",
        capability_id="M7-CAP-009",
        target=(
            "phoenix_mmi.hardware_validation_integration:"
            "run_hardware_validation_preparation_integration"
        ),
        evidence="Session 119 and SPEC-128",
        limitation="Session 120 requires signed physical bench evidence",
        graph_version="v111",
        node_id="m7-preparation-integration",
        section="hardware_validation_integration",
        summary=integration_first,
    )
    if (
        report119["classification"]["m7_status"]
        != "AWAITING_BENCH_EVIDENCE"
        or report119["exit_criteria_passed"] != 8
        or report119["milestone_transition"]["next_session"] != "120"
    ):
        raise ValueError("M7 honest-stop transition failed")
    _write_json(
        args.public_output / "session119/m7-preparation-readiness.json",
        report119,
    )

    print(
        json.dumps(
            {
                "sessions": [f"{value:03d}" for value in range(111, 120)],
                "criteria": (
                    f"{report119['exit_criteria_passed']}/"
                    f"{report119['exit_criteria_total']}"
                ),
                "preparation": "8/8",
                "physical": "0/1",
                "m7": report119["classification"]["m7_status"],
                "next_session": report119["milestone_transition"][
                    "next_session"
                ],
                "hardware_powered": False,
                "vehicle_communication_performed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

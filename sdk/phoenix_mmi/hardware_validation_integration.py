"""Deterministic preparation-package integration and honest M7 verdict."""

from __future__ import annotations

from hashlib import sha256
import json

from .bench_evidence import (
    build_bench_evidence_template,
    evaluate_bench_evidence_bundle,
)
from .bench_manifest import (
    build_bench_manifest_template,
    build_public_bench_manifest_summary,
)
from .bench_observation import build_bench_observation_contract
from .bench_power import build_bench_power_plan
from .bench_recovery import build_bench_recovery_plan
from .bench_risk import build_bench_risk_register, bench_risk_fingerprint
from .bench_state_machine import run_synthetic_bench_rehearsal
from .hardware_validation_contract import build_hardware_validation_contract


HARDWARE_VALIDATION_INTEGRATION_SCHEMA = (
    "phoenix-mmi.hardware-validation-integration/v1"
)


def run_hardware_validation_preparation_integration() -> dict[str, object]:
    """Run the complete host-only M7 preparation chain twice where relevant."""

    contract = build_hardware_validation_contract()
    manifest = build_public_bench_manifest_summary(
        build_bench_manifest_template()
    )
    power = build_bench_power_plan()
    recovery = build_bench_recovery_plan()
    observation = build_bench_observation_contract()
    risk = build_bench_risk_register()
    rehearsal_first = run_synthetic_bench_rehearsal()
    rehearsal_second = run_synthetic_bench_rehearsal()
    evidence = evaluate_bench_evidence_bundle(build_bench_evidence_template())
    repeat_equal = rehearsal_first == rehearsal_second
    stages = [
        _stage("M7-I1", "fail-closed preparation contract", True),
        _stage(
            "M7-I2",
            "private identity template and safe public summary",
            manifest["complete"] is False
            and manifest["publication_safety"][
                "raw_identity_values_included"
            ]
            is False,
        ),
        _stage(
            "M7-I3",
            "electrical plan uses authoritative references",
            power["classification"]["electrical_plan_complete"]
            and not power["classification"]["device_specific_limits_known"],
        ),
        _stage(
            "M7-I4",
            "abort and recovery plan remains non-writing",
            recovery["classification"]["recovery_plan_documented"]
            and not recovery["classification"][
                "target_write_recovery_available"
            ],
        ),
        _stage(
            "M7-I5",
            "passive observation contract",
            observation["classification"]["contract_complete"]
            and not observation["classification"][
                "active_protocol_interaction_authorized"
            ],
        ),
        _stage(
            "M7-I6",
            "hazard register and unsigned approval gate",
            risk["classification"]["risk_register_complete"]
            and not risk["classification"]["bench_risk_accepted"],
        ),
        _stage(
            "M7-I7",
            "deterministic normal and abort rehearsal",
            rehearsal_first["passed"] and repeat_equal,
        ),
        _stage(
            "M7-I8",
            "physical evidence intake fails closed",
            evidence["classification"]["evidence_intake_validator"]
            == "CONFIRMED"
            and evidence["classification"]["m7_physical_gate"] == "BLOCKED",
        ),
    ]
    preparation_passed = all(row["passed"] for row in stages)
    decision = {
        "preparation_package": {
            "status": "COMPLETE" if preparation_passed else "FAILED",
            "scope": "HOST_ONLY_TEMPLATES_AND_SYNTHETIC_REHEARSAL",
        },
        "physical_bench_validation": {
            "status": "NOT_PERFORMED",
            "reason": "PRIVATE_SIGNED_ISOLATED_BENCH_EVIDENCE_ABSENT",
            "next_session": "120",
        },
        "m7": {
            "status": (
                "AWAITING_BENCH_EVIDENCE"
                if preparation_passed
                else "IN_PROGRESS"
            ),
            "m8_ready": False,
        },
    }
    summary = {
        "integration_stage_count": len(stages),
        "risk_count": risk["summary"]["risk_count"],
        "manifest_identity_field_count": manifest["metrics"][
            "identity_field_count"
        ],
        "synthetic_normal_event_count": rehearsal_first["normal_path"][
            "event_count"
        ],
        "synthetic_abort_event_count": rehearsal_first["abort_path"][
            "event_count"
        ],
        "physical_evidence_blocker_count": len(
            evidence["summary"]["blockers"]
        ),
    }
    fingerprint = sha256(
        json.dumps(
            {
                "stages": stages,
                "decision": decision,
                "summary": summary,
                "risk_fingerprint": bench_risk_fingerprint(risk),
                "rehearsal_fingerprint": rehearsal_first[
                    "rehearsal_fingerprint"
                ],
                "evidence_summary_fingerprint": evidence[
                    "summary_fingerprint"
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema": HARDWARE_VALIDATION_INTEGRATION_SCHEMA,
        "integration_version": "m7-session119-v1",
        "stages": stages,
        "stages_passed": sum(int(row["passed"]) for row in stages),
        "stages_total": len(stages),
        "preparation_passed": preparation_passed,
        "repeat_run_equal": repeat_equal,
        "decision": decision,
        "summary": summary,
        "integration_fingerprint": fingerprint,
        "classification": {
            "m7_preparation_gate": (
                "PASS" if preparation_passed else "FAIL"
            ),
            "m7_physical_gate": "BLOCKED",
            "physical_bench_validation_performed": False,
            "vehicle_operations_authorized": False,
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "publication_safety": {
            "hardware_identifiers_included": False,
            "raw_measurements_included": False,
            "private_capture_hashes_included": False,
            "signatures_included": False,
            "firmware_bytes_included": False,
            "hardware_powered": False,
            "target_firmware_execution_performed": False,
            "vehicle_communication_performed": False,
        },
    }


def _stage(stage_id: str, name: str, passed: bool) -> dict[str, object]:
    return {"stage_id": stage_id, "name": name, "passed": bool(passed)}

"""Fail-closed private evidence intake and publication-safe M7 summary."""

from __future__ import annotations

from hashlib import sha256
import json
import re


BENCH_EVIDENCE_SCHEMA = "phoenix-mmi.bench-evidence-bundle/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOP_LEVEL_FIELDS = {
    "schema",
    "bundle_version",
    "evidence_kind",
    "prerequisites",
    "observation",
    "private_capture_sha256",
    "approval_record_sha256",
    "incident_record_sha256",
}
PREREQUISITE_FIELDS = {
    "bench_manifest_complete",
    "authoritative_power_reference_verified",
    "dummy_load_recovery_rehearsal_complete",
    "observation_contract_accepted",
    "risk_review_signed_by_operator",
    "risk_review_signed_by_independent_reviewer",
    "two_person_pre_power_check_complete",
}
OBSERVATION_FIELDS = {
    "physical_observation_performed",
    "safe_shutdown_confirmed",
    "stop_condition_triggered",
    "stop_response_completed",
}


def build_bench_evidence_template() -> dict[str, object]:
    """Return an empty private-input template for future Session 120."""

    return {
        "schema": BENCH_EVIDENCE_SCHEMA,
        "bundle_version": "m7-session118-v1",
        "evidence_kind": "PHYSICAL_BENCH_PRIVATE",
        "prerequisites": {
            "bench_manifest_complete": False,
            "authoritative_power_reference_verified": False,
            "dummy_load_recovery_rehearsal_complete": False,
            "observation_contract_accepted": False,
            "risk_review_signed_by_operator": False,
            "risk_review_signed_by_independent_reviewer": False,
            "two_person_pre_power_check_complete": False,
        },
        "observation": {
            "physical_observation_performed": False,
            "safe_shutdown_confirmed": False,
            "stop_condition_triggered": False,
            "stop_response_completed": False,
        },
        "private_capture_sha256": [],
        "approval_record_sha256": None,
        "incident_record_sha256": None,
    }


def evaluate_bench_evidence_bundle(
    bundle: dict[str, object],
) -> dict[str, object]:
    """Evaluate private metadata and return no raw identifiers or evidence."""

    if bundle.get("schema") != BENCH_EVIDENCE_SCHEMA:
        raise ValueError("unsupported bench evidence schema")
    if set(bundle) != TOP_LEVEL_FIELDS:
        raise ValueError("bench evidence top-level field set differs")
    if bundle.get("evidence_kind") not in {
        "PHYSICAL_BENCH_PRIVATE",
        "SYNTHETIC_REHEARSAL",
    }:
        raise ValueError("unsupported bench evidence kind")
    prerequisites = bundle.get("prerequisites")
    observation = bundle.get("observation")
    if (
        not isinstance(prerequisites, dict)
        or set(prerequisites) != PREREQUISITE_FIELDS
        or any(
        not isinstance(value, bool) for value in prerequisites.values()
        )
    ):
        raise ValueError("invalid bench evidence prerequisites")
    if (
        not isinstance(observation, dict)
        or set(observation) != OBSERVATION_FIELDS
        or any(not isinstance(value, bool) for value in observation.values())
    ):
        raise ValueError("invalid bench observation evidence")
    hashes = bundle.get("private_capture_sha256")
    if not isinstance(hashes, list) or len(hashes) > 32 or any(
        not isinstance(value, str) or not SHA256_RE.fullmatch(value)
        for value in hashes
    ):
        raise ValueError("invalid private capture hash list")
    for field in ("approval_record_sha256", "incident_record_sha256"):
        value = bundle.get(field)
        if value is not None and (
            not isinstance(value, str) or not SHA256_RE.fullmatch(value)
        ):
            raise ValueError(f"invalid {field}")

    blockers = [
        name for name, passed in prerequisites.items() if not passed
    ]
    physical = bundle["evidence_kind"] == "PHYSICAL_BENCH_PRIVATE"
    if not observation.get("physical_observation_performed"):
        blockers.append("physical_observation_not_performed")
    if not observation.get("safe_shutdown_confirmed"):
        blockers.append("safe_shutdown_not_confirmed")
    if not hashes:
        blockers.append("capture_hashes_absent")
    if bundle.get("approval_record_sha256") is None:
        blockers.append("approval_record_hash_absent")
    if (
        observation.get("stop_condition_triggered")
        and not observation.get("stop_response_completed")
    ):
        blockers.append("stop_response_incomplete")
    if (
        observation.get("stop_condition_triggered")
        and bundle.get("incident_record_sha256") is None
    ):
        blockers.append("incident_record_hash_absent")
    physical_claim_ready = bool(physical and not blockers)
    normalized = {
        "evidence_kind": bundle["evidence_kind"],
        "prerequisite_count": len(prerequisites),
        "prerequisites_passed": sum(
            int(value) for value in prerequisites.values()
        ),
        "capture_hash_count": len(hashes),
        "blockers": sorted(set(blockers)),
        "physical_claim_ready": physical_claim_ready,
    }
    return {
        "schema": "phoenix-mmi.public-bench-evidence-summary/v1",
        "summary": normalized,
        "summary_fingerprint": sha256(
            json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "classification": {
            "evidence_intake_validator": "CONFIRMED",
            "physical_bench_evidence": (
                "ACCEPTED" if physical_claim_ready else "NOT_ACCEPTED"
            ),
            "m7_physical_gate": (
                "PASS" if physical_claim_ready else "BLOCKED"
            ),
        },
        "publication_safety": {
            "raw_capture_included": False,
            "raw_identifiers_included": False,
            "approval_signatures_included": False,
            "private_hash_values_included": False,
            "vehicle_data_included": False,
        },
    }

"""Fail-closed safety and evidence contract for Milestone M7."""

from __future__ import annotations


M7_CONTRACT_SCHEMA = "phoenix-mmi.hardware-validation-contract/v1"


def build_hardware_validation_contract() -> dict[str, object]:
    """Return the deterministic M7 preparation contract.

    The SDK may prepare and validate evidence, but it cannot power hardware or
    communicate with a vehicle. A human-controlled bench observation becomes a
    candidate only after every external prerequisite is independently met.
    """

    contract: dict[str, object] = {
        "schema": M7_CONTRACT_SCHEMA,
        "contract_version": "m7-session111-v1",
        "scope": "CONTROLLED_READ_ONLY_BENCH_PREPARATION",
        "entry_evidence": {
            "m6_status": "COMPLETE",
            "m6_exit_criteria": "8/8",
            "operational_graph_version": "v102",
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "sdk_authorized_operations": {
            "build_bench_templates": True,
            "run_synthetic_rehearsals": True,
            "validate_user_supplied_metadata": True,
            "publish_aggregate_evidence": True,
            "power_hardware": False,
            "execute_target_firmware": False,
            "transmit_vehicle_or_most_messages": False,
            "write_target_storage": False,
            "change_component_protection": False,
            "generate_installable_artifacts": False,
        },
        "external_bench_candidate": {
            "scope": "ISOLATED_ORIGINAL_HARDWARE_READ_ONLY_OBSERVATION",
            "requires_all_prerequisites": True,
            "prerequisites": [
                "HARDWARE_IDENTITY_RECORDED_PRIVATELY",
                "UNIT_CONFIRMED_DISCONNECTED_FROM_VEHICLE",
                "AUTHORITATIVE_PINOUT_AND_POWER_LIMITS_AVAILABLE",
                "CURRENT_LIMITED_REGULATED_SUPPLY",
                "INDEPENDENT_FUSED_POWER_CUTOFF",
                "POLARITY_AND_GROUND_PLAN_VERIFIED",
                "NON_INVASIVE_CAPTURE_ONLY",
                "RECOVERY_AND_ABORT_PROCEDURE_REHEARSED",
                "SIGNED_RISK_REVIEW",
                "TWO_PERSON_PRE_POWER_CHECK",
            ],
            "candidate_actions": [
                "VISUAL_INSPECTION_WITH_POWER_OFF",
                "PASSIVE_VOLTAGE_AND_CURRENT_OBSERVATION",
                "PASSIVE_DISPLAY_AND_BOOT_TIMING_OBSERVATION",
                "CONTROLLED_POWER_REMOVAL",
            ],
            "prohibited_actions": [
                "FIRMWARE_UPDATE_OR_DOWNGRADE",
                "STORAGE_WRITE_OR_ERASE",
                "SERVICE_MENU_CONFIGURATION_CHANGE",
                "COMPONENT_PROTECTION_ACCESS",
                "VEHICLE_OR_LIVE_MOST_CONNECTION",
                "DIAGNOSTIC_COMMAND_WITH_UNKNOWN_SIDE_EFFECTS",
                "BYPASS_OF_FUSE_CURRENT_LIMIT_OR_INTERLOCK",
            ],
        },
        "stop_conditions": [
            "UNEXPECTED_CURRENT_RISE",
            "REVERSE_POLARITY_OR_GROUND_UNCERTAINTY",
            "THERMAL_ODOR_SMOKE_OR_NOISE",
            "UNEXPECTED_WRITE_OR_UPDATE_PROMPT",
            "LOSS_OF_CAPTURE_OR_INDEPENDENT_CUTOFF",
            "IDENTITY_PINOUT_OR_POWER_LIMIT_MISMATCH",
            "UNPLANNED_NETWORK_OR_VEHICLE_CONNECTION",
            "ANY_OPERATOR_UNCERTAINTY",
        ],
        "evidence_policy": {
            "private_raw_evidence_required_for_physical_claim": True,
            "public_aggregate_report_allowed": True,
            "raw_identifiers_publication_allowed": False,
            "raw_vehicle_data_publication_allowed": False,
            "raw_firmware_or_storage_capture_allowed": False,
            "signed_approval_required": True,
            "physical_claim_without_evidence_allowed": False,
        },
        "classification": {
            "m7_preparation_authorized": True,
            "physical_bench_observation_authorized_now": False,
            "vehicle_operations_authorized": False,
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "publication_safety": _publication_safety(),
    }
    validate_hardware_validation_contract(contract)
    return contract


def validate_hardware_validation_contract(
    contract: dict[str, object],
) -> None:
    """Reject a contract that weakens the M7 preparation boundary."""

    if contract.get("schema") != M7_CONTRACT_SCHEMA:
        raise ValueError("unsupported M7 contract schema")
    operations = contract.get("sdk_authorized_operations")
    if not isinstance(operations, dict):
        raise ValueError("missing M7 SDK operation policy")
    forbidden = (
        "power_hardware",
        "execute_target_firmware",
        "transmit_vehicle_or_most_messages",
        "write_target_storage",
        "change_component_protection",
        "generate_installable_artifacts",
    )
    if any(operations.get(name) is not False for name in forbidden):
        raise ValueError("M7 SDK operation boundary was weakened")
    candidate = contract.get("external_bench_candidate")
    if not isinstance(candidate, dict) or (
        candidate.get("requires_all_prerequisites") is not True
        or len(candidate.get("prerequisites", [])) != 10
    ):
        raise ValueError("M7 external prerequisite gate differs")
    evidence = contract.get("evidence_policy")
    if not isinstance(evidence, dict) or (
        evidence.get("private_raw_evidence_required_for_physical_claim")
        is not True
        or evidence.get("raw_identifiers_publication_allowed") is not False
        or evidence.get("raw_vehicle_data_publication_allowed") is not False
        or evidence.get("raw_firmware_or_storage_capture_allowed") is not False
        or evidence.get("physical_claim_without_evidence_allowed") is not False
    ):
        raise ValueError("M7 evidence policy differs")
    classification = contract.get("classification")
    if not isinstance(classification, dict) or (
        classification.get("physical_bench_observation_authorized_now")
        is not False
        or classification.get("vehicle_operations_authorized") is not False
        or classification.get("safe_mutation_ready") is not False
        or classification.get("installable_artifact_ready") is not False
    ):
        raise ValueError("M7 safety classification differs")


def _publication_safety() -> dict[str, bool]:
    return {
        "hardware_identifiers_included": False,
        "vehicle_identifiers_included": False,
        "firmware_bytes_included": False,
        "storage_capture_included": False,
        "electrical_measurements_included": False,
        "signatures_included": False,
        "installable_artifacts_included": False,
        "hardware_powered": False,
        "target_firmware_execution_performed": False,
        "vehicle_communication_performed": False,
        "offline_planning_only": True,
    }

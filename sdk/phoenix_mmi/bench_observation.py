"""Read-only observation allowlist and aggregate capture contract for M7."""

from __future__ import annotations


BENCH_OBSERVATION_SCHEMA = "phoenix-mmi.bench-observation-contract/v1"


def build_bench_observation_contract() -> dict[str, object]:
    """Return the passive observation contract for a future gated bench."""

    contract: dict[str, object] = {
        "schema": BENCH_OBSERVATION_SCHEMA,
        "contract_version": "m7-session115-v1",
        "allowed_only_after_gate": [
            "POWER_OFF_VISUAL_INSPECTION",
            "SUPPLY_VOLTAGE_AGGREGATE",
            "SUPPLY_CURRENT_AGGREGATE",
            "DISPLAY_STATE_LABEL",
            "BOOT_PHASE_DURATION",
            "OPERATOR_STOP_REASON_CODE",
            "CONTROLLED_POWER_REMOVAL_CONFIRMATION",
        ],
        "never_allowed": [
            "TARGET_STORAGE_READOUT_OR_DUMP",
            "TARGET_STORAGE_WRITE_OR_ERASE",
            "FIRMWARE_UPDATE_MEDIA",
            "CONFIGURATION_CHANGE",
            "COMPONENT_PROTECTION_ACCESS",
            "ACTIVE_DIAGNOSTIC_PROBING",
            "LIVE_VEHICLE_OR_MOST_CONNECTION",
            "UNKNOWN_COMMAND_INJECTION",
        ],
        "aggregate_record_fields": [
            "PRIVATE_SESSION_FINGERPRINT",
            "GATE_RESULT",
            "OBSERVATION_SEQUENCE_NUMBER",
            "DURATION_BUCKET",
            "CURRENT_BUCKET",
            "DISPLAY_STATE_CLASS",
            "STOP_REASON_CODE",
            "SAFE_SHUTDOWN_CONFIRMED",
            "RAW_CAPTURE_SHA256",
        ],
        "private_capture_policy": {
            "raw_capture_must_remain_private": True,
            "raw_capture_hash_required": True,
            "clock_source_recorded_privately": True,
            "operator_identity_recorded_privately": True,
            "public_report_contains_aggregates_only": True,
        },
        "classification": {
            "contract_complete": True,
            "gate_satisfied": False,
            "physical_observation_performed": False,
            "active_protocol_interaction_authorized": False,
        },
        "publication_safety": {
            "raw_capture_included": False,
            "hardware_identifiers_included": False,
            "operator_identifiers_included": False,
            "vehicle_data_included": False,
            "hardware_observation_performed": False,
        },
    }
    validate_bench_observation_contract(contract)
    return contract


def validate_bench_observation_contract(
    contract: dict[str, object],
) -> None:
    """Reject active, write-capable or ungated observation contracts."""

    if contract.get("schema") != BENCH_OBSERVATION_SCHEMA:
        raise ValueError("unsupported bench observation schema")
    forbidden = set(contract.get("never_allowed", []))
    required_forbidden = {
        "TARGET_STORAGE_WRITE_OR_ERASE",
        "FIRMWARE_UPDATE_MEDIA",
        "CONFIGURATION_CHANGE",
        "COMPONENT_PROTECTION_ACCESS",
        "ACTIVE_DIAGNOSTIC_PROBING",
        "LIVE_VEHICLE_OR_MOST_CONNECTION",
    }
    if not required_forbidden.issubset(forbidden):
        raise ValueError("observation denylist is incomplete")
    policy = contract.get("private_capture_policy")
    if not isinstance(policy, dict) or not all(policy.values()):
        raise ValueError("private capture policy is incomplete")
    classification = contract.get("classification")
    if not isinstance(classification, dict) or (
        classification.get("gate_satisfied") is not False
        or classification.get("physical_observation_performed") is not False
        or classification.get("active_protocol_interaction_authorized")
        is not False
    ):
        raise ValueError("observation classification differs")

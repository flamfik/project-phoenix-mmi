"""Fail-safe abort and recovery readiness model for M7."""

from __future__ import annotations


BENCH_RECOVERY_SCHEMA = "phoenix-mmi.bench-recovery-plan/v1"


def build_bench_recovery_plan() -> dict[str, object]:
    """Return a recovery plan that never relies on an unverified write path."""

    plan: dict[str, object] = {
        "schema": BENCH_RECOVERY_SCHEMA,
        "plan_version": "m7-session114-v1",
        "recovery_scope": "POWER_AND_EVIDENCE_RECOVERY_ONLY",
        "required_capabilities": [
            "IMMEDIATE_INDEPENDENT_POWER_REMOVAL",
            "KNOWN_SAFE_DEENERGIZED_STATE",
            "HARNESS_QUARANTINE_AND_INSPECTION",
            "CAPTURE_SEALING_AFTER_ABORT",
            "INCIDENT_REVIEW_BEFORE_RETRY",
        ],
        "abort_sequence": [
            "ANNOUNCE_ABORT",
            "USE_INDEPENDENT_CUTOFF",
            "VERIFY_SUPPLY_OUTPUT_ZERO_BY_INSTRUMENT",
            "DO_NOT_TOUCH_UNTIL THERMAL_SAFE_STATE",
            "SEAL_AGGREGATE_EVENT_LOG",
            "BLOCK_RETRY_PENDING_REVIEW",
        ],
        "rehearsal_requirements": {
            "dummy_load_only": True,
            "hardware_absent": True,
            "normal_shutdown_path_rehearsed": True,
            "emergency_cutoff_path_rehearsed": True,
            "reapplication_lockout_rehearsed": True,
        },
        "explicit_non_recovery": [
            "NO_BOOTLOADER_WRITE",
            "NO_FIRMWARE_REFLASH",
            "NO_EEPROM_RESTORE",
            "NO_COMPONENT_PROTECTION_OPERATION",
            "NO_VEHICLE_ASSISTED_RECOVERY",
        ],
        "classification": {
            "recovery_plan_documented": True,
            "physical_rehearsal_performed": False,
            "target_write_recovery_available": False,
            "bench_observation_authorized": False,
        },
        "publication_safety": {
            "target_recovery_payload_included": False,
            "device_identifiers_included": False,
            "hardware_rehearsal_performed": False,
            "vehicle_operation_performed": False,
        },
    }
    validate_bench_recovery_plan(plan)
    return plan


def validate_bench_recovery_plan(plan: dict[str, object]) -> None:
    """Reject plans that imply target writes or an unrehearsed retry."""

    if plan.get("schema") != BENCH_RECOVERY_SCHEMA:
        raise ValueError("unsupported bench recovery schema")
    rehearsals = plan.get("rehearsal_requirements")
    if not isinstance(rehearsals, dict) or not all(rehearsals.values()):
        raise ValueError("recovery rehearsal contract is incomplete")
    non_recovery = set(plan.get("explicit_non_recovery", []))
    if {
        "NO_BOOTLOADER_WRITE",
        "NO_FIRMWARE_REFLASH",
        "NO_COMPONENT_PROTECTION_OPERATION",
        "NO_VEHICLE_ASSISTED_RECOVERY",
    } - non_recovery:
        raise ValueError("forbidden recovery path is not explicit")
    classification = plan.get("classification")
    if not isinstance(classification, dict) or (
        classification.get("physical_rehearsal_performed") is not False
        or classification.get("target_write_recovery_available") is not False
        or classification.get("bench_observation_authorized") is not False
    ):
        raise ValueError("bench recovery classification differs")

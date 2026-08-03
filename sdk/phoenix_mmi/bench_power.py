"""Non-numeric electrical safety plan for an M7 isolated bench."""

from __future__ import annotations


BENCH_POWER_SCHEMA = "phoenix-mmi.bench-power-plan/v1"


def build_bench_power_plan() -> dict[str, object]:
    """Describe required controls without guessing device-specific limits."""

    plan: dict[str, object] = {
        "schema": BENCH_POWER_SCHEMA,
        "plan_version": "m7-session113-v1",
        "device_specific_values": {
            "nominal_voltage": "REQUIRES_AUTHORITATIVE_SERVICE_REFERENCE",
            "current_limit": "REQUIRES_AUTHORITATIVE_SERVICE_REFERENCE",
            "fuse_rating": "REQUIRES_AUTHORITATIVE_SERVICE_REFERENCE",
            "connector_pinout": "REQUIRES_AUTHORITATIVE_SERVICE_REFERENCE",
            "values_inferred_from_forums": False,
        },
        "required_controls": [
            "REGULATED_CURRENT_LIMITED_SUPPLY",
            "INDEPENDENT_OPERATOR_POWER_CUTOFF",
            "INLINE_FUSE_AT_SOURCE",
            "POLARITY_KEYED_OR_PHYSICALLY_VERIFIED_HARNESS",
            "DOCUMENTED_SINGLE_GROUND_REFERENCE",
            "VOLTAGE_AND_CURRENT_VISIBLE_TO_OPERATOR",
            "INSULATED_EXPOSED_CONDUCTORS",
            "NON_FLAMMABLE_CLEAR_WORK_AREA",
        ],
        "pre_power_checks": [
            "SUPPLY_OUTPUT_OFF",
            "PINOUT_REFERENCE_FINGERPRINT_MATCHES_REVIEW",
            "POLARITY_CONTINUITY_CHECK_COMPLETE",
            "CURRENT_LIMIT_AND_FUSE_FROM_SAME_REFERENCE",
            "INDEPENDENT_CUTOFF_TESTED_WITH_DUMMY_LOAD",
            "TWO_PERSON_CHECK_RECORDED",
        ],
        "stop_response": [
            "REMOVE_POWER_USING_INDEPENDENT_CUTOFF",
            "DO_NOT_REAPPLY_POWER",
            "RECORD_ONLY_AGGREGATE_STOP_REASON",
            "QUARANTINE_HARNESS_UNTIL_REVIEW",
        ],
        "classification": {
            "electrical_plan_complete": True,
            "device_specific_limits_known": False,
            "hardware_power_authorized": False,
            "synthetic_or_document_review_only": True,
        },
        "publication_safety": {
            "pinout_included": False,
            "device_specific_limits_included": False,
            "hardware_measurements_included": False,
            "hardware_powered": False,
        },
    }
    validate_bench_power_plan(plan)
    return plan


def validate_bench_power_plan(plan: dict[str, object]) -> None:
    """Reject inferred limits or a plan without independent controls."""

    if plan.get("schema") != BENCH_POWER_SCHEMA:
        raise ValueError("unsupported bench power schema")
    values = plan.get("device_specific_values")
    if not isinstance(values, dict) or (
        values.get("values_inferred_from_forums") is not False
        or any(
            values.get(name) != "REQUIRES_AUTHORITATIVE_SERVICE_REFERENCE"
            for name in (
                "nominal_voltage",
                "current_limit",
                "fuse_rating",
                "connector_pinout",
            )
        )
    ):
        raise ValueError("bench power limits were guessed")
    controls = set(plan.get("required_controls", []))
    required = {
        "REGULATED_CURRENT_LIMITED_SUPPLY",
        "INDEPENDENT_OPERATOR_POWER_CUTOFF",
        "INLINE_FUSE_AT_SOURCE",
        "POLARITY_KEYED_OR_PHYSICALLY_VERIFIED_HARNESS",
    }
    if not required.issubset(controls):
        raise ValueError("bench power controls are incomplete")
    classification = plan.get("classification")
    if not isinstance(classification, dict) or (
        classification.get("hardware_power_authorized") is not False
        or classification.get("device_specific_limits_known") is not False
    ):
        raise ValueError("bench power authorization differs")

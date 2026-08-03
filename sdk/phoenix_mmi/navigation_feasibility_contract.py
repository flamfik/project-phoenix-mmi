"""Frozen safety, provenance and decision boundaries for Milestone M6."""

from __future__ import annotations


M6_CONSTRAINT_SCHEMA = "phoenix-mmi.navigation-feasibility-contract/v1"


def build_navigation_feasibility_contract() -> dict[str, object]:
    """Return the deterministic publication-safe M6 research contract."""

    contract: dict[str, object] = {
        "schema": M6_CONSTRAINT_SCHEMA,
        "contract_version": "m6-session102-v1",
        "scope": "STATIC_NAVIGATION_FEASIBILITY_RESEARCH",
        "research_inputs": {
            "allowed": [
                "REGISTERED_PUBLIC_AGGREGATE_EVIDENCE",
                "INDEPENDENTLY_LICENSED_OPEN_DATA",
                "PROJECT_PHOENIX_SYNTHETIC_FIXTURES",
            ],
            "registered_media_content_publication_allowed": False,
            "proprietary_payload_reuse_allowed": False,
            "unverified_license_mixing_allowed": False,
        },
        "osm_policy": {
            "data_license": "ODbL-1.0",
            "attribution_required": True,
            "attribution_text": "OpenStreetMap contributors",
            "copyright_url": "https://www.openstreetmap.org/copyright",
            "attribution_guideline_url": (
                "https://osmfoundation.org/wiki/Licence/"
                "Attribution_Guidelines"
            ),
            "source_snapshot_required": True,
            "source_hash_required": True,
            "derivative_database_review_required": True,
            "legal_advice_provided": False,
        },
        "authorized_operations": {
            "read_registered_public_reports": True,
            "verify_registered_artifact_identity_locally": True,
            "build_neutral_host_model": True,
            "parse_bounded_authorized_osm_xml": True,
            "route_original_or_licensed_host_data": True,
            "extract_or_publish_map_payloads": False,
            "generate_proprietary_map_payloads": False,
            "synthesize_unknown_integrity_fields": False,
            "repack_navigation_media": False,
            "generate_installable_media": False,
            "execute_firmware": False,
            "communicate_with_vehicle": False,
        },
        "decision_tracks": {
            "direct_mmi_media_replacement": {
                "required_evidence": [
                    "INNER_ROUTING_SCHEMA",
                    "COORDINATE_ENCODING",
                    "INDEX_AND_PARTITION_SEMANTICS",
                    "WRITE_MODEL",
                    "INTEGRITY_MODEL",
                    "FIRMWARE_CONSUMER_ABI",
                    "RECOVERY_VALIDATION",
                ],
                "initial_status": "BLOCKED",
            },
            "independent_osm_host_pipeline": {
                "required_evidence": [
                    "LICENSE_AND_ATTRIBUTION_POLICY",
                    "NEUTRAL_GRAPH_MODEL",
                    "BOUNDED_OSM_ADAPTER",
                    "DETERMINISTIC_ROUTE_PROOF",
                ],
                "initial_status": "OPEN",
            },
        },
        "unresolved_target_boundaries": [
            "INNER_ROUTING_SCHEMA",
            "COORDINATE_ENCODING",
            "INDEX_AND_PARTITION_SEMANTICS",
            "PROPRIETARY_WRITE_MODEL",
            "PROPRIETARY_INTEGRITY_MODEL",
            "FIRMWARE_CONSUMER_ABI",
            "TARGET_MEMORY_AND_TIMING_BUDGET",
            "RECOVERY_PATH",
        ],
        "classification": {
            "m6_scope_frozen": True,
            "direct_target_generation_authorized": False,
            "offline_host_feasibility_authorized": True,
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "publication_safety": _publication_safety(),
    }
    validate_navigation_feasibility_contract(contract)
    return contract


def validate_navigation_feasibility_contract(
    contract: dict[str, object],
) -> None:
    """Reject any M6 contract that weakens the frozen safety boundary."""

    if contract.get("schema") != M6_CONSTRAINT_SCHEMA:
        raise ValueError("unsupported M6 constraint schema")
    inputs = contract.get("research_inputs")
    if not isinstance(inputs, dict):
        raise ValueError("missing M6 input policy")
    if (
        inputs.get("registered_media_content_publication_allowed") is not False
        or inputs.get("proprietary_payload_reuse_allowed") is not False
        or inputs.get("unverified_license_mixing_allowed") is not False
    ):
        raise ValueError("M6 input policy was weakened")
    osm = contract.get("osm_policy")
    if not isinstance(osm, dict) or (
        osm.get("data_license") != "ODbL-1.0"
        or osm.get("attribution_required") is not True
        or osm.get("source_snapshot_required") is not True
        or osm.get("source_hash_required") is not True
        or osm.get("legal_advice_provided") is not False
    ):
        raise ValueError("M6 OSM provenance policy differs")
    operations = contract.get("authorized_operations")
    if not isinstance(operations, dict):
        raise ValueError("missing M6 authorization policy")
    forbidden = (
        "extract_or_publish_map_payloads",
        "generate_proprietary_map_payloads",
        "synthesize_unknown_integrity_fields",
        "repack_navigation_media",
        "generate_installable_media",
        "execute_firmware",
        "communicate_with_vehicle",
    )
    if any(operations.get(name) is not False for name in forbidden):
        raise ValueError("M6 forbidden operation was enabled")
    classification = contract.get("classification")
    if not isinstance(classification, dict) or (
        classification.get("direct_target_generation_authorized") is not False
        or classification.get("safe_mutation_ready") is not False
        or classification.get("installable_artifact_ready") is not False
    ):
        raise ValueError("M6 target safety gate differs")


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "map_payload_bytes_included": False,
        "extracted_resources_included": False,
        "raw_proprietary_names_included": False,
        "navigation_media_content_included": False,
        "vehicle_identifiers_included": False,
        "installable_artifacts_included": False,
        "firmware_execution_performed": False,
        "vehicle_communication_performed": False,
        "offline_only": True,
    }

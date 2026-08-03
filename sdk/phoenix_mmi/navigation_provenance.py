"""Machine-checkable open-data provenance and attribution policy for M6."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re


NAVIGATION_PROVENANCE_SCHEMA = "phoenix-mmi.navigation-provenance-policy/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class NavigationSource:
    source_id: str
    source_kind: str
    license_id: str
    attribution: str
    source_uri: str
    snapshot_sha256: str


def validate_navigation_source(source: NavigationSource) -> None:
    if not source.source_id or not _SHA256.fullmatch(source.snapshot_sha256):
        raise ValueError("navigation source identity is incomplete")
    if source.source_kind == "OPENSTREETMAP":
        if (
            source.license_id != "ODbL-1.0"
            or "OpenStreetMap" not in source.attribution
            or not source.source_uri.startswith(("https://", "file:"))
        ):
            raise ValueError("OpenStreetMap provenance is incomplete")
    elif source.source_kind == "SYNTHETIC":
        if (
            source.license_id != "PROJECT_PHOENIX_ORIGINAL"
            or source.source_uri != "synthetic://project-phoenix/m6"
        ):
            raise ValueError("synthetic provenance is incomplete")
    else:
        raise ValueError("unsupported navigation source kind")


def build_navigation_provenance_policy() -> dict[str, object]:
    """Return the deterministic OSM and synthetic source acceptance policy."""

    policy = {
        "schema": NAVIGATION_PROVENANCE_SCHEMA,
        "policy_version": "m6-session106-v1",
        "accepted_source_kinds": [
            {
                "source_kind": "OPENSTREETMAP",
                "license_id": "ODbL-1.0",
                "attribution_required": True,
                "snapshot_sha256_required": True,
                "source_uri_required": True,
            },
            {
                "source_kind": "SYNTHETIC",
                "license_id": "PROJECT_PHOENIX_ORIGINAL",
                "attribution_required": False,
                "snapshot_sha256_required": True,
                "source_uri_required": True,
            },
        ],
        "authoritative_references": [
            {
                "reference_id": "osm-copyright",
                "url": "https://www.openstreetmap.org/copyright",
                "purpose": "data license and attribution entry point",
            },
            {
                "reference_id": "osmf-attribution-guideline",
                "url": (
                    "https://osmfoundation.org/wiki/Licence/"
                    "Attribution_Guidelines"
                ),
                "purpose": "official attribution guidance",
            },
            {
                "reference_id": "osm-xml",
                "url": "https://wiki.openstreetmap.org/wiki/OSM_XML",
                "purpose": "OSM XML node, way and relation structure",
            },
        ],
        "required_attribution": {
            "text": "OpenStreetMap contributors",
            "license": "ODbL-1.0",
            "copyright_url": "https://www.openstreetmap.org/copyright",
        },
        "distribution_gate": {
            "provenance_record_required": True,
            "attribution_surface_required": True,
            "derivative_database_review_required": True,
            "license_compatibility_review_required": True,
            "automatic_legal_clearance": False,
        },
        "classification": {
            "policy_is_legal_advice": False,
            "real_osm_dataset_included": False,
            "synthetic_testing_authorized": True,
        },
        "publication_safety": {
            "osm_source_data_included": False,
            "map_payload_bytes_included": False,
            "vehicle_data_included": False,
            "source_credentials_included": False,
        },
    }
    validate_navigation_provenance_policy(policy)
    return policy


def build_public_source_record(source: NavigationSource) -> dict[str, str]:
    validate_navigation_source(source)
    return asdict(source)


def validate_navigation_provenance_policy(policy: dict[str, object]) -> None:
    if policy.get("schema") != NAVIGATION_PROVENANCE_SCHEMA:
        raise ValueError("unsupported navigation provenance policy")
    gate = policy.get("distribution_gate")
    if not isinstance(gate, dict) or (
        gate.get("provenance_record_required") is not True
        or gate.get("attribution_surface_required") is not True
        or gate.get("derivative_database_review_required") is not True
        or gate.get("automatic_legal_clearance") is not False
    ):
        raise ValueError("navigation distribution gate differs")
    classification = policy.get("classification")
    if not isinstance(classification, dict) or (
        classification.get("policy_is_legal_advice") is not False
        or classification.get("real_osm_dataset_included") is not False
    ):
        raise ValueError("navigation provenance classification differs")

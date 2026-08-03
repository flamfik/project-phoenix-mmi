"""Private-input/public-summary bench identity manifest for M7."""

from __future__ import annotations

from hashlib import sha256
import json


BENCH_MANIFEST_SCHEMA = "phoenix-mmi.bench-manifest/v1"
IDENTITY_FIELDS = (
    "unit_family",
    "part_number",
    "hardware_index",
    "serial_number",
    "installed_software_version",
    "connector_variant",
)


def build_bench_manifest_template() -> dict[str, object]:
    """Return a safe empty template; it contains no device identifiers."""

    manifest = {
        "schema": BENCH_MANIFEST_SCHEMA,
        "template_version": "m7-session112-v1",
        "identity": {name: None for name in IDENTITY_FIELDS},
        "isolation_assertions": {
            "disconnected_from_vehicle": False,
            "disconnected_from_live_most_ring": False,
            "no_vehicle_gateway_present": False,
            "bench_unit_ownership_confirmed": False,
        },
        "source_documents": {
            "authoritative_pinout_reference_recorded": False,
            "authoritative_power_limits_recorded": False,
            "reference_fingerprints_recorded": False,
        },
        "operator_review": {
            "identity_checked_by_operator": False,
            "identity_checked_by_reviewer": False,
        },
    }
    validate_bench_manifest(manifest, require_complete=False)
    return manifest


def validate_bench_manifest(
    manifest: dict[str, object],
    *,
    require_complete: bool,
) -> None:
    """Validate a private bench manifest without publishing its values."""

    if manifest.get("schema") != BENCH_MANIFEST_SCHEMA:
        raise ValueError("unsupported bench manifest schema")
    identity = manifest.get("identity")
    if not isinstance(identity, dict) or set(identity) != set(IDENTITY_FIELDS):
        raise ValueError("bench identity field set differs")
    for value in identity.values():
        if value is not None and (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 128
        ):
            raise ValueError("invalid bench identity value")
    for section_name in (
        "isolation_assertions",
        "source_documents",
        "operator_review",
    ):
        section = manifest.get(section_name)
        if not isinstance(section, dict) or any(
            not isinstance(value, bool) for value in section.values()
        ):
            raise ValueError(f"invalid {section_name}")
    if require_complete and (
        any(value is None for value in identity.values())
        or not all(manifest["isolation_assertions"].values())
        or not all(manifest["source_documents"].values())
        or not all(manifest["operator_review"].values())
    ):
        raise ValueError("bench manifest is incomplete")


def build_public_bench_manifest_summary(
    manifest: dict[str, object],
) -> dict[str, object]:
    """Return aggregate completeness only; never return raw identifiers."""

    validate_bench_manifest(manifest, require_complete=False)
    identity = manifest["identity"]
    isolation = manifest["isolation_assertions"]
    documents = manifest["source_documents"]
    review = manifest["operator_review"]
    normalized = {
        "identity_complete": all(value is not None for value in identity.values()),
        "isolation_checks_passed": sum(int(value) for value in isolation.values()),
        "source_checks_passed": sum(int(value) for value in documents.values()),
        "review_checks_passed": sum(int(value) for value in review.values()),
    }
    return {
        "schema": "phoenix-mmi.public-bench-manifest-summary/v1",
        "metrics": {
            "identity_field_count": len(identity),
            **normalized,
            "isolation_check_count": len(isolation),
            "source_check_count": len(documents),
            "review_check_count": len(review),
        },
        "complete": bool(
            normalized["identity_complete"]
            and normalized["isolation_checks_passed"] == len(isolation)
            and normalized["source_checks_passed"] == len(documents)
            and normalized["review_checks_passed"] == len(review)
        ),
        "summary_fingerprint": sha256(
            json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "publication_safety": {
            "raw_identity_values_included": False,
            "source_document_content_included": False,
            "vehicle_identifiers_included": False,
        },
    }

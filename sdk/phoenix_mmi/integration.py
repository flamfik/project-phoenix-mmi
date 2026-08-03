"""Deterministic sanitized-fixture integration gate for Milestone M2."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zlib

from .checksum_experiments import (
    ChecksumExperiment,
    ChecksumRegion,
    checksum_experiment_report,
    run_checksum_experiments,
)
from .format_registry import DEFAULT_FORMAT_REGISTRY
from .manifest import ArtifactManifest, ArtifactRecord, build_public_manifest_summary
from .parse_result import parse_artifact
from .schema_registry import DEFAULT_SCHEMA_REGISTRY
from .structural_diff import structural_diff


INTEGRATION_SCHEMA = "phoenix-mmi.m2-integration/v1"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def run_sanitized_integration(fixture: str | Path) -> dict[str, object]:
    """Run every M2 layer against a non-firmware Intel HEX fixture."""

    source = Path(fixture)
    data = source.read_bytes()
    record = ArtifactRecord.from_file(source, logical_id="sanitized-intel-hex")
    manifest = ArtifactManifest.build("m2-sanitized-integration", [record])
    manifest_value = manifest.to_dict()
    evidence = DEFAULT_FORMAT_REGISTRY.classify(
        data, path=source.name, size=len(data)
    )
    parsed = parse_artifact(data, path=source.name).to_dict()
    crc = zlib.crc32(data) & 0xFFFFFFFF
    experiments = (
        ChecksumExperiment(
            "whole-crc32-match",
            "CRC32/IEEE",
            ChecksumRegion("whole-file", 0, len(data)),
            crc,
        ),
        ChecksumExperiment(
            "whole-adler-observe",
            "ADLER32",
            ChecksumRegion("whole-file", 0, len(data)),
        ),
    )
    checksum = checksum_experiment_report(
        experiments, run_checksum_experiments(data, experiments)
    )
    equal_diff = structural_diff(parsed, parsed)
    changed = dict(parsed)
    changed["classification"] = "SANITIZED_CONTROL_CHANGE"
    changed_diff = structural_diff(parsed, changed)
    validations = [
        DEFAULT_SCHEMA_REGISTRY.validate(value).to_dict()
        for value in (manifest_value, parsed, checksum, equal_diff, changed_diff)
    ]
    body: dict[str, object] = {
        "schema": INTEGRATION_SCHEMA,
        "fixture_class": "SYNTHETIC_NON_FIRMWARE_INTEL_HEX",
        "manifest": build_public_manifest_summary(manifest),
        "classification": {
            "evidence_count": len(evidence),
            "primary_family": evidence[0].family if evidence else None,
            "primary_status": evidence[0].status if evidence else None,
        },
        "parser": {
            "schema": parsed["schema"],
            "family": parsed["family"],
            "fully_validated": parsed["fully_validated"],
            "region_count": parsed["region_count"],
            "region_data_included": parsed["region_data_included"],
        },
        "checksum": {
            "schema": checksum["schema"],
            "experiment_count": checksum["experiment_count"],
            "outcome_counts": checksum["outcome_counts"],
        },
        "diff": {
            "equal_control_passed": equal_diff["equal"] is True,
            "changed_control_detected": changed_diff["difference_count"] == 1,
        },
        "schema_validation": {
            "validation_count": len(validations),
            "all_valid": all(row["valid"] for row in validations),
        },
        "publication_safety": {
            "fixture_is_firmware": False,
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "source_content_hashes_included": False,
            "local_paths_included": False,
            "installable_artifacts_included": False,
            "runtime_execution_observed": False,
        },
    }
    body["integration_fingerprint"] = hashlib.sha256(_canonical(body)).hexdigest()
    body["passed"] = (
        body["classification"]["primary_family"] == "INTEL_HEX_TEXT"
        and body["classification"]["primary_status"] == "CONFIRMED"
        and body["parser"]["fully_validated"] is True
        and body["checksum"]["outcome_counts"].get("MATCH") == 1
        and body["diff"]["equal_control_passed"] is True
        and body["diff"]["changed_control_detected"] is True
        and body["schema_validation"]["all_valid"] is True
    )
    return body

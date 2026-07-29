"""Normalize existing publication-safe navigation evidence for M6."""

from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path


NAVIGATION_EVIDENCE_SCHEMA = "phoenix-mmi.navigation-evidence-ledger/v1"

_REPORTS = (
    (
        "media-structure",
        "research/navigation-media/session011/navigation-media.public.json",
        "phoenix-mmi.navigation-media/v1",
    ),
    (
        "payload-families",
        (
            "research/navigation-media/session012/"
            "navigation-payload-families.public.json"
        ),
        "phoenix-mmi.navigation-payload-families/v1",
    ),
    (
        "firmware-evidence-map",
        (
            "research/navigation-media/session060/"
            "firmware-evidence-map-v2.json"
        ),
        "phoenix-mmi.firmware-evidence-map/v2",
    ),
)


def _load_report(
    root: Path, relative_path: str, schema: str
) -> tuple[dict[str, object], str]:
    path = root / relative_path
    payload = path.read_bytes()
    report = json.loads(payload.decode("utf-8"))
    if report.get("schema") != schema:
        raise ValueError(f"unsupported evidence schema in {relative_path}")
    safety = report.get("publication_safety")
    if not isinstance(safety, dict):
        raise ValueError(f"missing publication safety in {relative_path}")
    for key, value in safety.items():
        if (
            key.endswith("_included")
            or key.endswith("_observed")
            or key.endswith("_performed")
        ) and value is not False:
            raise ValueError(f"unsafe evidence flag {key} in {relative_path}")
    return report, sha256(payload).hexdigest()


def build_navigation_evidence_ledger(
    repository_root: str | Path,
) -> dict[str, object]:
    """Build a sanitized ledger from the registered public evidence chain."""

    root = Path(repository_root)
    loaded: dict[str, dict[str, object]] = {}
    sources = []
    for evidence_id, relative_path, schema in _REPORTS:
        report, digest = _load_report(root, relative_path, schema)
        loaded[evidence_id] = report
        sources.append(
            {
                "evidence_id": evidence_id,
                "repository_path": relative_path,
                "schema": schema,
                "sha256": digest,
                "publication_safe": True,
            }
        )

    register_path = (
        root / "research/navigation-media/manifests/artifacts.csv"
    )
    with register_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 1:
        raise ValueError("M6 requires exactly one registered navigation artifact")
    registered = rows[0]
    media = loaded["media-structure"]
    payload = loaded["payload-families"]
    firmware = loaded["firmware-evidence-map"]
    media_artifact = media["artifact"]
    payload_artifact = payload["artifact"]
    identity_consistent = bool(
        media_artifact["artifact_id"] == registered["artifact_id"]
        and payload_artifact["artifact_id"] == registered["artifact_id"]
        and media_artifact["sha256"] == registered["sha256"]
        and payload_artifact["sha256"] == registered["sha256"]
        and int(media_artifact["size_bytes"]) == int(registered["size_bytes"])
    )
    if not identity_consistent:
        raise ValueError("registered navigation identity differs across evidence")

    ledger = {
        "schema": NAVIGATION_EVIDENCE_SCHEMA,
        "ledger_version": "m6-session103-v1",
        "source_reports": sources,
        "registered_artifact": {
            "artifact_id": registered["artifact_id"],
            "size_bytes": int(registered["size_bytes"]),
            "sha256": registered["sha256"],
            "provenance_status": registered["provenance_status"],
            "identity_consistent_across_reports": True,
            "local_filename_or_path_included": False,
        },
        "structural_summary": {
            "optical_filesystem": media["classification"][
                "optical_filesystem"
            ],
            "outer_container_format": media["classification"][
                "map_container_format"
            ],
            "root_file_count": media["topology"]["root_file_count"],
            "validated_container_count": media["aggregate"][
                "validated_fldb_container_count"
            ],
            "internal_record_count": media["aggregate"][
                "internal_record_count"
            ],
            "inner_payload_schema": payload["classification"][
                "inner_payload_schema"
            ],
            "partition_model": payload["classification"]["partition_model"],
            "partition_count": payload["partition_topology"][
                "partition_count"
            ],
            "routing_or_coordinate_encoding": payload["classification"][
                "routing_or_coordinate_encoding"
            ],
            "firmware_operational_model": firmware["classification"][
                "firmware_operational_model"
            ],
        },
        "confidence_boundary": {
            "registered_media_identity": "CONFIRMED_REGISTERED",
            "outer_media_structure": "CONFIRMED",
            "inner_family_structure": "CONFIRMED_PARTIAL",
            "routing_semantics": "OPEN",
            "coordinate_encoding": "OPEN",
            "firmware_consumer_abi": "OPEN",
            "write_and_integrity_model": "OPEN",
        },
        "classification": {
            "evidence_chain": "CONSISTENT_PUBLIC_AGGREGATES",
            "local_media_rehash_claimed": False,
            "direct_replacement_evidence_complete": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "map_payload_bytes_included": False,
            "raw_proprietary_names_included": False,
            "local_paths_included": False,
            "navigation_media_content_included": False,
            "source_report_hashes_only": True,
        },
    }
    validate_navigation_evidence_ledger(ledger)
    return ledger


def validate_navigation_evidence_ledger(ledger: dict[str, object]) -> None:
    if ledger.get("schema") != NAVIGATION_EVIDENCE_SCHEMA:
        raise ValueError("unsupported navigation evidence ledger")
    sources = ledger.get("source_reports")
    if not isinstance(sources, list) or len(sources) != len(_REPORTS):
        raise ValueError("navigation evidence source set differs")
    if len({row["evidence_id"] for row in sources}) != len(sources):
        raise ValueError("duplicate navigation evidence source")
    summary = ledger.get("structural_summary")
    if not isinstance(summary, dict) or (
        summary.get("root_file_count") != 7
        or summary.get("validated_container_count") != 7
        or summary.get("internal_record_count") != 3599
        or summary.get("partition_count") != 16
    ):
        raise ValueError("registered navigation structure differs")
    boundary = ledger.get("confidence_boundary")
    if not isinstance(boundary, dict) or any(
        boundary.get(key) != "OPEN"
        for key in (
            "routing_semantics",
            "coordinate_encoding",
            "firmware_consumer_abi",
            "write_and_integrity_model",
        )
    ):
        raise ValueError("navigation evidence boundary was over-promoted")

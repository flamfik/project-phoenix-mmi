#!/usr/bin/env python3
"""Build the private Session 067 manifest and public aggregate report."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath

from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.manifest import (
    ArtifactManifest,
    ArtifactRecord,
    VerificationResult,
    build_public_manifest_summary,
    write_manifest,
)
from phoenix_mmi.report import write_json
from phoenix_mmi.toolkit_audit import advance_m2_progress


DISC_IDS = ("mmi5570-cd1", "mmi5570-cd2", "mmi5570-cd3")


def _load_register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = {
            row["artifact"]: row for row in csv.DictReader(handle)
        }
    if len(rows) != 3:
        raise ValueError("Session 067 requires exactly three register rows")
    return rows


def _member_logical_id(parent_id: str, member_path: str) -> str:
    locator_id = hashlib.sha256(
        member_path.encode("utf-8")
    ).hexdigest()[:20]
    return f"{parent_id}.member-{locator_id}"


def _build_manifest(
    paths: tuple[Path, Path, Path],
    register: dict[str, dict[str, str]],
) -> tuple[
    ArtifactManifest,
    list[VerificationResult],
    dict[str, object],
]:
    artifacts: list[ArtifactRecord] = []
    verifications: list[VerificationResult] = []
    media_checks = []
    images: list[tuple[str, ISO9660Image]] = []

    for logical_id, path in zip(DISC_IDS, paths):
        if path.name not in register:
            raise ValueError(f"unregistered media artifact: {path.name}")
        registered = register[path.name]
        image = ISO9660Image(path)
        volume_label = registered.get("volume_label", "")
        root = ArtifactRecord.from_file(
            path,
            logical_id=logical_id,
            kind="media-image",
            metadata={
                "filesystem": registered.get("filesystem", ""),
                "register_status": registered.get("status", ""),
                "volume_identifier": image.volume_identifier,
            },
        )
        size_matches = root.size_bytes == int(
            registered["size_bytes"]
        )
        sha_matches = root.sha256 == registered["sha256"].lower()
        volume_matches = image.volume_identifier == volume_label
        verification = VerificationResult(
            logical_id=logical_id,
            size_matches=size_matches,
            sha256_matches=sha_matches,
        )
        if not verification.verified or not volume_matches:
            raise ValueError(
                f"registered identity mismatch for {logical_id}"
            )
        artifacts.append(root)
        verifications.append(verification)
        images.append((logical_id, image))
        media_checks.append(
            {
                "logical_id": logical_id,
                "size_matches": size_matches,
                "sha256_matches": sha_matches,
                "volume_identifier_matches": volume_matches,
            }
        )

    member_count = 0
    for parent_id, image in images:
        entries = sorted(
            (
                entry
                for entry in image.entries()
                if not entry.is_directory
            ),
            key=lambda entry: entry.path,
        )
        for entry in entries:
            chunks = (
                chunk
                for _, chunk in image.iter_entry_chunks(entry)
            )
            artifacts.append(
                ArtifactRecord.from_container_member(
                    chunks,
                    logical_id=_member_logical_id(
                        parent_id, entry.path
                    ),
                    parent_logical_id=parent_id,
                    member_path=entry.path,
                    expected_size=entry.size,
                    metadata={
                        "suffix": PurePosixPath(entry.path).suffix.upper(),
                    },
                )
            )
            member_count += 1

    manifest = ArtifactManifest.build(
        "mmi5570-registered-update-media", artifacts
    )
    local_checks = {
        "registered_media_count": len(paths),
        "registered_media_checks": media_checks,
        "container_member_count": member_count,
        "all_registered_media_verified": all(
            row.verified for row in verifications
        ),
    }
    return manifest, verifications, local_checks


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build and validate the Session 067 artifact manifest"
        )
    )
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd2", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "--public-output", type=Path, required=True
    )
    parser.add_argument(
        "--repository-root", type=Path, default=Path(".")
    )
    parser.add_argument(
        "--firmware-register",
        type=Path,
        default=Path(
            "research/firmware-5570/manifests/artifacts.csv"
        ),
    )
    parser.add_argument(
        "--previous-m2-state",
        type=Path,
        default=Path(
            "research/milestones/m2/session066/"
            "m2-toolkit-foundation.json"
        ),
    )
    args = parser.parse_args()

    paths = (
        args.firmware_cd1,
        args.firmware_cd2,
        args.firmware_cd3,
    )
    manifest, verifications, local_checks = _build_manifest(
        paths, _load_register(args.firmware_register)
    )
    public_summary = build_public_manifest_summary(
        manifest, verifications=verifications
    )
    if public_summary["container_member_count"] != 593:
        raise SystemExit(
            "registered Session 001 member count did not reproduce"
        )

    previous = json.loads(
        args.previous_m2_state.read_text(encoding="utf-8")
    )
    progress = advance_m2_progress(
        args.repository_root,
        previous,
        session="067",
        transitions=[
            {
                "capability_id": "M2-CAP-023",
                "from_status": "MISSING",
                "to_status": "IMPLEMENTED",
                "probe_kind": "python-symbol",
                "probe_target": (
                    "phoenix_mmi.manifest:ArtifactManifest"
                ),
                "evidence": "Session 067 and SPEC-075",
                "limitation": (
                    "schema v1 is read-only; public summaries omit "
                    "source identities and locators"
                ),
            }
        ],
        graph_version="v59",
        graph_node_id="m2-versioned-artifact-manifest",
    )
    progress["artifact_manifest"] = public_summary
    progress["classification"].update(
        {
            "manifest_identity_model": "PASS",
            "m2_x1": "PASS",
        }
    )
    progress["publication_safety"]["member_paths_included"] = False
    progress["publication_safety"]["source_names_included"] = False

    args.output.mkdir(parents=True, exist_ok=True)
    write_manifest(
        manifest, args.output / "mmi5570.artifact-manifest.json"
    )
    write_json(
        {
            "schema": "phoenix-mmi.session067-private-analysis/v1",
            "manifest": manifest.to_dict(),
            "registered_checks": local_checks,
            "m2_progress": progress,
        },
        args.output / "session067.analysis.json",
    )
    write_json(progress, args.public_output)
    if (
        progress["exit_criteria_passed"] != 1
        or progress["classification"]["m2_x1"] != "PASS"
    ):
        raise SystemExit("M2-X1 did not pass exclusively")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

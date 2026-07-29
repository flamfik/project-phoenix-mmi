"""Reproducible Milestone M1 closure audits.

The module verifies the three registered update media, classifies every update
member, reconstructs descriptor topology and audits documentation coverage.
It never executes firmware, extracts persistent payloads or creates update
media.
"""

from __future__ import annotations

from collections import Counter
import copy
import json
from pathlib import Path, PurePosixPath
import re
from typing import Protocol

from .iso9660 import ISO9660Image, ISOEntry
from .yim import parse_yim_envelope


_MAIN_MEMBERS = {
    "cd1": "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN",
    "cd3": "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN",
}

_SESSION001_BASELINE = {
    "cd1": {
        "artifact": "MMI-5570-4L0.998.961-cd1-3.iso",
        "volume_identifier": "H2_HI_EU_K942",
        "iso_size": 150089728,
        "file_count": 215,
        "directory_count": 332,
        "payload_bytes": 148185748,
    },
    "cd2": {
        "artifact": "MMI-5570-4L0.998.961-cd2-3.iso",
        "volume_identifier": "DISC",
        "iso_size": 98762752,
        "file_count": 93,
        "directory_count": 199,
        "payload_bytes": 95351480,
    },
    "cd3": {
        "artifact": "MMI-5570-4L0.998.961-cd3-3.iso",
        "volume_identifier": "DISK",
        "iso_size": 194539520,
        "file_count": 285,
        "directory_count": 437,
        "payload_bytes": 192171275,
    },
}

_METAINFO_BASELINE = {
    "cd1": {
        "section_count": 275,
        "device_family_count": 27,
        "payload_record_count": 213,
        "link_count": 20,
        "option_count": 14,
    },
    "cd2": {
        "section_count": 95,
        "device_family_count": 2,
        "payload_record_count": 92,
        "link_count": 0,
        "option_count": 0,
    },
    "cd3": {
        "section_count": 336,
        "device_family_count": 30,
        "payload_record_count": 284,
        "link_count": 20,
        "option_count": 1,
    },
}

_SECTION_RE = re.compile(r"^\[(.+)\]$")
_QUOTED_VALUE_RE = re.compile(r'^([^=]+?)\s*=\s*"(.*)"\s*$')
_BARE_VALUE_RE = re.compile(r"^([^=]+?)\s*=\s*(.*?)\s*$")


class _Image(Protocol):
    path: Path
    volume_identifier: str

    def sha256(self) -> str: ...

    def entries(self) -> list[ISOEntry]: ...

    def read_entry(
        self, entry: ISOEntry, offset: int, length: int
    ) -> bytes: ...

    def volume_metadata(self) -> dict[str, object]: ...


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "source_content_hashes_included": False,
        "member_paths_included": False,
        "raw_header_values_included": False,
        "raw_offsets_included": False,
        "raw_strings_included": False,
        "local_paths_included": False,
        "extracted_resources_included": False,
        "installable_artifacts_included": False,
        "runtime_execution_observed": False,
    }


def _extension(path: str) -> str:
    suffix = PurePosixPath(path).suffix.upper()
    return suffix if suffix else "[NONE]"


def audit_m1_media(
    images: dict[str, _Image],
    register: dict[str, dict[str, str]],
    *,
    baseline: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    """Reproduce the Session 001 aggregate inventory and artifact identity."""

    if sorted(images) != ["cd1", "cd2", "cd3"]:
        raise ValueError("M1 media audit requires cd1, cd2 and cd3")
    expected = baseline or _SESSION001_BASELINE
    rows = []
    for disc in ("cd1", "cd2", "cd3"):
        image = images[disc]
        registered = register.get(image.path.name)
        if registered is None:
            raise ValueError(f"unregistered update image: {image.path.name}")
        registered_identity = (
            image.path.stat().st_size == int(registered["size_bytes"])
            and image.sha256() == registered["sha256"].lower()
        )
        entries = image.entries()
        files = [entry for entry in entries if not entry.is_directory]
        directories = [entry for entry in entries if entry.is_directory]
        extension_counts = Counter(_extension(entry.path) for entry in files)
        metadata = image.volume_metadata()
        row = {
            "disc": disc,
            "registered_identity_verified": registered_identity,
            "volume_identifier": image.volume_identifier,
            "iso_size": image.path.stat().st_size,
            "logical_block_size": metadata["logical_block_size"],
            "file_count": len(files),
            "directory_count": len(directories),
            "payload_bytes": sum(entry.size for entry in files),
            "extension_counts": dict(sorted(extension_counts.items())),
        }
        reference = expected.get(disc)
        if reference is None:
            raise ValueError(f"missing baseline for {disc}")
        row["session001_aggregate_reproduced"] = all(
            row[key] == value
            for key, value in reference.items()
            if key != "artifact"
        ) and image.path.name == reference["artifact"]
        rows.append(row)
    totals = {
        "file_count": sum(int(row["file_count"]) for row in rows),
        "directory_count": sum(
            int(row["directory_count"]) for row in rows
        ),
        "payload_bytes": sum(int(row["payload_bytes"]) for row in rows),
    }
    all_reproduced = all(
        bool(row["registered_identity_verified"])
        and bool(row["session001_aggregate_reproduced"])
        and int(row["logical_block_size"]) == 2048
        for row in rows
    )
    return {
        "schema": "phoenix-mmi.m1-media-reproduction/v1",
        "analysis_mode": (
            "read-only-registered-identity-and-session001-aggregate-replay"
        ),
        "session": "061",
        "disc_count": len(rows),
        "discs": rows,
        "totals": totals,
        "classification": {
            "registered_artifact_identity": (
                "CONFIRMED" if all_reproduced else "FAILED"
            ),
            "session001_inventory": (
                "REPRODUCED" if all_reproduced else "DIFFERS"
            ),
            "media_readiness_for_m1": (
                "PASS" if all_reproduced else "FAIL"
            ),
        },
        "operational_graph_version": "v53",
        "publication_safety": _publication_safety(),
    }


def _classify_member(
    disc: str,
    image: _Image,
    entry: ISOEntry,
) -> str:
    suffix = _extension(entry.path)
    name = PurePosixPath(entry.path).name.upper()
    head = image.read_entry(entry, 0, min(entry.size, 64))
    if suffix == ".TXT" and name.startswith("METAINFO"):
        return "UPDATE_DESCRIPTOR_METAINFO"
    if suffix == ".HEX":
        return (
            "INTEL_HEX_TEXT"
            if head.lstrip().startswith(b":")
            else "OPAQUE_HEX"
        )
    if suffix == ".SW":
        return (
            "S_RECORD_STREAM"
            if head.lstrip().startswith(b"S")
            else "OPAQUE_SW"
        )
    if suffix == ".LOD":
        return "LOD_LANGUAGE_PAYLOAD"
    if suffix == ".YIM":
        data = image.read_entry(entry, 0, entry.size)
        parse_yim_envelope(data)
        return "YIM_XIM2_RESOURCE"
    if suffix == ".BIN":
        if (
            disc in _MAIN_MEMBERS
            and entry.path.casefold() == _MAIN_MEMBERS[disc].casefold()
        ):
            return "PRINCIPAL_MMI_SUPERH_IMAGE"
        if head.startswith(b"\x7fELF"):
            return "ELF_EXECUTABLE"
        if head.startswith(b"\x27\x05\x19\x56"):
            return "UBOOT_LEGACY_IMAGE"
        return "OPAQUE_BIN_PAYLOAD"
    return "UNCLASSIFIED"


_FAMILY_ROUTES = {
    "UPDATE_DESCRIPTOR_METAINFO": {
        "evidence": "Sessions 002-003",
        "next_milestone": "M2",
        "route": "descriptor checksums and package tooling",
    },
    "PRINCIPAL_MMI_SUPERH_IMAGE": {
        "evidence": "Sessions 003-010 and 053",
        "next_milestone": "M3/M4",
        "route": "resource laboratory and runtime ownership",
    },
    "ELF_EXECUTABLE": {
        "evidence": "Session 001",
        "next_milestone": "M4",
        "route": "target-specific runtime analysis",
    },
    "UBOOT_LEGACY_IMAGE": {
        "evidence": "Session 001",
        "next_milestone": "M4",
        "route": "ARM/INTEGRITY component runtime analysis",
    },
    "OPAQUE_BIN_PAYLOAD": {
        "evidence": "Sessions 001-002 and 040",
        "next_milestone": "M2/M4",
        "route": "format classification before component semantics",
    },
    "INTEL_HEX_TEXT": {
        "evidence": "Sessions 001-002 and 041",
        "next_milestone": "M2",
        "route": "validated record normalization and checksums",
    },
    "S_RECORD_STREAM": {
        "evidence": "Session 041",
        "next_milestone": "M2",
        "route": "strict record-envelope coverage",
    },
    "OPAQUE_SW": {
        "evidence": "Session 041",
        "next_milestone": "M2",
        "route": "format validation before decoding",
    },
    "LOD_LANGUAGE_PAYLOAD": {
        "evidence": "Sessions 044, 048 and 055-059",
        "next_milestone": "M2/M3",
        "route": "record model and speech-resource research",
    },
    "YIM_XIM2_RESOURCE": {
        "evidence": "Sessions 044-054",
        "next_milestone": "M2/M3",
        "route": "integrity writer and resource semantics",
    },
}


def classify_m1_members(
    images: dict[str, _Image],
) -> dict[str, object]:
    """Classify every update member into an evidence-backed analysis route."""

    family_counts: Counter[str] = Counter()
    extension_counts: Counter[str] = Counter()
    disc_counts: dict[str, Counter[str]] = {}
    for disc in ("cd1", "cd2", "cd3"):
        image = images[disc]
        counts: Counter[str] = Counter()
        for entry in image.entries():
            if entry.is_directory:
                continue
            family = _classify_member(disc, image, entry)
            family_counts[family] += 1
            counts[family] += 1
            extension_counts[_extension(entry.path)] += 1
        disc_counts[disc] = counts
    total = sum(family_counts.values())
    unclassified = family_counts["UNCLASSIFIED"]
    rows = [
        {
            "family": family,
            "artifact_count": count,
            **_FAMILY_ROUTES.get(
                family,
                {
                    "evidence": "none",
                    "next_milestone": "UNROUTED",
                    "route": "classification required",
                },
            ),
        }
        for family, count in sorted(family_counts.items())
        if count
    ]
    routed = sum(
        int(row["artifact_count"])
        for row in rows
        if row["next_milestone"] != "UNROUTED"
    )
    return {
        "schema": "phoenix-mmi.m1-artifact-routing/v1",
        "analysis_mode": (
            "read-only-bounded-signature-and-extension-family-routing"
        ),
        "session": "062",
        "artifact_count": total,
        "classified_artifact_count": total - unclassified,
        "routed_artifact_count": routed,
        "extension_counts": dict(sorted(extension_counts.items())),
        "disc_family_counts": {
            disc: dict(sorted(counts.items()))
            for disc, counts in disc_counts.items()
        },
        "families": rows,
        "classification": {
            "artifact_family_coverage": (
                "COMPLETE" if not unclassified else "INCOMPLETE"
            ),
            "deeper_analysis_routing": (
                "COMPLETE" if routed == total else "INCOMPLETE"
            ),
            "m1_artifact_understanding": (
                "PASS"
                if not unclassified and routed == total
                else "FAIL"
            ),
        },
        "operational_graph_version": "v54",
        "publication_safety": _publication_safety(),
    }


def parse_metainfo_text(text: str) -> dict[str, object]:
    """Parse the structural METAINFO hierarchy without interpreting policies."""

    sections: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        section_match = _SECTION_RE.match(line)
        if section_match:
            current = {
                "name": section_match.group(1),
                "line": line_number,
                "fields": {},
            }
            sections.append(current)
            continue
        if current is None:
            continue
        match = _QUOTED_VALUE_RE.match(line) or _BARE_VALUE_RE.match(line)
        if match:
            fields = current["fields"]
            fields[match.group(1).strip()] = (
                match.group(2).strip().strip('"')
            )
    common: dict[str, str] = {}
    devices: list[dict[str, object]] = []
    payloads: list[dict[str, object]] = []
    links: list[dict[str, object]] = []
    options: list[dict[str, object]] = []
    for section in sections:
        name = str(section["name"])
        fields = dict(section["fields"])
        parts = name.split("\\")
        if name.casefold() == "common":
            common = fields
        elif len(parts) == 1:
            devices.append(section)
        elif len(parts) >= 5:
            record = {
                "name": name,
                "parts": parts,
                "fields": fields,
            }
            if "Link" in fields:
                links.append(record)
            elif parts[4].casefold() == "options":
                options.append(record)
            else:
                payloads.append(record)
    return {
        "section_count": len(sections),
        "common": common,
        "devices": devices,
        "payloads": payloads,
        "links": links,
        "options": options,
    }


def _parse_declared_size(value: str) -> int | None:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


def _iso9660_level1_name(value: str) -> str:
    """Return the observed 8.3 alias used by the primary ISO directory."""

    path = PurePosixPath(value)
    stem = re.sub(r"[^A-Z0-9_]", "_", path.stem.upper())[:8]
    suffix = re.sub(
        r"[^A-Z0-9_]", "_", path.suffix.lstrip(".").upper()
    )[:3]
    return f"{stem}.{suffix}" if suffix else stem


def audit_update_model(
    images: dict[str, _Image],
    *,
    baseline: dict[str, dict[str, int]] | None = None,
) -> dict[str, object]:
    """Reproduce descriptor counts, member resolution and EEPROM chain."""

    expected = baseline or _METAINFO_BASELINE
    suite_exact_index: dict[tuple[str, int], set[str]] = {}
    suite_level1_index: dict[tuple[str, int], set[str]] = {}
    for indexed_disc, indexed_image in images.items():
        for indexed_entry in indexed_image.entries():
            if indexed_entry.is_directory:
                continue
            indexed_name = PurePosixPath(indexed_entry.path).name
            suite_exact_index.setdefault(
                (indexed_name.casefold(), indexed_entry.size), set()
            ).add(indexed_disc)
            suite_level1_index.setdefault(
                (
                    _iso9660_level1_name(indexed_name).casefold(),
                    indexed_entry.size,
                ),
                set(),
            ).add(indexed_disc)
    summaries = []
    private_documents: dict[str, dict[str, object]] = {}
    for disc in ("cd1", "cd2", "cd3"):
        image = images[disc]
        entries = image.entries()
        descriptors = [
            entry
            for entry in entries
            if not entry.is_directory
            and _extension(entry.path) == ".TXT"
            and PurePosixPath(entry.path).name.upper().startswith("METAINFO")
        ]
        if len(descriptors) != 1:
            raise ValueError(f"{disc} METAINFO count differs")
        descriptor = descriptors[0]
        document = parse_metainfo_text(
            image.read_entry(descriptor, 0, descriptor.size).decode(
                "latin1"
            )
        )
        private_documents[disc] = document
        file_index: dict[str, set[int]] = {}
        level1_index: dict[str, set[int]] = {}
        for entry in entries:
            if entry.is_directory:
                continue
            member_name = PurePosixPath(entry.path).name
            file_index.setdefault(member_name.casefold(), set()).add(
                entry.size
            )
            level1_index.setdefault(
                _iso9660_level1_name(member_name).casefold(), set()
            ).add(entry.size)
        exact_resolved = 0
        level1_alias_resolved = 0
        other_media_resolved = 0
        checksum_declared = 0
        for record in document["payloads"]:
            fields = record["fields"]
            filename = fields.get("FileName")
            size = _parse_declared_size(fields.get("FileSize", ""))
            exact_match = bool(
                filename
                and size is not None
                and size in file_index.get(filename.casefold(), set())
            )
            alias_match = bool(
                filename
                and size is not None
                and size
                in level1_index.get(
                    _iso9660_level1_name(filename).casefold(), set()
                )
            )
            if exact_match:
                exact_resolved += 1
            elif alias_match:
                level1_alias_resolved += 1
            elif filename and size is not None:
                suite_discs = suite_exact_index.get(
                    (filename.casefold(), size), set()
                ) | suite_level1_index.get(
                    (_iso9660_level1_name(filename).casefold(), size),
                    set(),
                )
                if suite_discs - {disc}:
                    other_media_resolved += 1
            if "CheckSum" in fields:
                checksum_declared += 1
        local_resolved = exact_resolved + level1_alias_resolved
        resolved = local_resolved + other_media_resolved
        summary = {
            "disc": disc,
            "section_count": document["section_count"],
            "device_family_count": len(document["devices"]),
            "payload_record_count": len(document["payloads"]),
            "link_count": len(document["links"]),
            "option_count": len(document["options"]),
            "payload_name_size_resolution_count": resolved,
            "payload_local_media_resolution_count": local_resolved,
            "payload_other_registered_media_resolution_count": (
                other_media_resolved
            ),
            "payload_exact_name_size_resolution_count": exact_resolved,
            "payload_iso9660_level1_alias_resolution_count": (
                level1_alias_resolved
            ),
            "payload_checksum_declaration_count": checksum_declared,
            "metafile_checksum_declared": (
                "MetafileChecksum" in document["common"]
            ),
            "eeprom_update_enabled": (
                document["common"].get(
                    "PerformEepromUpdate", ""
                ).casefold()
                == "true"
            ),
        }
        reference = expected.get(disc)
        if reference is None:
            raise ValueError(f"missing METAINFO baseline for {disc}")
        summary["session002_counts_reproduced"] = all(
            summary[key] == value for key, value in reference.items()
        )
        summary["all_payloads_resolve_in_registered_set"] = (
            resolved == len(document["payloads"])
        )
        summaries.append(summary)

    def version_crc_pairs(
        document: dict[str, object], prefix: str
    ) -> set[tuple[str, str]]:
        pairs = set()
        for record in document["payloads"]:
            fields = record["fields"]
            version = fields.get(f"{prefix}Version")
            crc = fields.get(f"{prefix}Crc")
            if version and crc:
                pairs.add((version, crc.casefold()))
        return pairs

    cd1_targets = version_crc_pairs(
        private_documents["cd1"], "EEPROMPatchTarget"
    )
    cd3_sources = version_crc_pairs(
        private_documents["cd3"], "EEPROMPatchSource"
    )
    eeprom_chain = bool(cd1_targets & cd3_sources)
    all_counts = all(
        bool(row["session002_counts_reproduced"]) for row in summaries
    )
    all_payloads = all(
        bool(row["all_payloads_resolve_in_registered_set"])
        for row in summaries
    )
    return {
        "schema": "phoenix-mmi.m1-update-model-reproduction/v1",
        "analysis_mode": (
            "read-only-metainfo-structure-name-size-and-state-chain-replay"
        ),
        "session": "063",
        "descriptors": summaries,
        "totals": {
            "section_count": sum(
                int(row["section_count"]) for row in summaries
            ),
            "device_family_count": sum(
                int(row["device_family_count"]) for row in summaries
            ),
            "payload_record_count": sum(
                int(row["payload_record_count"]) for row in summaries
            ),
            "link_count": sum(int(row["link_count"]) for row in summaries),
            "option_count": sum(
                int(row["option_count"]) for row in summaries
            ),
        },
        "cd1_target_to_cd3_source_eeprom_chain_reproduced": eeprom_chain,
        "classification": {
            "session002_descriptor_topology": (
                "REPRODUCED" if all_counts else "DIFFERS"
            ),
            "payload_record_resolution": (
                "COMPLETE" if all_payloads else "PARTIAL"
            ),
            "staged_eeprom_dependency": (
                "CONFIRMED" if eeprom_chain else "NOT_REPRODUCED"
            ),
            "m1_update_model_understanding": (
                "PASS"
                if all_counts and all_payloads and eeprom_chain
                else "FAIL"
            ),
        },
        "operational_graph_version": "v55",
        "publication_safety": _publication_safety(),
    }


def _numeric_ids(
    paths: list[Path], pattern: re.Pattern[str]
) -> list[int]:
    values = []
    for path in paths:
        match = pattern.match(path.name)
        if match:
            values.append(int(match.group(1)))
    return sorted(set(values))


def audit_m1_evidence(
    repository_root: str | Path,
    *,
    expected_session_ids: set[int] | None = None,
    expected_spec_ids: set[int] | None = None,
    expected_rq_ids: set[int] | None = None,
) -> dict[str, object]:
    """Audit documentation sequences and parse all public JSON evidence."""

    root = Path(repository_root)
    sessions = _numeric_ids(
        list((root / "docs/sessions").glob("SESSION-*.md")),
        re.compile(r"^SESSION-(\d{3})"),
    )
    specs = _numeric_ids(
        list((root / "docs/specs").glob("SPEC-*.md")),
        re.compile(r"^SPEC-(\d{3})"),
    )
    rq_text = (
        root / "docs/research-questions/README.md"
    ).read_text(encoding="utf-8")
    rqs = sorted(
        {
            int(value)
            for value in re.findall(r"\| RQ-(\d{3}) \|", rq_text)
        }
    )
    expected_sessions = expected_session_ids or (
        set(range(0, 66)) - {43}
    )
    expected_specs = expected_spec_ids or set(range(1, 74))
    expected_rqs = expected_rq_ids or set(range(1, 243))
    milestone_root = root / "research/milestones/m1"
    public_json = [
        path
        for path in (root / "research").rglob("*.json")
        if milestone_root not in path.parents
    ]
    invalid_json = 0
    for path in public_json:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            invalid_json += 1
    entrypoints = [
        root / "README.md",
        root / "sdk/README.md",
        root / "docs/000-project-charter.md",
        root / "docs/001-roadmap.md",
        root / "docs/research-questions/README.md",
        root / "docs/safety/lab-safety.md",
        root / "docs/milestones/M1-firmware-archaeology.md",
    ]
    sequence_pass = (
        set(sessions) == expected_sessions
        and set(specs) == expected_specs
        and set(rqs) == expected_rqs
    )
    gap_documented = "Session 043: not executed" in (
        root / "docs/001-roadmap.md"
    ).read_text(encoding="utf-8")
    entrypoints_pass = all(path.is_file() for path in entrypoints)
    reports_pass = bool(public_json) and not invalid_json
    overall = (
        sequence_pass
        and gap_documented
        and entrypoints_pass
        and reports_pass
    )
    return {
        "schema": "phoenix-mmi.m1-evidence-traceability/v1",
        "analysis_mode": "repository-documentation-and-json-integrity-audit",
        "session": "064",
        "session_document_count": len(sessions),
        "specification_count": len(specs),
        "research_question_count": len(rqs),
        "public_json_report_count": len(public_json),
        "invalid_public_json_count": invalid_json,
        "deliberate_session_gaps": [43],
        "deliberate_session_gap_documented": gap_documented,
        "newcomer_entrypoint_count": len(entrypoints),
        "newcomer_entrypoints_present": entrypoints_pass,
        "identifier_sequences_complete": sequence_pass,
        "classification": {
            "evidence_traceability": (
                "PASS" if overall else "FAIL"
            ),
            "undocumented_session_gaps": (
                "NONE" if gap_documented else "PRESENT"
            ),
            "public_report_parseability": (
                "PASS" if reports_pass else "FAIL"
            ),
            "m1_reproducibility_documentation": (
                "PASS" if overall else "FAIL"
            ),
        },
        "operational_graph_version": "v56",
        "publication_safety": _publication_safety(),
    }


def build_m1_closure(
    session060: dict[str, object],
    reports: list[dict[str, object]],
) -> dict[str, object]:
    """Apply the charter exit criteria without resolving out-of-scope work."""

    if session060.get("schema") != (
        "phoenix-mmi.firmware-evidence-map/v2"
    ):
        raise ValueError("unsupported Session 060 schema")
    expected_sessions = ["061", "062", "063", "064"]
    if [str(report.get("session")) for report in reports] != expected_sessions:
        raise ValueError("Sessions 061-064 report order differs")
    checks = [
        (
            "registered_media_and_inventory",
            reports[0]["classification"]["media_readiness_for_m1"]
            == "PASS",
            "Session 061",
        ),
        (
            "all_update_members_classified_and_routed",
            reports[1]["classification"]["m1_artifact_understanding"]
            == "PASS",
            "Session 062",
        ),
        (
            "update_descriptors_dependencies_and_sequence_understood",
            reports[2]["classification"][
                "m1_update_model_understanding"
            ]
            == "PASS",
            "Session 063",
        ),
        (
            "new_researcher_reproduction_path_is_explicit",
            reports[3]["classification"][
                "m1_reproducibility_documentation"
            ]
            == "PASS",
            "Session 064",
        ),
        (
            "unsafe_mutation_remains_out_of_scope",
            session060["classification"]["safe_mutation_ready"] is False,
            "Project charter and Session 060",
        ),
    ]
    criteria = [
        {"criterion": name, "passed": passed, "evidence": evidence}
        for name, passed, evidence in checks
    ]
    complete = all(passed for _, passed, _ in checks)
    graph = copy.deepcopy(session060["operational_graph"])
    node_specs = [
        (
            "m1-media-reproduction",
            "CONFIRMED",
            "reproduces-registered-media-inventory",
            "061",
        ),
        (
            "m1-artifact-routing",
            "CONFIRMED",
            "routes-every-update-member",
            "062",
        ),
        (
            "m1-update-model-reproduction",
            "CONFIRMED",
            "reproduces-descriptor-dependency-model",
            "063",
        ),
        (
            "m1-evidence-traceability",
            "CONFIRMED",
            "audits-newcomer-reproduction-path",
            "064",
        ),
        (
            "milestone-m1",
            "CONFIRMED_COMPLETE" if complete else "OPEN",
            "applies-project-charter-exit-criteria",
            "065",
        ),
    ]
    previous = "firmware-evidence-map-v2"
    for node_id, status, relation, session in node_specs:
        graph["nodes"].append(
            {
                "id": node_id,
                "status": status,
                "evidence_session": session,
            }
        )
        graph["edges"].append(
            {
                "source": previous,
                "target": node_id,
                "status": status,
                "relation": relation,
            }
        )
        previous = node_id
    graph["schema"] = "phoenix-mmi.operational-graph/v57"
    graph["node_count"] = len(graph["nodes"])
    graph["edge_count"] = len(graph["edges"])
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED")
        for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE")
        for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(
        node["status"] == "OPEN" for node in graph["nodes"]
    )
    graph["bounded_negative_edge_count"] = sum(
        "BOUNDED_NEGATIVE" in edge["status"]
        for edge in graph["edges"]
    )
    graph["disproved_edge_count"] = sum(
        "DISPROVED" in edge["status"] for edge in graph["edges"]
    )
    graph["interpretation"] = (
        "Graph v57 closes M1 under the project charter because media, "
        "inventory, update relationships, artifact routing and the newcomer "
        "reproduction path are explicit. Unresolved write, runtime, resource "
        "and navigation semantics remain deferred rather than inferred."
    )
    return {
        "schema": "phoenix-mmi.milestone-m1-closure/v1",
        "analysis_mode": "charter-exit-criteria-and-evidence-gate",
        "session": "065",
        "source_sessions": ["001-064"],
        "charter_exit_criteria": criteria,
        "criteria_passed": sum(
            int(row["passed"]) for row in criteria
        ),
        "criteria_total": len(criteria),
        "scope_correction": {
            "deep_semantic_questions_resolved_by_closure": False,
            "open_questions_reclassified_out_of_m1_scope": True,
            "reason": (
                "M1 requires reproducible archaeology and routing, not a "
                "writer, renderer, runtime owner or replacement firmware."
            ),
        },
        "deferred_work": [
            {
                "milestone": "M2",
                "domains": [
                    "YIM and METAINFO integrity algorithms",
                    "LOD record/address/integrity model",
                    "additional binary classifiers and pack tooling",
                ],
            },
            {
                "milestone": "M3",
                "domains": [
                    "pixel semantics",
                    "renderer and resource ownership",
                    "resource preview and editing laboratory",
                ],
            },
            {
                "milestone": "M4",
                "domains": [
                    "runtime linkage and loader provenance",
                    "callback and state-owner resolution",
                    "broader executable boundaries",
                ],
            },
            {
                "milestone": "M6",
                "domains": [
                    "navigation partition consumers",
                    "routing and coordinate grammars",
                    "new-map compatibility",
                ],
            },
            {
                "milestone": "M7",
                "domains": [
                    "bench recovery validation",
                    "vehicle-side observation",
                    "controlled installation safety",
                ],
            },
        ],
        "classification": {
            "milestone_m1": "COMPLETE" if complete else "BLOCKED",
            "m2_analysis_toolkit": (
                "READY_TO_START" if complete else "NOT_READY"
            ),
            "safe_mutation_ready": False,
            "installable_artifact_ready": False,
        },
        "operational_graph": graph,
        "operational_graph_version": "v57",
        "publication_safety": _publication_safety(),
    }


def load_iso_images(paths: dict[str, str | Path]) -> dict[str, ISO9660Image]:
    """Construct the three read-only ISO objects for the closure runner."""

    return {disc: ISO9660Image(path) for disc, path in paths.items()}

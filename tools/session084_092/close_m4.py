#!/usr/bin/env python3
"""Run the complete static-first Milestone M4 Runtime Research cycle."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import tempfile

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.resource_catalog import scan_embedded_xim2
from phoenix_mmi.resource_text import scan_font_candidates
from phoenix_mmi.runtime_devices import analyze_device_boundaries
from phoenix_mmi.runtime_harness import build_host_emulation_contract
from phoenix_mmi.runtime_inventory import analyze_runtime_inventory
from phoenix_mmi.runtime_ipc import analyze_ipc_contract
from phoenix_mmi.runtime_lab_audit import (
    advance_m4_progress,
    build_m4_baseline,
)
from phoenix_mmi.runtime_lab_integration import run_runtime_lab_integration
from phoenix_mmi.runtime_objects import (
    analyze_runtime_object_model,
    build_runtime_evidence_graph,
)
from phoenix_mmi.runtime_resources import analyze_resource_consumers


CD1_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU.BIN"
CD3_MEMBER = "MMI_HI/MMI/42/DEFAULT/H2_HI_EU_R1006_SH3_AUDIHI_5.BIN"


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _register(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["artifact"]: row for row in csv.DictReader(handle)}


def _verify_iso(image: ISO9660Image, row: dict[str, str]) -> None:
    if image.path.stat().st_size != int(row["size_bytes"]):
        raise ValueError(f"registered size mismatch for {image.path.name}")
    if image.sha256() != row["sha256"].lower():
        raise ValueError(f"registered SHA-256 mismatch for {image.path.name}")


def _transition(
    capability_id: str,
    *,
    target: str,
    evidence: str,
    limitation: str,
) -> dict[str, str]:
    return {
        "capability_id": capability_id,
        "from_status": "MISSING",
        "to_status": "IMPLEMENTED",
        "probe_kind": "python-symbol",
        "probe_target": target,
        "evidence": evidence,
        "limitation": limitation,
    }


def _advance(
    repository: Path,
    previous: dict[str, object],
    *,
    session: str,
    capability_id: str,
    target: str,
    evidence: str,
    limitation: str,
    graph_version: str,
    graph_node_id: str,
    section: str,
    summary: dict[str, object],
) -> dict[str, object]:
    report = advance_m4_progress(
        repository,
        previous,
        session=session,
        transitions=[
            _transition(
                capability_id,
                target=target,
                evidence=evidence,
                limitation=limitation,
            )
        ],
        graph_version=graph_version,
        graph_node_id=graph_node_id,
    )
    report[section] = summary
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware_cd1", type=Path)
    parser.add_argument("firmware_cd2", type=Path)
    parser.add_argument("firmware_cd3", type=Path)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument(
        "--firmware-register",
        type=Path,
        default=Path("research/firmware-5570/manifests/artifacts.csv"),
    )
    args = parser.parse_args()
    repository = args.repository.resolve()
    register_path = (
        args.firmware_register
        if args.firmware_register.is_absolute()
        else repository / args.firmware_register
    )
    rows = _register(register_path)
    images = {
        "cd1": ISO9660Image(args.firmware_cd1),
        "cd2": ISO9660Image(args.firmware_cd2),
        "cd3": ISO9660Image(args.firmware_cd3),
    }
    for image in images.values():
        row = rows.get(image.path.name)
        if row is None:
            raise ValueError(f"{image.path.name} is absent from the register")
        _verify_iso(image, row)

    m3 = json.loads(
        (
            repository
            / "research/milestones/m3/session083/milestone-m3-closure.json"
        ).read_text(encoding="utf-8")
    )
    report084 = build_m4_baseline(repository, m3)
    _write(
        args.public_output / "session084/m4-runtime-research-baseline.json",
        report084,
    )
    args.private_output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="phoenix-mmi-m4-") as temporary:
        readers = {}
        for release, member_path in (
            ("cd1", CD1_MEMBER),
            ("cd3", CD3_MEMBER),
        ):
            entry = images[release].find_path(member_path)
            extracted = images[release].extract(
                entry, Path(temporary) / release / Path(entry.path).name
            )
            readers[release] = BinaryReader(extracted)

        inventory, inventory_private = analyze_runtime_inventory(readers)
        _write(
            args.private_output
            / "session085/runtime-inventory.private.json",
            inventory_private,
        )
        report085 = _advance(
            repository,
            report084,
            session="085",
            capability_id="M4-CAP-010",
            target="phoenix_mmi.runtime_inventory:analyze_runtime_inventory",
            evidence="Session 085 and SPEC-093",
            limitation="actual scheduled task set and entry points remain unknown",
            graph_version="v77",
            graph_node_id="m4-task-service-inventory",
            section="runtime_inventory",
            summary=inventory,
        )
        _write(
            args.public_output / "session085/runtime-inventory-summary.json",
            report085,
        )

        ipc = analyze_ipc_contract(readers)
        report086 = _advance(
            repository,
            report085,
            session="086",
            capability_id="M4-CAP-011",
            target="phoenix_mmi.runtime_ipc:analyze_ipc_contract",
            evidence="Session 086 and SPEC-094",
            limitation="payload schemas and producer/consumer pairs remain unknown",
            graph_version="v78",
            graph_node_id="m4-ipc-contract",
            section="ipc_contract",
            summary=ipc,
        )
        _write(
            args.public_output / "session086/ipc-contract-summary.json",
            report086,
        )

        embedded = {
            release: scan_embedded_xim2(reader, release=release)
            for release, reader in readers.items()
        }
        fonts = {
            release: scan_font_candidates(reader)
            for release, reader in readers.items()
        }
        resource_consumers, resource_private = analyze_resource_consumers(
            readers, embedded, fonts
        )
        _write(
            args.private_output
            / "session087/resource-consumer-matrix.private.json",
            resource_private,
        )
        report087 = _advance(
            repository,
            report086,
            session="087",
            capability_id="M4-CAP-012",
            target="phoenix_mmi.runtime_resources:analyze_resource_consumers",
            evidence="Session 087 and SPEC-095",
            limitation="exact words do not identify a renderer or lifecycle",
            graph_version="v79",
            graph_node_id="m4-resource-consumer-matrix",
            section="resource_consumer_matrix",
            summary=resource_consumers,
        )
        _write(
            args.public_output
            / "session087/resource-consumer-matrix-summary.json",
            report087,
        )

        devices = analyze_device_boundaries(readers)
        report088 = _advance(
            repository,
            report087,
            session="088",
            capability_id="M4-CAP-013",
            target="phoenix_mmi.runtime_devices:analyze_device_boundaries",
            evidence="Session 088 and SPEC-096",
            limitation="driver entries, registers and protocols remain unknown",
            graph_version="v80",
            graph_node_id="m4-device-boundary-catalog",
            section="device_boundaries",
            summary=devices,
        )
        _write(
            args.public_output
            / "session088/device-boundary-catalog-summary.json",
            report088,
        )

        objects = analyze_runtime_object_model(
            readers, resource_consumers, devices
        )
        report089 = _advance(
            repository,
            report088,
            session="089",
            capability_id="M4-CAP-014",
            target="phoenix_mmi.runtime_objects:analyze_runtime_object_model",
            evidence="Session 089 and SPEC-097",
            limitation="pointer-shaped topology is not object identity",
            graph_version="v81",
            graph_node_id="m4-runtime-object-topology",
            section="runtime_object_model",
            summary=objects,
        )
        _write(
            args.public_output
            / "session089/runtime-object-model-summary.json",
            report089,
        )

        harness = build_host_emulation_contract()
        report090 = _advance(
            repository,
            report089,
            session="090",
            capability_id="M4-CAP-015",
            target="phoenix_mmi.runtime_harness:HostRuntimeHarness",
            evidence="Session 090 and SPEC-098",
            limitation="metadata harness is not an MMI or vehicle emulator",
            graph_version="v82",
            graph_node_id="m4-host-contract-harness",
            section="host_runtime_contract",
            summary=harness,
        )
        _write(
            args.public_output
            / "session090/host-runtime-contract-summary.json",
            report090,
        )

        graph = build_runtime_evidence_graph(
            inventory, ipc, resource_consumers, devices, objects, harness
        )
        report091 = _advance(
            repository,
            report090,
            session="091",
            capability_id="M4-CAP-016",
            target="phoenix_mmi.runtime_objects:build_runtime_evidence_graph",
            evidence="Session 091 and SPEC-099",
            limitation="dynamic runtime behavior remains unobserved",
            graph_version="v83",
            graph_node_id="m4-runtime-evidence-graph",
            section="runtime_evidence_graph",
            summary=graph,
        )
        _write(
            args.public_output
            / "session091/runtime-evidence-graph-summary.json",
            report091,
        )

        integration_first = run_runtime_lab_integration()
        integration_second = run_runtime_lab_integration()
        if integration_first != integration_second:
            raise ValueError("M4 integration output is not deterministic")
        if not integration_first["passed"]:
            raise ValueError("M4 integration gate failed")
        report092 = _advance(
            repository,
            report091,
            session="092",
            capability_id="M4-CAP-017",
            target="phoenix_mmi.runtime_lab_integration:run_runtime_lab_integration",
            evidence="Session 092 and SPEC-100",
            limitation="M5 is offline UI prototyping only",
            graph_version="v84",
            graph_node_id="milestone-m4-closure",
            section="integration",
            summary={
                **integration_first,
                "repeat_run_equal": True,
            },
        )
        if (
            report092["classification"]["m4_status"] != "COMPLETE"
            or report092["milestone_transition"]["m5"] != "READY"
        ):
            raise ValueError("M4 closure gate failed")
        _write(
            args.public_output
            / "session092/milestone-m4-closure.json",
            report092,
        )

    print(
        json.dumps(
            {
                "sessions": [f"{value:03d}" for value in range(84, 93)],
                "criteria": (
                    f"{report092['exit_criteria_passed']}/"
                    f"{report092['exit_criteria_total']}"
                ),
                "m4": report092["classification"]["m4_status"],
                "m5": report092["milestone_transition"]["m5"],
                "integration_repeat_equal": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

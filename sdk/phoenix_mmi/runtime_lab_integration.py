"""Deterministic synthetic end-to-end integration gate for Milestone M4."""

from __future__ import annotations

import hashlib
import json

from .resource_catalog import scan_embedded_xim2
from .resource_lab_integration import (
    MemoryReader,
    _synthetic_sfnt,
    build_synthetic_yim,
)
from .resource_text import scan_font_candidates
from .runtime_devices import analyze_device_boundaries
from .runtime_harness import build_host_emulation_contract
from .runtime_inventory import analyze_runtime_inventory
from .runtime_ipc import analyze_ipc_contract
from .runtime_objects import (
    analyze_runtime_object_model,
    build_runtime_evidence_graph,
)
from .runtime_resources import analyze_resource_consumers


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _synthetic_runtime_image() -> bytes:
    raster = bytes.fromhex("0000 f800 07e0 001f".replace(" ", ""))
    yim = build_synthetic_yim(raster, width=2, height=2)
    resource = yim[24:]
    prefix = (
        b"VxWorks taskSpawn taskCreate msgQCreate msgQSend msgQReceive "
        b"semMCreate semTake semGive eventSend eventReceive wdCreate wdStart "
        b"CDROM dosFs GPS route MOST socket display audio manager task event "
    )
    blob = bytearray(prefix)
    while len(blob) % 4:
        blob.append(0)
    resource_offset = len(blob)
    blob.extend(resource)
    while len(blob) % 4:
        blob.append(0)
    font_offset = len(blob)
    blob.extend(_synthetic_sfnt())
    blob.extend((0x0C000000 + resource_offset).to_bytes(4, "big"))
    blob.extend((0x0C000000 + font_offset).to_bytes(4, "big"))
    return bytes(blob)


def run_runtime_lab_integration() -> dict[str, object]:
    data = _synthetic_runtime_image()
    readers = {
        release: MemoryReader(data) for release in ("cd1", "cd3")
    }
    inventory, _ = analyze_runtime_inventory(readers)
    ipc = analyze_ipc_contract(readers)
    embedded = {
        release: scan_embedded_xim2(readers[release], release=release)
        for release in ("cd1", "cd3")
    }
    fonts = {
        release: scan_font_candidates(readers[release])
        for release in ("cd1", "cd3")
    }
    resources, _ = analyze_resource_consumers(
        readers, embedded, fonts
    )
    devices = analyze_device_boundaries(readers)
    objects = analyze_runtime_object_model(
        readers, resources, devices
    )
    harness = build_host_emulation_contract()
    graph = build_runtime_evidence_graph(
        inventory, ipc, resources, devices, objects, harness
    )
    report: dict[str, object] = {
        "schema": "phoenix-mmi.m4-runtime-lab-integration/v1",
        "fixture_class": "SYNTHETIC_NON_FIRMWARE_RUNTIME_CORPUS",
        "inventory": {
            "schema": inventory["schema"],
            "artifact_count": len(inventory["artifacts"]),
        },
        "ipc": {
            "schema": ipc["schema"],
            "family_count": len(ipc["artifacts"][0]["families"]),
        },
        "resources": {
            "schema": resources["schema"],
            "embedded_count": resources["artifacts"][0][
                "embedded_resource_count"
            ],
        },
        "devices": {
            "schema": devices["schema"],
            "family_count": devices["boundary_graph"]["node_count"],
        },
        "objects": {
            "schema": objects["schema"],
            "artifact_count": len(objects["artifacts"]),
        },
        "harness": {
            "schema": harness["schema"],
            "deterministic_fifo_gate": harness["deterministic_fifo_gate"],
        },
        "graph": {
            "schema": graph["schema"],
            "node_count": graph["node_count"],
            "edge_count": graph["edge_count"],
        },
        "publication_safety": {
            "fixture_is_firmware": False,
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "raw_strings_included": False,
            "runtime_addresses_included": False,
            "vehicle_identifiers_included": False,
            "runtime_execution_observed": False,
            "installable_artifacts_included": False,
        },
    }
    report["integration_fingerprint"] = hashlib.sha256(
        _canonical(report)
    ).hexdigest()
    report["passed"] = (
        report["inventory"]["artifact_count"] == 2
        and report["ipc"]["family_count"] == 4
        and report["resources"]["embedded_count"] == 1
        and report["devices"]["family_count"] == 7
        and report["objects"]["artifact_count"] == 2
        and report["harness"]["deterministic_fifo_gate"] is True
        and report["graph"]["node_count"] == 20
        and report["publication_safety"]["firmware_bytes_included"] is False
    )
    return report

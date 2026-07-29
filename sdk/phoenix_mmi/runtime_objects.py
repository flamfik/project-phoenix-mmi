"""Aligned pointer-shaped topology and confidence-graded runtime synthesis."""

from __future__ import annotations

from collections import Counter
import struct
from typing import Protocol


class Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...


def _pointer_topology(
    reader: Reader,
    *,
    runtime_base: int,
    band_size: int,
) -> dict[str, object]:
    if band_size <= 0 or band_size & (band_size - 1):
        raise ValueError("band size must be a positive power of two")
    data = reader.read(0, reader.size)
    aligned = data[: len(data) - len(data) % 4]
    edges: Counter[tuple[int, int]] = Counter()
    targets: Counter[int] = Counter()
    pointer_words = 0
    for index, (value,) in enumerate(struct.iter_unpack(">I", aligned)):
        if runtime_base <= value < runtime_base + reader.size:
            source_offset = index * 4
            target_offset = value - runtime_base
            source_band = source_offset // band_size
            target_band = target_offset // band_size
            edges[(source_band, target_band)] += 1
            targets[target_band] += 1
            pointer_words += 1
    return {
        "pointer_word_count": pointer_words,
        "source_target_band_edge_count": len(edges),
        "source_band_count": len({source for source, _ in edges}),
        "target_band_count": len(targets),
        "maximum_edge_multiplicity": max(edges.values(), default=0),
        "maximum_target_band_multiplicity": max(targets.values(), default=0),
        "_edge_set": set(edges),
    }


def analyze_runtime_object_model(
    readers: dict[str, Reader],
    resource_consumers: dict[str, object],
    device_boundaries: dict[str, object],
    *,
    runtime_base: int = 0x0C000000,
    band_size: int = 0x10000,
) -> dict[str, object]:
    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("runtime object analysis requires cd1 and cd3")
    private = {
        release: _pointer_topology(
            readers[release],
            runtime_base=runtime_base,
            band_size=band_size,
        )
        for release in ("cd1", "cd3")
    }
    artifacts = []
    for release in ("cd1", "cd3"):
        row = private[release]
        artifacts.append(
            {
                "artifact": release,
                **{
                    key: value
                    for key, value in row.items()
                    if not key.startswith("_")
                },
            }
        )
    left_edges = private["cd1"]["_edge_set"]
    right_edges = private["cd3"]["_edge_set"]
    return {
        "schema": "phoenix-mmi.runtime-object-model/v1",
        "analysis_mode": "aligned-runtime-range-words-and-anonymous-band-topology",
        "runtime_address_model": {
            "name": "runtime-link-base",
            "base": runtime_base,
            "status": "CONFIRMED_BOUNDED_STATIC_MODEL",
        },
        "band_size": band_size,
        "artifacts": artifacts,
        "cross_version": {
            "shared_anonymous_band_edge_count": len(
                left_edges & right_edges
            ),
            "cd1_only_anonymous_band_edge_count": len(
                left_edges - right_edges
            ),
            "cd3_only_anonymous_band_edge_count": len(
                right_edges - left_edges
            ),
        },
        "input_contracts": {
            "resource_consumer_schema": resource_consumers["schema"],
            "device_boundary_schema": device_boundaries["schema"],
        },
        "classification": {
            "runtime_address_mapping": "CONFIRMED_BOUNDED_STATIC_MODEL",
            "pointer_shaped_word_topology": "CONFIRMED_STRUCTURAL",
            "object_identity": "NOT_ESTABLISHED",
            "allocation_lifetime": "NOT_ESTABLISHED",
            "dynamic_dispatch_semantics": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "pointer_values_included": False,
            "source_offsets_included": False,
            "target_offsets_included": False,
            "firmware_bytes_included": False,
            "runtime_execution_observed": False,
        },
    }


def build_runtime_evidence_graph(
    inventory: dict[str, object],
    ipc: dict[str, object],
    resources: dict[str, object],
    devices: dict[str, object],
    objects: dict[str, object],
    harness: dict[str, object],
) -> dict[str, object]:
    nodes = [
        ("firmware-image", "CONFIRMED_STATIC_ARTIFACT"),
        ("superh-runtime", "CONFIRMED_ARCHITECTURE"),
        ("vxworks-runtime", "CONFIRMED_PLATFORM_FAMILY"),
        ("task-service-inventory", "CONFIRMED_BOUNDED_LEXICAL"),
        ("scheduled-task-set", "OPEN"),
        (
            "ipc-primitives",
            str(
                ipc["classification"][
                    "fixed_vxworks_ipc_api_vocabulary"
                ]
            ),
        ),
        ("ipc-payload-schema", "OPEN"),
        ("runtime-pointer-topology", "CONFIRMED_STRUCTURAL"),
        ("runtime-object-identity", "OPEN"),
        ("embedded-resources", "CONFIRMED_STRUCTURE"),
        ("resource-consumer", "OPEN"),
        ("standard-font-containers", "CONFIRMED_STRUCTURE"),
        ("device-boundaries", "CONFIRMED_LEXICAL_BOUNDED"),
        ("hardware-register-map", "OPEN"),
        ("vehicle-protocol-semantics", "OPEN"),
        ("optical-service", "CONFIRMED_PARTIAL"),
        ("navigation-runtime", "CONFIRMED_PARTIAL"),
        ("host-contract-harness", "CONFIRMED_SYNTHETIC_ONLY"),
        ("firmware-execution", "BLOCKED"),
        ("vehicle-communication", "BLOCKED"),
    ]
    edges = [
        ("firmware-image", "superh-runtime", "contains"),
        ("superh-runtime", "vxworks-runtime", "hosts"),
        ("vxworks-runtime", "task-service-inventory", "exposes-static-vocabulary"),
        ("task-service-inventory", "scheduled-task-set", "does-not-establish"),
        ("vxworks-runtime", "ipc-primitives", "has-fixed-probe-result"),
        ("ipc-primitives", "ipc-payload-schema", "does-not-establish"),
        ("firmware-image", "runtime-pointer-topology", "contains"),
        ("runtime-pointer-topology", "runtime-object-identity", "does-not-establish"),
        ("firmware-image", "embedded-resources", "contains"),
        ("firmware-image", "standard-font-containers", "contains"),
        ("embedded-resources", "resource-consumer", "requires"),
        ("standard-font-containers", "resource-consumer", "requires"),
        ("vxworks-runtime", "device-boundaries", "hosts-static-support-for"),
        ("device-boundaries", "hardware-register-map", "does-not-establish"),
        ("device-boundaries", "vehicle-protocol-semantics", "does-not-establish"),
        ("device-boundaries", "optical-service", "contains-partial-evidence-for"),
        ("optical-service", "navigation-runtime", "supports"),
        ("task-service-inventory", "host-contract-harness", "abstracts"),
        ("ipc-primitives", "host-contract-harness", "abstracts"),
        ("host-contract-harness", "firmware-execution", "explicitly-excludes"),
        ("host-contract-harness", "vehicle-communication", "explicitly-excludes"),
    ]
    return {
        "schema": "phoenix-mmi.runtime-evidence-graph/v1",
        "analysis_mode": "confidence-graded-static-runtime-synthesis",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": [
            {"id": node_id, "status": status} for node_id, status in nodes
        ],
        "edges": [
            {"source": source, "target": target, "relation": relation}
            for source, target, relation in edges
        ],
        "source_contracts": {
            "inventory_schema": inventory["schema"],
            "ipc_schema": ipc["schema"],
            "resource_schema": resources["schema"],
            "device_schema": devices["schema"],
            "object_schema": objects["schema"],
            "harness_schema": harness["schema"],
        },
        "classification": {
            "static_runtime_model": "CONFIRMED_PARTIAL",
            "runtime_behavior_model": "NOT_OBSERVED",
            "safe_host_abstraction": "CONFIRMED_SYNTHETIC_ONLY",
            "safe_mutation_ready": False,
        },
        "publication_safety": {
            "raw_strings_included": False,
            "firmware_bytes_included": False,
            "runtime_addresses_included": False,
            "vehicle_identifiers_included": False,
            "runtime_execution_observed": False,
            "installable_artifacts_included": False,
        },
    }

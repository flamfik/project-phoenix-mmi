"""Deterministic, I/O-free host contract harness for synthetic runtime events."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json


_BLOCKED_SERVICE_PREFIXES = (
    "can",
    "component-protection",
    "diagnostic-write",
    "immobilizer",
    "most",
    "vehicle",
)


@dataclass(frozen=True)
class ServiceContract:
    service_id: str
    accepted_event_types: tuple[str, ...]
    max_queue_depth: int = 16

    def __post_init__(self) -> None:
        if (
            not self.service_id
            or self.service_id != self.service_id.casefold()
            or any(
                self.service_id.startswith(prefix)
                for prefix in _BLOCKED_SERVICE_PREFIXES
            )
            or not self.accepted_event_types
            or tuple(sorted(set(self.accepted_event_types)))
            != self.accepted_event_types
            or not 1 <= self.max_queue_depth <= 1024
        ):
            raise ValueError("unsafe or invalid synthetic service contract")


@dataclass(frozen=True)
class RuntimeEvent:
    sequence: int
    target_service: str
    event_type: str
    payload_size: int

    def __post_init__(self) -> None:
        if (
            self.sequence < 0
            or not self.target_service
            or not self.event_type
            or not 0 <= self.payload_size <= 1_048_576
        ):
            raise ValueError("invalid synthetic runtime event")


class HostRuntimeHarness:
    """FIFO metadata router with no clocks, threads, byte payloads or I/O."""

    def __init__(self, contracts: tuple[ServiceContract, ...]) -> None:
        if not contracts:
            raise ValueError("at least one service contract is required")
        by_id = {item.service_id: item for item in contracts}
        if len(by_id) != len(contracts):
            raise ValueError("duplicate service contract")
        self._contracts = dict(sorted(by_id.items()))
        self._queues = {
            service_id: deque() for service_id in self._contracts
        }
        self._processed: list[RuntimeEvent] = []
        self._ready = False

    def start(self) -> None:
        if self._ready:
            raise RuntimeError("harness is already ready")
        self._ready = True

    def stop(self) -> None:
        self._ready = False

    def submit(self, event: RuntimeEvent) -> None:
        if not self._ready:
            raise RuntimeError("harness is not ready")
        contract = self._contracts.get(event.target_service)
        if contract is None or event.event_type not in contract.accepted_event_types:
            raise ValueError("event is outside the synthetic contract")
        queue = self._queues[event.target_service]
        if len(queue) >= contract.max_queue_depth:
            raise OverflowError("synthetic service queue is full")
        queue.append(event)

    def step(self) -> RuntimeEvent | None:
        if not self._ready:
            raise RuntimeError("harness is not ready")
        candidate = min(
            (
                queue[0]
                for queue in self._queues.values()
                if queue
            ),
            key=lambda item: item.sequence,
            default=None,
        )
        if candidate is None:
            return None
        self._queues[candidate.target_service].popleft()
        self._processed.append(candidate)
        return candidate

    def snapshot(self) -> dict[str, object]:
        state = {
            "ready": self._ready,
            "services": [
                {
                    "service_id": service_id,
                    "accepted_event_type_count": len(
                        contract.accepted_event_types
                    ),
                    "queued_event_count": len(self._queues[service_id]),
                    "max_queue_depth": contract.max_queue_depth,
                }
                for service_id, contract in self._contracts.items()
            ],
            "processed_event_count": len(self._processed),
            "processed_sequence": [
                event.sequence for event in self._processed
            ],
        }
        canonical = json.dumps(
            state, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        return {
            **state,
            "state_fingerprint": hashlib.sha256(canonical).hexdigest(),
        }


def build_host_emulation_contract() -> dict[str, object]:
    contracts = (
        ServiceContract("media-ui", ("refresh", "select")),
        ServiceContract("navigation-ui", ("position", "route-state")),
        ServiceContract("system-ui", ("input", "tick")),
    )
    harness = HostRuntimeHarness(contracts)
    harness.start()
    for event in (
        RuntimeEvent(2, "navigation-ui", "route-state", 0),
        RuntimeEvent(1, "system-ui", "input", 4),
        RuntimeEvent(3, "media-ui", "refresh", 0),
    ):
        harness.submit(event)
    while harness.step() is not None:
        pass
    snapshot = harness.snapshot()
    return {
        "schema": "phoenix-mmi.host-runtime-contract/v1",
        "fixture_class": "SYNTHETIC_METADATA_ONLY",
        "service_count": len(contracts),
        "accepted_event_type_count": sum(
            len(item.accepted_event_types) for item in contracts
        ),
        "deterministic_fifo_gate": snapshot["processed_sequence"] == [1, 2, 3],
        "state_fingerprint": snapshot["state_fingerprint"],
        "isolation_contract": {
            "firmware_loaded": False,
            "firmware_executed": False,
            "payload_bytes_retained": False,
            "wall_clock_used": False,
            "threads_used": False,
            "network_io_used": False,
            "filesystem_io_used": False,
            "vehicle_io_used": False,
            "can_most_services_allowed": False,
        },
        "classification": {
            "host_contract_harness": "CONFIRMED_SYNTHETIC_ONLY",
            "mmi_runtime_emulator": "NOT_IMPLEMENTED",
            "vehicle_simulator": "NOT_IMPLEMENTED",
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "vehicle_identifiers_included": False,
            "runtime_execution_observed": False,
            "installable_artifacts_included": False,
        },
    }

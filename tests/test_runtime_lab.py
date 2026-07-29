import json
from pathlib import Path
import unittest

from phoenix_mmi.resource_catalog import scan_embedded_xim2
from phoenix_mmi.resource_lab_integration import MemoryReader
from phoenix_mmi.resource_text import scan_font_candidates
from phoenix_mmi.runtime_devices import (
    DEVICE_FAMILIES,
    analyze_device_boundaries,
)
from phoenix_mmi.runtime_harness import (
    HostRuntimeHarness,
    RuntimeEvent,
    ServiceContract,
    build_host_emulation_contract,
)
from phoenix_mmi.runtime_inventory import analyze_runtime_inventory
from phoenix_mmi.runtime_ipc import analyze_ipc_contract
from phoenix_mmi.runtime_lab_audit import (
    M4_EXIT_CRITERIA,
    advance_m4_progress,
    build_m4_baseline,
)
from phoenix_mmi.runtime_lab_integration import (
    _synthetic_runtime_image,
    run_runtime_lab_integration,
)
from phoenix_mmi.runtime_objects import (
    analyze_runtime_object_model,
    build_runtime_evidence_graph,
)
from phoenix_mmi.runtime_resources import analyze_resource_consumers


def _readers(data: bytes) -> dict[str, MemoryReader]:
    return {release: MemoryReader(data) for release in ("cd1", "cd3")}


def _m3_closure() -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.m3-resource-lab-progress/v1",
        "classification": {
            "m3_status": "COMPLETE",
            "m3_exit": "PASS",
            "safe_mutation_ready": False,
        },
        "milestone_transition": {"m4": "READY"},
    }


class RuntimeInventoryTests(unittest.TestCase):
    def test_inventory_reports_fixed_families_without_raw_strings(self):
        report, private = analyze_runtime_inventory(
            _readers(
                b"VxWorks taskSpawn task manager event timer "
                b"msgQCreate semTake wdStart"
            )
        )
        self.assertEqual(report["schema"], "phoenix-mmi.runtime-inventory/v1")
        self.assertEqual(len(report["artifacts"]), 2)
        serialized = json.dumps(report)
        self.assertNotIn("taskSpawn", serialized)
        self.assertFalse(report["publication_safety"]["raw_strings_included"])
        self.assertIn("taskSpawn", json.dumps(private))

    def test_inventory_does_not_count_identifier_substrings(self):
        report, _ = analyze_runtime_inventory(
            _readers(b"xtaskSpawny service manager")
        )
        task_family = next(
            row
            for row in report["artifacts"][0]["api_families"]
            if row["family"] == "TASK_LIFECYCLE"
        )
        self.assertEqual(task_family["present_probe_count"], 0)

    def test_inventory_requires_both_releases(self):
        with self.assertRaises(ValueError):
            analyze_runtime_inventory({"cd1": MemoryReader(b"task")})


class RuntimeIpcTests(unittest.TestCase):
    def test_fixed_ipc_probe_can_be_confirmed_on_synthetic_data(self):
        report = analyze_ipc_contract(
            _readers(b"msgQCreate msgQSend semMCreate semTake eventSend wdStart")
        )
        self.assertEqual(
            report["classification"]["fixed_vxworks_ipc_api_vocabulary"],
            "CONFIRMED_BOUNDED",
        )
        self.assertIn(
            "MESSAGE_QUEUE", report["cross_version"]["shared_present_families"]
        )
        self.assertEqual(
            report["classification"]["ipc_primitive_vocabulary"],
            "NOT_ESTABLISHED",
        )

    def test_negative_fixed_probe_result_is_first_class(self):
        report = analyze_ipc_contract(
            _readers(b"queue event mutex timer manager")
        )
        self.assertEqual(
            report["classification"]["fixed_vxworks_ipc_api_vocabulary"],
            "NOT_FOUND_UNDER_FIXED_PROBE_SET",
        )
        self.assertGreater(report["artifacts"][0]["ipc_label_record_count"], 0)

    def test_ipc_terms_do_not_match_inside_unrelated_words(self):
        report = analyze_ipc_contract(_readers(b"prevent block prequeue"))
        self.assertEqual(report["artifacts"][0]["ipc_label_record_count"], 0)

    def test_ipc_report_excludes_offsets_and_raw_strings(self):
        report = analyze_ipc_contract(_readers(b"msgQCreate queue"))
        serialized = json.dumps(report)
        self.assertNotIn("msgQCreate", serialized)
        self.assertFalse(report["publication_safety"]["offsets_included"])


class RuntimeResourceTests(unittest.TestCase):
    def setUp(self):
        self.data = _synthetic_runtime_image()
        self.readers = _readers(self.data)
        self.embedded = {
            release: scan_embedded_xim2(self.readers[release], release=release)
            for release in ("cd1", "cd3")
        }
        self.fonts = {
            release: scan_font_candidates(self.readers[release])
            for release in ("cd1", "cd3")
        }

    def test_resource_and_font_targets_are_structurally_counted(self):
        report, private = analyze_resource_consumers(
            self.readers, self.embedded, self.fonts
        )
        row = report["artifacts"][0]
        self.assertEqual(row["embedded_resource_count"], 1)
        self.assertEqual(row["validated_font_container_count"], 1)
        self.assertGreater(row["resource_literal_word_occurrence_count"], 0)
        self.assertGreater(row["font_literal_word_occurrence_count"], 0)
        self.assertIn("resource_profiles", private["artifacts"]["cd1"])

    def test_address_words_do_not_assign_renderer(self):
        report, _ = analyze_resource_consumers(
            self.readers, self.embedded, self.fonts
        )
        self.assertEqual(
            report["classification"]["renderer_consumer_identity"],
            "NOT_ESTABLISHED",
        )
        self.assertFalse(report["classification"]["runtime_rendering_observed"])

    def test_public_resource_consumer_report_has_no_offsets_or_hashes(self):
        report, _ = analyze_resource_consumers(
            self.readers, self.embedded, self.fonts
        )
        self.assertFalse(report["publication_safety"]["resource_offsets_included"])
        self.assertFalse(report["publication_safety"]["resource_hashes_included"])


class RuntimeDeviceAndObjectTests(unittest.TestCase):
    def test_all_fixed_device_families_are_cataloged(self):
        data = (
            b"audio DSP display screen dosFs flash navigation GPS map "
            b"socket TCP CDROM optical MOST CAN ringbreak"
        )
        report = analyze_device_boundaries(_readers(data))
        self.assertEqual(
            report["boundary_graph"]["node_count"], len(DEVICE_FAMILIES)
        )
        self.assertEqual(
            report["cross_version"]["bilaterally_present_family_count"],
            len(DEVICE_FAMILIES),
        )
        self.assertFalse(report["publication_safety"]["raw_strings_included"])

    def test_device_catalog_does_not_claim_driver_or_registers(self):
        report = analyze_device_boundaries(_readers(b"CDROM MOST GPS"))
        self.assertEqual(
            report["classification"]["driver_entry_points"], "NOT_ESTABLISHED"
        )
        self.assertEqual(
            report["classification"]["hardware_register_map"], "NOT_ESTABLISHED"
        )

    def test_short_device_terms_do_not_match_inside_unrelated_words(self):
        report = analyze_device_boundaries(_readers(b"SCAN monkey bitmap"))
        vehicle = next(
            row
            for row in report["artifacts"][0]["families"]
            if row["family"] == "VEHICLE_NETWORK"
        )
        display = next(
            row
            for row in report["artifacts"][0]["families"]
            if row["family"] == "DISPLAY_INPUT"
        )
        navigation = next(
            row
            for row in report["artifacts"][0]["families"]
            if row["family"] == "NAVIGATION_GPS"
        )
        self.assertEqual(vehicle["unique_lexical_record_count"], 0)
        self.assertEqual(display["unique_lexical_record_count"], 0)
        self.assertEqual(navigation["unique_lexical_record_count"], 0)

    def test_pointer_topology_is_anonymous_and_structural(self):
        data = (
            b"\x00" * 16
            + (0x0C000000).to_bytes(4, "big")
            + (0x0C000010).to_bytes(4, "big")
        )
        placeholder = {"schema": "test/v1"}
        report = analyze_runtime_object_model(
            _readers(data), placeholder, placeholder, band_size=16
        )
        self.assertEqual(report["artifacts"][0]["pointer_word_count"], 2)
        self.assertEqual(
            report["classification"]["object_identity"], "NOT_ESTABLISHED"
        )
        self.assertFalse(report["publication_safety"]["pointer_values_included"])

    def test_pointer_topology_rejects_non_power_of_two_band(self):
        placeholder = {"schema": "test/v1"}
        with self.assertRaises(ValueError):
            analyze_runtime_object_model(
                _readers(b"\x00" * 32),
                placeholder,
                placeholder,
                band_size=24,
            )


class RuntimeHarnessTests(unittest.TestCase):
    def test_contract_rejects_vehicle_and_most_services(self):
        for service_id in ("vehicle-bus", "most-control", "can-reader"):
            with self.assertRaises(ValueError):
                ServiceContract(service_id, ("event",))

    def test_contract_requires_sorted_unique_event_types(self):
        with self.assertRaises(ValueError):
            ServiceContract("ui", ("tick", "input"))
        with self.assertRaises(ValueError):
            ServiceContract("ui", ("input", "input"))

    def test_harness_requires_start_and_valid_event(self):
        harness = HostRuntimeHarness((ServiceContract("ui", ("input",)),))
        with self.assertRaises(RuntimeError):
            harness.submit(RuntimeEvent(0, "ui", "input", 0))
        harness.start()
        with self.assertRaises(ValueError):
            harness.submit(RuntimeEvent(0, "ui", "unknown", 0))

    def test_harness_enforces_queue_bound(self):
        harness = HostRuntimeHarness(
            (ServiceContract("ui", ("input",), max_queue_depth=1),)
        )
        harness.start()
        harness.submit(RuntimeEvent(0, "ui", "input", 0))
        with self.assertRaises(OverflowError):
            harness.submit(RuntimeEvent(1, "ui", "input", 0))

    def test_harness_processes_global_head_sequence_deterministically(self):
        harness = HostRuntimeHarness(
            (
                ServiceContract("a", ("event",)),
                ServiceContract("b", ("event",)),
            )
        )
        harness.start()
        harness.submit(RuntimeEvent(2, "a", "event", 0))
        harness.submit(RuntimeEvent(1, "b", "event", 0))
        self.assertEqual(harness.step().sequence, 1)
        self.assertEqual(harness.step().sequence, 2)
        self.assertIsNone(harness.step())
        self.assertEqual(harness.snapshot()["processed_sequence"], [1, 2])

    def test_host_contract_uses_no_io_or_firmware(self):
        report = build_host_emulation_contract()
        self.assertTrue(report["deterministic_fifo_gate"])
        self.assertFalse(report["isolation_contract"]["firmware_executed"])
        self.assertFalse(report["isolation_contract"]["vehicle_io_used"])
        self.assertEqual(
            report["classification"]["mmi_runtime_emulator"],
            "NOT_IMPLEMENTED",
        )


class RuntimeAuditAndIntegrationTests(unittest.TestCase):
    def test_m4_baseline_passes_entry_but_not_exit(self):
        baseline = build_m4_baseline(Path(__file__).parents[1], _m3_closure())
        self.assertEqual(baseline["session"], "084")
        self.assertEqual(baseline["exit_criteria_total"], len(M4_EXIT_CRITERIA))
        self.assertEqual(baseline["exit_criteria_passed"], 0)
        self.assertEqual(baseline["classification"]["m4_status"], "IN_PROGRESS")
        self.assertFalse(baseline["classification"]["safe_mutation_ready"])

    def test_m4_baseline_rejects_bad_entry(self):
        closure = _m3_closure()
        closure["milestone_transition"] = {"m4": "BLOCKED"}
        with self.assertRaises(ValueError):
            build_m4_baseline(Path(__file__).parents[1], closure)

    def test_progress_advances_one_capability_without_mutating_baseline(self):
        baseline = build_m4_baseline(Path(__file__).parents[1], _m3_closure())
        advanced = advance_m4_progress(
            Path(__file__).parents[1],
            baseline,
            session="085",
            transitions=[
                {
                    "capability_id": "M4-CAP-010",
                    "from_status": "MISSING",
                    "to_status": "IMPLEMENTED",
                    "probe_kind": "python-symbol",
                    "probe_target": (
                        "phoenix_mmi.runtime_inventory:"
                        "analyze_runtime_inventory"
                    ),
                    "evidence": "test",
                    "limitation": "test",
                }
            ],
            graph_version="v77",
            graph_node_id="test",
        )
        self.assertEqual(advanced["exit_criteria_passed"], 1)
        self.assertEqual(baseline["exit_criteria_passed"], 0)

    def test_progress_rejects_stale_transition(self):
        baseline = build_m4_baseline(Path(__file__).parents[1], _m3_closure())
        with self.assertRaises(ValueError):
            advance_m4_progress(
                Path(__file__).parents[1],
                baseline,
                session="085",
                transitions=[
                    {
                        "capability_id": "M4-CAP-010",
                        "from_status": "IMPLEMENTED",
                        "to_status": "IMPLEMENTED",
                        "probe_kind": "python-symbol",
                        "probe_target": (
                            "phoenix_mmi.runtime_inventory:"
                            "analyze_runtime_inventory"
                        ),
                        "evidence": "test",
                        "limitation": "test",
                    }
                ],
                graph_version="v77",
                graph_node_id="test",
            )

    def test_runtime_graph_keeps_execution_and_vehicle_blocked(self):
        integration = run_runtime_lab_integration()
        self.assertTrue(integration["passed"])
        self.assertEqual(integration["graph"]["node_count"], 20)
        self.assertFalse(
            integration["publication_safety"]["runtime_execution_observed"]
        )

    def test_synthetic_integration_is_deterministic(self):
        first = run_runtime_lab_integration()
        second = run_runtime_lab_integration()
        self.assertEqual(first, second)
        self.assertEqual(len(first["integration_fingerprint"]), 64)
        self.assertEqual(
            first["fixture_class"],
            "SYNTHETIC_NON_FIRMWARE_RUNTIME_CORPUS",
        )

    def test_runtime_evidence_graph_preserves_open_semantics(self):
        integration = run_runtime_lab_integration()
        placeholder = {
            "schema": "test/v1",
            "classification": {
                "fixed_vxworks_ipc_api_vocabulary": "CONFIRMED_BOUNDED"
            },
        }
        graph = build_runtime_evidence_graph(
            placeholder,
            placeholder,
            placeholder,
            placeholder,
            placeholder,
            placeholder,
        )
        statuses = {row["id"]: row["status"] for row in graph["nodes"]}
        self.assertEqual(statuses["runtime-object-identity"], "OPEN")
        self.assertEqual(statuses["firmware-execution"], "BLOCKED")
        self.assertFalse(graph["classification"]["safe_mutation_ready"])
        self.assertTrue(integration["passed"])


if __name__ == "__main__":
    unittest.main()

from hashlib import sha256
import unittest

from phoenix_mmi.navigation_provenance import NavigationSource
from phoenix_mmi.navigation_routing import (
    build_synthetic_routing_lab,
    shortest_route,
)
from phoenix_mmi.osm_adapter import adapt_osm_xml, synthetic_osm_fixture


def _graph():
    payload = synthetic_osm_fixture()
    source = NavigationSource(
        "project-phoenix-route-test",
        "SYNTHETIC",
        "PROJECT_PHOENIX_ORIGINAL",
        "Project Phoenix synthetic fixture",
        "synthetic://project-phoenix/m6",
        sha256(payload).hexdigest(),
    )
    return adapt_osm_xml(payload, source)[0]


class NavigationRoutingTests(unittest.TestCase):
    def test_forward_route_is_reachable(self):
        route = shortest_route(_graph(), "n1", "n4")
        self.assertTrue(route.reachable)
        self.assertGreater(route.distance_mm, 0)
        self.assertGreater(len(route.edge_ids), 0)

    def test_disconnected_node_is_unreachable(self):
        route = shortest_route(_graph(), "n5", "n1")
        self.assertFalse(route.reachable)
        self.assertIsNone(route.distance_mm)
        self.assertEqual(route.node_ids, ())

    def test_unknown_endpoint_is_rejected(self):
        with self.assertRaises(ValueError):
            shortest_route(_graph(), "n1", "missing")

    def test_route_is_deterministic(self):
        graph = _graph()
        self.assertEqual(
            shortest_route(graph, "n1", "n4"),
            shortest_route(graph, "n1", "n4"),
        )

    def test_one_way_reverse_edge_is_absent(self):
        graph = _graph()
        self.assertFalse(
            any(
                edge.edge_id.startswith("w101:")
                and edge.source_node_id == "n4"
                and edge.target_node_id == "n3"
                for edge in graph.edges
            )
        )

    def test_routing_lab_passes_and_reproduces(self):
        first = build_synthetic_routing_lab()
        second = build_synthetic_routing_lab()
        self.assertEqual(first, second)
        self.assertTrue(first["passed"])
        self.assertEqual(
            first["classification"]["independent_osm_host_pipeline"],
            "PROTOTYPE_FEASIBLE",
        )
        self.assertEqual(
            first["classification"]["direct_mmi_media_replacement"],
            "BLOCKED",
        )

    def test_routing_lab_publishes_no_source_data(self):
        safety = build_synthetic_routing_lab()["publication_safety"]
        self.assertTrue(safety["synthetic_fixture_only"])
        self.assertFalse(safety["osm_source_data_included"])
        self.assertFalse(safety["coordinates_included"])
        self.assertFalse(safety["map_payload_bytes_included"])


if __name__ == "__main__":
    unittest.main()

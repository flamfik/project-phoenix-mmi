from dataclasses import replace
from hashlib import sha256
import unittest

from phoenix_mmi.navigation_model import (
    NavigationEdge,
    NavigationNode,
    build_neutral_navigation_graph,
    build_public_navigation_graph_summary,
    navigation_graph_fingerprint,
)
from phoenix_mmi.navigation_provenance import NavigationSource
from phoenix_mmi.osm_adapter import adapt_osm_xml, synthetic_osm_fixture


def _source(payload: bytes | None = None) -> NavigationSource:
    content = payload or b"synthetic-model"
    return NavigationSource(
        "project-phoenix-test",
        "SYNTHETIC",
        "PROJECT_PHOENIX_ORIGINAL",
        "Project Phoenix synthetic fixture",
        "synthetic://project-phoenix/m6",
        sha256(content).hexdigest(),
    )


class NeutralNavigationModelTests(unittest.TestCase):
    def test_graph_orders_and_validates_nodes_and_edges(self):
        graph = build_neutral_navigation_graph(
            [
                NavigationNode("b", 1, 1),
                NavigationNode("a", 0, 0),
            ],
            [
                NavigationEdge("z", "a", "b", 100, "synthetic", False),
            ],
            _source(),
        )
        self.assertEqual([row.node_id for row in graph.nodes], ["a", "b"])
        self.assertEqual(navigation_graph_fingerprint(graph), navigation_graph_fingerprint(graph))

    def test_duplicate_node_is_rejected(self):
        with self.assertRaises(ValueError):
            build_neutral_navigation_graph(
                [NavigationNode("a", 0, 0), NavigationNode("a", 1, 1)],
                [],
                _source(),
            )

    def test_unknown_edge_endpoint_is_rejected(self):
        with self.assertRaises(ValueError):
            build_neutral_navigation_graph(
                [NavigationNode("a", 0, 0)],
                [NavigationEdge("e", "a", "b", 10, "road", False)],
                _source(),
            )

    def test_public_summary_omits_ids_and_coordinates(self):
        graph = build_neutral_navigation_graph(
            [NavigationNode("a", 0, 0), NavigationNode("b", 1, 1)],
            [NavigationEdge("e", "a", "b", 10, "road", True)],
            _source(),
        )
        summary = build_public_navigation_graph_summary(graph)
        self.assertFalse(summary["publication_safety"]["node_ids_included"])
        self.assertFalse(summary["publication_safety"]["coordinates_included"])
        self.assertNotIn('"a"', repr(summary))

    def test_source_hash_changes_graph_fingerprint(self):
        graph = build_neutral_navigation_graph(
            [NavigationNode("a", 0, 0)],
            [],
            _source(),
        )
        changed = replace(graph, source=_source(b"changed"))
        self.assertNotEqual(
            navigation_graph_fingerprint(graph),
            navigation_graph_fingerprint(changed),
        )


class OSMAdapterTests(unittest.TestCase):
    def test_synthetic_fixture_builds_bounded_graph(self):
        payload = synthetic_osm_fixture()
        graph, report = adapt_osm_xml(payload, _source(payload))
        self.assertEqual(len(graph.nodes), 5)
        self.assertEqual(len(graph.edges), 7)
        self.assertEqual(report["metrics"]["routable_way_count"], 3)
        self.assertEqual(
            report["classification"]["bounded_xml_adapter"], "CONFIRMED"
        )

    def test_adapter_is_deterministic(self):
        payload = synthetic_osm_fixture()
        self.assertEqual(
            adapt_osm_xml(payload, _source(payload)),
            adapt_osm_xml(payload, _source(payload)),
        )

    def test_adapter_keeps_relations_explicitly_unsupported(self):
        payload = synthetic_osm_fixture()
        _, report = adapt_osm_xml(payload, _source(payload))
        self.assertEqual(
            report["limitations"]["relations_and_turn_restrictions"],
            "NOT_IMPLEMENTED",
        )
        self.assertFalse(report["classification"]["target_media_converter"])

    def test_adapter_rejects_doctype(self):
        payload = b'<!DOCTYPE osm><osm version="0.6"></osm>'
        with self.assertRaises(ValueError):
            adapt_osm_xml(payload, _source(payload))

    def test_adapter_rejects_oversized_input(self):
        payload = b"x" * 1_048_577
        with self.assertRaises(ValueError):
            adapt_osm_xml(payload, _source(payload))

    def test_adapter_rejects_unresolved_way_reference(self):
        payload = (
            b'<osm version="0.6"><node id="1" lat="0" lon="0"/>'
            b'<way id="2"><nd ref="1"/><nd ref="9"/>'
            b'<tag k="highway" v="road"/></way></osm>'
        )
        with self.assertRaises(ValueError):
            adapt_osm_xml(payload, _source(payload))

    def test_adapter_rejects_duplicate_tags(self):
        payload = (
            b'<osm version="0.6"><node id="1" lat="0" lon="0"/>'
            b'<node id="2" lat="0.1" lon="0.1"/>'
            b'<way id="2"><nd ref="1"/><nd ref="2"/>'
            b'<tag k="highway" v="road"/><tag k="highway" v="service"/>'
            b'</way></osm>'
        )
        with self.assertRaises(ValueError):
            adapt_osm_xml(payload, _source(payload))


if __name__ == "__main__":
    unittest.main()

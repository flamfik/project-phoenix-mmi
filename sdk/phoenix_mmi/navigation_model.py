"""Target-independent navigation graph model for the M6 host prototype."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .navigation_provenance import NavigationSource, validate_navigation_source


NEUTRAL_NAVIGATION_SCHEMA = "phoenix-mmi.neutral-navigation-graph/v1"


@dataclass(frozen=True)
class NavigationNode:
    node_id: str
    latitude_e7: int
    longitude_e7: int


@dataclass(frozen=True)
class NavigationEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    distance_mm: int
    road_class: str
    one_way: bool


@dataclass(frozen=True)
class NeutralNavigationGraph:
    nodes: tuple[NavigationNode, ...]
    edges: tuple[NavigationEdge, ...]
    source: NavigationSource
    graph_version: str = "m6-session107-v1"


def build_neutral_navigation_graph(
    nodes: list[NavigationNode] | tuple[NavigationNode, ...],
    edges: list[NavigationEdge] | tuple[NavigationEdge, ...],
    source: NavigationSource,
) -> NeutralNavigationGraph:
    graph = NeutralNavigationGraph(
        nodes=tuple(sorted(nodes, key=lambda row: row.node_id)),
        edges=tuple(sorted(edges, key=lambda row: row.edge_id)),
        source=source,
    )
    validate_neutral_navigation_graph(graph)
    return graph


def validate_neutral_navigation_graph(graph: NeutralNavigationGraph) -> None:
    validate_navigation_source(graph.source)
    if not graph.nodes:
        raise ValueError("neutral navigation graph has no nodes")
    node_ids = [row.node_id for row in graph.nodes]
    edge_ids = [row.edge_id for row in graph.edges]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("duplicate neutral navigation node")
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("duplicate neutral navigation edge")
    if tuple(sorted(node_ids)) != tuple(node_ids):
        raise ValueError("neutral navigation nodes are not ordered")
    if tuple(sorted(edge_ids)) != tuple(edge_ids):
        raise ValueError("neutral navigation edges are not ordered")
    known = set(node_ids)
    for node in graph.nodes:
        if not (-900_000_000 <= node.latitude_e7 <= 900_000_000):
            raise ValueError("navigation latitude is out of bounds")
        if not (-1_800_000_000 <= node.longitude_e7 <= 1_800_000_000):
            raise ValueError("navigation longitude is out of bounds")
    for edge in graph.edges:
        if (
            edge.source_node_id not in known
            or edge.target_node_id not in known
            or edge.source_node_id == edge.target_node_id
            or edge.distance_mm <= 0
            or not edge.road_class
        ):
            raise ValueError("neutral navigation edge is invalid")


def navigation_graph_fingerprint(graph: NeutralNavigationGraph) -> str:
    validate_neutral_navigation_graph(graph)
    payload = {
        "schema": NEUTRAL_NAVIGATION_SCHEMA,
        "graph_version": graph.graph_version,
        "nodes": [asdict(row) for row in graph.nodes],
        "edges": [asdict(row) for row in graph.edges],
        "source": asdict(graph.source),
    }
    return sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def build_public_navigation_graph_summary(
    graph: NeutralNavigationGraph,
) -> dict[str, object]:
    validate_neutral_navigation_graph(graph)
    return {
        "schema": NEUTRAL_NAVIGATION_SCHEMA,
        "graph_version": graph.graph_version,
        "metrics": {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "one_way_edge_count": sum(row.one_way for row in graph.edges),
            "road_class_count": len({row.road_class for row in graph.edges}),
        },
        "source": {
            "source_kind": graph.source.source_kind,
            "license_id": graph.source.license_id,
            "attribution": graph.source.attribution,
            "snapshot_sha256": graph.source.snapshot_sha256,
        },
        "graph_fingerprint": navigation_graph_fingerprint(graph),
        "classification": {
            "target_independent": True,
            "coordinate_model": "WGS84_E7_HOST_MODEL",
            "target_format_compatibility": "NOT_ESTABLISHED",
            "production_routing_suitability": "NOT_ESTABLISHED",
        },
        "publication_safety": {
            "node_ids_included": False,
            "edge_ids_included": False,
            "coordinates_included": False,
            "osm_source_data_included": False,
            "proprietary_map_content_included": False,
        },
    }

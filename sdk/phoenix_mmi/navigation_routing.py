"""Deterministic host-only routing feasibility lab for neutral graphs."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import heapq
import json

from .navigation_model import (
    NavigationEdge,
    NeutralNavigationGraph,
    validate_neutral_navigation_graph,
)
from .navigation_provenance import NavigationSource
from .osm_adapter import adapt_osm_xml, synthetic_osm_fixture


NAVIGATION_ROUTING_SCHEMA = "phoenix-mmi.navigation-routing-lab/v1"


@dataclass(frozen=True)
class RouteResult:
    reachable: bool
    distance_mm: int | None
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]


def shortest_route(
    graph: NeutralNavigationGraph,
    source_node_id: str,
    target_node_id: str,
) -> RouteResult:
    """Run deterministic distance-only Dijkstra on a validated graph."""

    validate_neutral_navigation_graph(graph)
    known = {row.node_id for row in graph.nodes}
    if source_node_id not in known or target_node_id not in known:
        raise ValueError("route endpoint is absent from graph")
    adjacency: dict[str, list[NavigationEdge]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.source_node_id, []).append(edge)
    for value in adjacency.values():
        value.sort(key=lambda edge: edge.edge_id)

    distances = {source_node_id: 0}
    previous: dict[str, tuple[str, str]] = {}
    queue = [(0, source_node_id)]
    while queue:
        distance, node_id = heapq.heappop(queue)
        if distance != distances.get(node_id):
            continue
        if node_id == target_node_id:
            break
        for edge in adjacency.get(node_id, []):
            candidate = distance + edge.distance_mm
            old = distances.get(edge.target_node_id)
            old_predecessor = previous.get(edge.target_node_id)
            candidate_key = (node_id, edge.edge_id)
            if old is None or candidate < old or (
                candidate == old
                and (old_predecessor is None or candidate_key < old_predecessor)
            ):
                distances[edge.target_node_id] = candidate
                previous[edge.target_node_id] = candidate_key
                heapq.heappush(queue, (candidate, edge.target_node_id))

    if target_node_id not in distances:
        return RouteResult(False, None, (), ())
    nodes = [target_node_id]
    edges = []
    current = target_node_id
    while current != source_node_id:
        parent, edge_id = previous[current]
        nodes.append(parent)
        edges.append(edge_id)
        current = parent
    nodes.reverse()
    edges.reverse()
    return RouteResult(
        True,
        distances[target_node_id],
        tuple(nodes),
        tuple(edges),
    )


def _route_summary(route: RouteResult) -> dict[str, object]:
    fingerprint = sha256(
        json.dumps(
            {
                "reachable": route.reachable,
                "distance_mm": route.distance_mm,
                "node_ids": route.node_ids,
                "edge_ids": route.edge_ids,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "reachable": route.reachable,
        "distance_mm": route.distance_mm,
        "hop_count": len(route.edge_ids),
        "route_fingerprint": fingerprint,
        "node_or_edge_ids_included": False,
    }


def build_synthetic_routing_lab() -> dict[str, object]:
    """Exercise the complete host path using only original synthetic data."""

    payload = synthetic_osm_fixture()
    source = NavigationSource(
        source_id="project-phoenix-m6-synthetic",
        source_kind="SYNTHETIC",
        license_id="PROJECT_PHOENIX_ORIGINAL",
        attribution="Project Phoenix synthetic fixture",
        source_uri="synthetic://project-phoenix/m6",
        snapshot_sha256=sha256(payload).hexdigest(),
    )
    graph, adapter = adapt_osm_xml(payload, source)
    forward = shortest_route(graph, "n1", "n4")
    reverse = shortest_route(graph, "n4", "n3")
    unreachable = shortest_route(graph, "n5", "n1")
    one_way_reverse_absent = not any(
        edge.edge_id.startswith("w101:")
        and edge.source_node_id == "n4"
        and edge.target_node_id == "n3"
        for edge in graph.edges
    )
    routes = {
        "forward": _route_summary(forward),
        "reverse_alternative": _route_summary(reverse),
        "disconnected": _route_summary(unreachable),
    }
    fingerprint = sha256(
        json.dumps(
            {
                "adapter": adapter,
                "routes": routes,
                "one_way_reverse_absent": one_way_reverse_absent,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    passed = bool(
        forward.reachable
        and reverse.reachable
        and not unreachable.reachable
        and one_way_reverse_absent
    )
    return {
        "schema": NAVIGATION_ROUTING_SCHEMA,
        "lab_version": "m6-session109-v1",
        "adapter": adapter,
        "routes": routes,
        "checks": {
            "forward_route_reachable": forward.reachable,
            "reverse_uses_available_alternative": reverse.reachable,
            "disconnected_route_unreachable": not unreachable.reachable,
            "one_way_reverse_edge_absent": one_way_reverse_absent,
        },
        "lab_fingerprint": fingerprint,
        "passed": passed,
        "classification": {
            "independent_osm_host_pipeline": (
                "PROTOTYPE_FEASIBLE" if passed else "NOT_DEMONSTRATED"
            ),
            "direct_mmi_media_replacement": "BLOCKED",
            "target_routing_compatibility": "NOT_ESTABLISHED",
            "production_router": False,
        },
        "publication_safety": {
            "synthetic_fixture_only": True,
            "osm_source_data_included": False,
            "coordinates_included": False,
            "map_payload_bytes_included": False,
            "target_artifacts_included": False,
        },
    }

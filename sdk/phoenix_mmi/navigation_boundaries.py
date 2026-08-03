"""Static media-to-runtime boundary graph for M6."""

from __future__ import annotations

from collections import deque


NAVIGATION_BOUNDARY_SCHEMA = "phoenix-mmi.navigation-boundary-graph/v1"


def build_navigation_boundary_graph(
    knowledge: dict[str, object],
) -> dict[str, object]:
    """Build a graph that preserves every unconfirmed target boundary."""

    if knowledge.get("schema") != "phoenix-mmi.navigation-knowledge-matrix/v1":
        raise ValueError("unsupported navigation knowledge matrix")
    nodes = [
        _node("registered-medium", "CONFIRMED", "media"),
        _node("iso-joliet", "CONFIRMED", "storage"),
        _node("fldb-containers", "CONFIRMED", "container"),
        _node("payload-families", "CONFIRMED_STRUCTURE_ONLY", "payload"),
        _node("partition-domain", "CONFIRMED_STRUCTURE_ONLY", "payload"),
        _node("routing-grammar", "OPEN", "semantics"),
        _node("coordinate-model", "OPEN", "semantics"),
        _node("integrity-writer", "OPEN", "writer"),
        _node("optical-volume-reader", "PROBABLE", "firmware"),
        _node("sector-read-abi", "OPEN", "firmware"),
        _node("inner-payload-consumer", "OPEN", "firmware"),
        _node("navigation-runtime", "CONFIRMED_PRESENCE_ONLY", "firmware"),
    ]
    edges = [
        _edge("registered-medium", "iso-joliet", "CONFIRMED"),
        _edge("iso-joliet", "fldb-containers", "CONFIRMED"),
        _edge("fldb-containers", "payload-families", "CONFIRMED"),
        _edge("payload-families", "partition-domain", "CONFIRMED_STRUCTURE_ONLY"),
        _edge("partition-domain", "routing-grammar", "OPEN"),
        _edge("partition-domain", "coordinate-model", "OPEN"),
        _edge("routing-grammar", "integrity-writer", "OPEN"),
        _edge("optical-volume-reader", "iso-joliet", "PROBABLE"),
        _edge("optical-volume-reader", "sector-read-abi", "OPEN"),
        _edge("sector-read-abi", "inner-payload-consumer", "OPEN"),
        _edge("inner-payload-consumer", "navigation-runtime", "OPEN"),
    ]
    confirmed_path = _has_path(
        "registered-medium",
        "navigation-runtime",
        edges,
        allowed={"CONFIRMED"},
    )
    graph = {
        "schema": NAVIGATION_BOUNDARY_SCHEMA,
        "graph_version": "m6-session105-v1",
        "nodes": nodes,
        "edges": edges,
        "metrics": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "open_node_count": sum(row["status"] == "OPEN" for row in nodes),
            "open_edge_count": sum(row["status"] == "OPEN" for row in edges),
            "confirmed_media_to_runtime_path": confirmed_path,
        },
        "classification": {
            "media_to_outer_container": "CONFIRMED",
            "outer_container_to_runtime": "OPEN",
            "direct_runtime_bridge": "NOT_CONFIRMED",
            "graph_is_dynamic_trace": False,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "map_payload_bytes_included": False,
            "raw_addresses_included": False,
            "raw_proprietary_names_included": False,
        },
    }
    validate_navigation_boundary_graph(graph)
    return graph


def _node(node_id: str, status: str, domain: str) -> dict[str, str]:
    return {"node_id": node_id, "status": status, "domain": domain}


def _edge(source: str, target: str, status: str) -> dict[str, str]:
    return {"source": source, "target": target, "status": status}


def _has_path(
    source: str,
    target: str,
    edges: list[dict[str, str]],
    *,
    allowed: set[str],
) -> bool:
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        if edge["status"] in allowed:
            adjacency.setdefault(edge["source"], []).append(edge["target"])
    queue = deque([source])
    seen = {source}
    while queue:
        current = queue.popleft()
        if current == target:
            return True
        for neighbor in adjacency.get(current, []):
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append(neighbor)
    return False


def validate_navigation_boundary_graph(graph: dict[str, object]) -> None:
    if graph.get("schema") != NAVIGATION_BOUNDARY_SCHEMA:
        raise ValueError("unsupported navigation boundary graph")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("incomplete navigation boundary graph")
    ids = {row["node_id"] for row in nodes}
    if len(ids) != len(nodes):
        raise ValueError("duplicate navigation boundary node")
    if any(edge["source"] not in ids or edge["target"] not in ids for edge in edges):
        raise ValueError("navigation boundary edge has an unknown endpoint")
    metrics = graph.get("metrics")
    if not isinstance(metrics, dict) or (
        metrics.get("confirmed_media_to_runtime_path") is not False
        or metrics.get("open_edge_count", 0) < 1
    ):
        raise ValueError("navigation runtime boundary was over-promoted")

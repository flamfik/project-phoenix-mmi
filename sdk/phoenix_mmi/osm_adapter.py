"""Bounded OSM XML to neutral navigation graph adapter."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from hashlib import sha256
import math
import xml.etree.ElementTree as ET

from .navigation_model import (
    NavigationEdge,
    NavigationNode,
    NeutralNavigationGraph,
    build_neutral_navigation_graph,
    build_public_navigation_graph_summary,
)
from .navigation_provenance import NavigationSource, validate_navigation_source


OSM_ADAPTER_SCHEMA = "phoenix-mmi.osm-xml-adapter/v1"
MAX_OSM_XML_BYTES = 1_048_576
MAX_OSM_ELEMENTS = 10_000


def _coordinate_e7(value: str, *, latitude: bool) -> int:
    try:
        scaled = int(Decimal(value) * Decimal(10_000_000))
    except (InvalidOperation, ValueError):
        raise ValueError("invalid OSM coordinate") from None
    limit = 900_000_000 if latitude else 1_800_000_000
    if not -limit <= scaled <= limit:
        raise ValueError("OSM coordinate is out of bounds")
    return scaled


def _distance_mm(left: NavigationNode, right: NavigationNode) -> int:
    """Return deterministic host weight using a WGS84 haversine estimate."""

    latitude_1 = math.radians(left.latitude_e7 / 10_000_000)
    latitude_2 = math.radians(right.latitude_e7 / 10_000_000)
    delta_latitude = latitude_2 - latitude_1
    delta_longitude = math.radians(
        (right.longitude_e7 - left.longitude_e7) / 10_000_000
    )
    term = (
        math.sin(delta_latitude / 2) ** 2
        + math.cos(latitude_1)
        * math.cos(latitude_2)
        * math.sin(delta_longitude / 2) ** 2
    )
    term = min(1.0, max(0.0, term))
    metres = 6_371_008.8 * 2 * math.atan2(math.sqrt(term), math.sqrt(1 - term))
    return max(1, round(metres * 1000))


def _tags(element: ET.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for child in element:
        if child.tag != "tag":
            continue
        key = child.attrib.get("k")
        value = child.attrib.get("v")
        if key is None or value is None or key in values:
            raise ValueError("invalid or duplicate OSM tag")
        values[key] = value
    return values


def adapt_osm_xml(
    payload: bytes,
    source: NavigationSource,
) -> tuple[NeutralNavigationGraph, dict[str, object]]:
    """Parse bounded authorized OSM XML without network or target output."""

    validate_navigation_source(source)
    if not payload or len(payload) > MAX_OSM_XML_BYTES:
        raise ValueError("OSM XML size is outside the adapter bound")
    upper = payload[:4096].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("DTD and entity declarations are prohibited")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise ValueError("invalid OSM XML") from error
    if root.tag != "osm" or root.attrib.get("version") != "0.6":
        raise ValueError("only bounded OSM XML 0.6 is supported")
    elements = list(root)
    if len(elements) > MAX_OSM_ELEMENTS:
        raise ValueError("OSM element count exceeds the adapter bound")

    nodes: dict[str, NavigationNode] = {}
    ways: list[ET.Element] = []
    relation_count = 0
    for element in elements:
        if element.tag == "node":
            osm_id = element.attrib.get("id")
            latitude = element.attrib.get("lat")
            longitude = element.attrib.get("lon")
            if osm_id is None or latitude is None or longitude is None:
                raise ValueError("OSM node is incomplete")
            node_id = f"n{osm_id}"
            if node_id in nodes:
                raise ValueError("duplicate OSM node")
            nodes[node_id] = NavigationNode(
                node_id=node_id,
                latitude_e7=_coordinate_e7(latitude, latitude=True),
                longitude_e7=_coordinate_e7(longitude, latitude=False),
            )
        elif element.tag == "way":
            ways.append(element)
        elif element.tag == "relation":
            relation_count += 1
        elif element.tag not in {"bounds", "note", "meta"}:
            raise ValueError("unsupported top-level OSM element")

    edges: list[NavigationEdge] = []
    routable_way_count = 0
    skipped_way_count = 0
    for way in ways:
        way_id = way.attrib.get("id")
        if way_id is None:
            raise ValueError("OSM way has no identifier")
        tags = _tags(way)
        road_class = tags.get("highway")
        if not road_class:
            skipped_way_count += 1
            continue
        refs = [
            f"n{child.attrib['ref']}"
            for child in way
            if child.tag == "nd" and "ref" in child.attrib
        ]
        if len(refs) < 2 or any(item not in nodes for item in refs):
            raise ValueError("routable OSM way has unresolved node references")
        routable_way_count += 1
        one_way_value = tags.get("oneway", "").casefold()
        forward_only = one_way_value in {"yes", "1", "true"}
        reverse_only = one_way_value == "-1"
        ordered = list(reversed(refs)) if reverse_only else refs
        one_way = forward_only or reverse_only
        for index, (left_id, right_id) in enumerate(
            zip(ordered, ordered[1:])
        ):
            distance = _distance_mm(nodes[left_id], nodes[right_id])
            edges.append(
                NavigationEdge(
                    edge_id=f"w{way_id}:{index}:f",
                    source_node_id=left_id,
                    target_node_id=right_id,
                    distance_mm=distance,
                    road_class=road_class,
                    one_way=one_way,
                )
            )
            if not one_way:
                edges.append(
                    NavigationEdge(
                        edge_id=f"w{way_id}:{index}:r",
                        source_node_id=right_id,
                        target_node_id=left_id,
                        distance_mm=distance,
                        road_class=road_class,
                        one_way=False,
                    )
                )

    graph = build_neutral_navigation_graph(list(nodes.values()), edges, source)
    report = {
        "schema": OSM_ADAPTER_SCHEMA,
        "adapter_version": "m6-session108-v1",
        "input": {
            "byte_count": len(payload),
            "sha256": sha256(payload).hexdigest(),
            "source_kind": source.source_kind,
            "license_id": source.license_id,
            "xml_version": "0.6",
        },
        "metrics": {
            "node_count": len(nodes),
            "way_count": len(ways),
            "routable_way_count": routable_way_count,
            "skipped_way_count": skipped_way_count,
            "relation_count": relation_count,
            "edge_count": len(edges),
        },
        "neutral_graph": build_public_navigation_graph_summary(graph),
        "limitations": {
            "relations_and_turn_restrictions": "NOT_IMPLEMENTED",
            "areas_and_lane_semantics": "NOT_IMPLEMENTED",
            "weight_model": "HOST_HAVERSINE_DISTANCE_ONLY",
            "target_format_output": "PROHIBITED",
        },
        "classification": {
            "bounded_xml_adapter": "CONFIRMED",
            "production_osm_importer": False,
            "target_media_converter": False,
        },
        "publication_safety": {
            "osm_source_data_included": False,
            "coordinates_included": False,
            "element_ids_included": False,
            "map_payload_bytes_included": False,
            "target_artifacts_included": False,
        },
    }
    return graph, report


def synthetic_osm_fixture() -> bytes:
    """Return a small Project Phoenix-authored OSM-shaped test fixture."""

    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<osm version="0.6" generator="project-phoenix-synthetic">\n'
        b'  <node id="1" lat="50.0000000" lon="20.0000000"/>\n'
        b'  <node id="2" lat="50.0005000" lon="20.0005000"/>\n'
        b'  <node id="3" lat="50.0010000" lon="20.0010000"/>\n'
        b'  <node id="4" lat="50.0015000" lon="20.0015000"/>\n'
        b'  <node id="5" lat="50.0050000" lon="20.0050000"/>\n'
        b'  <way id="100"><nd ref="1"/><nd ref="2"/><nd ref="3"/>'
        b'<tag k="highway" v="residential"/></way>\n'
        b'  <way id="101"><nd ref="3"/><nd ref="4"/>'
        b'<tag k="highway" v="service"/><tag k="oneway" v="yes"/></way>\n'
        b'  <way id="102"><nd ref="2"/><nd ref="4"/>'
        b'<tag k="highway" v="secondary"/></way>\n'
        b'</osm>\n'
    )

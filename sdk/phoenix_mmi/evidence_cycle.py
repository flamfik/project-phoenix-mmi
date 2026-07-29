"""Cross-session operational-model synthesis for Sessions 051-060."""

from __future__ import annotations

import copy


def _publication_safety() -> dict[str, bool]:
    return {
        "firmware_bytes_included": False,
        "payload_bytes_included": False,
        "decoded_raster_bytes_included": False,
        "decoded_raster_hashes_included": False,
        "source_content_hashes_included": False,
        "integrity_field_values_included": False,
        "raw_header_values_included": False,
        "raw_offsets_included": False,
        "raw_strings_included": False,
        "local_paths_included": False,
        "extracted_resources_included": False,
        "installable_artifacts_included": False,
        "runtime_execution_observed": False,
    }


def build_session060_evidence_map(
    session050: dict[str, object],
    reports: list[dict[str, object]],
) -> dict[str, object]:
    if session050.get("schema") != (
        "phoenix-mmi.firmware-evidence-map/v1"
    ):
        raise ValueError("unsupported Session 050 schema")
    expected_sessions = [f"{number:03d}" for number in range(51, 60)]
    if [str(report.get("session")) for report in reports] != expected_sessions:
        raise ValueError("Sessions 051-059 report order differs")
    graph = copy.deepcopy(session050["operational_graph"])
    node_specs = [
        (
            "yim-expanded-integrity-catalog",
            "expanded_integrity_catalog",
            "bounds-common-integrity-algorithms",
            "BOUNDED_NEGATIVE",
        ),
        (
            "yim-field-relations",
            "simple_field_relation",
            "tests-simple-preamble-relations",
            "BOUNDED_NEGATIVE",
        ),
        (
            "embedded-xim2-census",
            "embedded_xim2",
            "links-display-assets-to-main-image",
            "CONFIRMED",
        ),
        (
            "yim-integrity-decision",
            "yim_write_model",
            "gates-yim-mutation",
            "OPEN",
        ),
        (
            "lod-alignment-census",
            "global_alignment",
            "tests-fixed-width-phase-bias",
            "HYPOTHESIS",
        ),
        (
            "lod-fill-regions",
            "fill_topology",
            "segments-by-frozen-fill-thresholds",
            "CONFIRMED",
        ),
        (
            "lod-grid-reuse",
            "cross_language_reuse",
            "tests-grid-origin-robustness",
            "CONFIRMED",
        ),
        (
            "lod-record-hypothesis",
            "three_byte_record_model",
            "falsifies-three-byte-record-model",
            "OPEN",
        ),
        (
            "lod-shared-regions",
            "shared_regions",
            "maps-bounded-shared-regions",
            "CONFIRMED",
        ),
    ]
    previous = "firmware-evidence-map"
    for report, (node_id, key, relation, status) in zip(
        reports, node_specs
    ):
        result = str(report["classification"][key])
        graph["nodes"].append(
            {
                "id": node_id,
                "status": status,
                "result": result,
                "evidence_session": report["session"],
            }
        )
        graph["edges"].append(
            {
                "source": previous,
                "target": node_id,
                "status": status,
                "relation": relation,
            }
        )
        previous = node_id
    graph["nodes"].append(
        {
            "id": "firmware-evidence-map-v2",
            "status": "PARTIAL_EVIDENCE_LINKED_MODEL",
            "evidence_session": "060",
        }
    )
    graph["edges"].append(
        {
            "source": previous,
            "target": "firmware-evidence-map-v2",
            "status": "SYNTHESIZED",
            "relation": "contributes-to-integrated-model",
        }
    )
    graph["schema"] = "phoenix-mmi.operational-graph/v52"
    graph["node_count"] = len(graph["nodes"])
    graph["edge_count"] = len(graph["edges"])
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED")
        for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE")
        for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(
        node["status"] == "OPEN" for node in graph["nodes"]
    )
    graph["bounded_negative_edge_count"] = sum(
        "BOUNDED_NEGATIVE" in edge["status"]
        for edge in graph["edges"]
    )
    graph["disproved_edge_count"] = sum(
        "DISPROVED" in edge["status"] for edge in graph["edges"]
    )
    graph["interpretation"] = (
        "Graph v52 confirms embedded XIM2 containment and bounded LOD "
        "structure while preserving YIM write integrity, XIM2 consumer "
        "ownership and the LOD record/consumer model as open."
    )
    return {
        "schema": "phoenix-mmi.firmware-evidence-map/v2",
        "analysis_mode": "evidence-only-cross-session-synthesis",
        "session": "060",
        "source_sessions": ["001-050", *expected_sessions],
        "layers": [
            {
                "id": "UPDATE_MEDIA",
                "status": "CONFIRMED",
                "role": (
                    "ISO9660 media and METAINFO-driven component selection"
                ),
            },
            {
                "id": "DISTRIBUTED_COMPONENT_PAYLOADS",
                "status": "CONFIRMED_PARTIAL_FORMAT_COVERAGE",
                "role": (
                    "MOST-device applications, bootloaders and data packages"
                ),
            },
            {
                "id": "MAIN_MMI_IMAGE",
                "status": "STRUCTURALLY_MAPPED_SEMANTIC_OWNER_OPEN",
                "role": (
                    "SuperH runtime plus embedded display-resource region"
                ),
            },
            {
                "id": "DISPLAY_ASSETS",
                "status": "EMBEDDED_XIM2_AND_EXTERNAL_YIM_LINKED",
                "role": (
                    "strictly decoded XIM2 resources shared by 5150 and 5570"
                ),
            },
            {
                "id": "DISPLAY_ASSET_INTEGRITY",
                "status": "WRITE_MODEL_UNRESOLVED",
                "role": (
                    "external YIM ASCII-preamble integrity and mutation gate"
                ),
            },
            {
                "id": "SPEECH_LANGUAGE_PAYLOAD",
                "status": "STRUCTURED_SHARED_REGIONS_RECORD_MODEL_OPEN",
                "role": (
                    "LOD language payloads with repeated delimiters, alignment "
                    "bias and bounded exact reuse"
                ),
            },
            {
                "id": "NAVIGATION_MEDIA",
                "status": "PARTIALLY_MAPPED",
                "role": "optical navigation data and runtime consumers",
            },
        ],
        "firmware_flow": [
            {
                "from": "update-media",
                "to": "metainfo-selector",
                "status": "CONFIRMED",
            },
            {
                "from": "metainfo-selector",
                "to": "principal-image",
                "status": "PROBABLE_RUNTIME_BEHAVIOR",
            },
            {
                "from": "principal-image",
                "to": "embedded-xim2-assets",
                "status": "CONFIRMED_PHYSICAL_CONTAINMENT",
            },
            {
                "from": "external-yim-update-payload",
                "to": "embedded-xim2-asset-set",
                "status": "CONFIRMED_EXACT_CONTENT_RELATION_PARTIAL",
            },
            {
                "from": "lod-language-payload",
                "to": "speech-runtime",
                "status": "PROBABLE_PACKAGE_ROLE_SEMANTIC_DECODER_OPEN",
            },
        ],
        "closed_in_cycle": [
            "strict embedded XIM2 presence in both principal images",
            "cross-version equality of the validated embedded XIM2 set",
            "exact external-YIM to embedded-XIM2 relationship",
            "repeatable LOD large-fill topology",
            "LOD exact reuse robustness across shifted fixed grids",
            "bounded aligned nontrivial LOD shared regions",
        ],
        "bounded_negative_results": [
            "no YIM integrity match under the frozen expanded catalogue",
            "no corpus-wide simple relation for YIM integrity fields",
            "three-byte LOD record model not established",
        ],
        "open_after_cycle": [
            "YIM ASCII-preamble integrity algorithm",
            "YIM pixel semantics and rendering consumer",
            "safe YIM repacking",
            "LOD record, address, length and integrity model",
            "LOD consumer routine",
            "exact main-image section boundary",
            "semantic owner of the reorder component",
            "external or runtime loader transformation",
        ],
        "classification": {
            "firmware_operational_model": (
                "PARTIAL_EVIDENCE_LINKED_MODEL"
            ),
            "display_resource_read_model": "CONFIRMED_PARTIAL",
            "speech_payload_read_model": "STRUCTURAL_ONLY",
            "milestone_m1": "PARTIAL_NOT_COMPLETE",
            "safe_mutation_ready": False,
        },
        "operational_graph": graph,
        "operational_graph_version": "v52",
        "publication_safety": _publication_safety(),
    }

"""Phoenix MMI read-only firmware research SDK."""

from .analysis import AnalysisConfig, analyze_file, compare_reports
from .accessor_dispatch import (
    analyze_accessor_dispatch,
    build_public_accessor_dispatch_report,
    correlate_accessor_dispatch,
    update_operational_graph_v11,
)
from .binary import BinaryReader
from .checksum import ChecksumExpectation, ChecksumMatch, crc32_bytes
from .continuation_contract import (
    analyze_internal_continuation_contract,
    build_public_internal_continuation_report,
    correlate_internal_continuation_contract,
    update_operational_graph_v16,
)
from .descriptor_lineage import (
    analyze_descriptor_lineage,
    build_public_descriptor_lineage_report,
    correlate_descriptor_lineage,
    trace_dispatch_producer,
    update_operational_graph_v10,
)
from .entropy import EntropyWindow, entropy_profile, shannon_entropy
from .fingerprint import FingerprintHit, scan_fingerprints
from .layout import analyze_executable_layout
from .map_media import (
    analyze_navigation_media,
    build_public_navigation_media_report,
    correlate_firmware_and_media,
    parse_fldb_container,
    probe_firmware_media_markers,
    update_operational_graph_v4,
)
from .map_payload import (
    analyze_navigation_payloads,
    build_public_navigation_payload_report,
    classify_payload_header,
)
from .navigation_dataflow import (
    analyze_navigation_dataflow,
    build_public_navigation_dataflow_report,
    compare_navigation_dataflow,
    discover_contract_anchors,
    summarize_code_window,
    summarize_runtime_neighborhood,
    update_operational_graph_v3,
)
from .navigation_storage import (
    analyze_navigation_storage_boundary,
    build_public_navigation_storage_report,
    compare_navigation_storage_boundaries,
    scan_storage_signatures,
    update_operational_graph,
)
from .operational_model import (
    analyze_relocated_bitmap_atlas,
    build_operational_graph,
    build_public_operational_report,
)
from .object_dispatch import (
    analyze_object_dispatch_context,
    build_public_object_dispatch_report,
    correlate_dispatch_context,
    summarize_contextual_dispatch_calls,
    update_operational_graph_v9,
)
from .optical_callgraph import (
    build_bounded_interprocedural_graph,
    build_public_optical_callgraph_report,
    collect_seed_pairs,
    compare_optical_navigation_callgraph,
    correlate_optical_sector_model,
    summarize_bounded_entry,
    update_operational_graph_v8,
)
from .parser_contract import (
    compare_parser_constants,
    correlate_payload_parser_contract,
    scan_parser_constants,
    update_operational_graph_v5,
)
from .parser_dataflow import (
    analyze_fldb_candidate_dataflow,
    build_public_fldb_candidate_report,
    compare_fldb_candidate_dataflow,
    correlate_corrected_parser_model,
    update_operational_graph_v6,
)
from .parser_search import (
    build_public_global_parser_report,
    compare_global_fldb_parser_search,
    correlate_global_fldb_parser_search,
    scan_global_fldb_parser_candidates,
    update_operational_graph_v7,
)
from .reference_graph import (
    analyze_reference_graph,
    build_public_reference_graph,
    compare_reference_graphs,
)
from .resource_bundle import analyze_resource_bundle, build_public_resource_bundle
from .runtime_map import analyze_runtime_map, build_public_runtime_map
from .runtime_slot import (
    analyze_runtime_slot_lineage,
    build_public_runtime_slot_report,
    correlate_runtime_slot_lineage,
    update_operational_graph_v12,
)
from .runtime_linkage import (
    analyze_runtime_linkage_family,
    build_public_runtime_linkage_report,
    correlate_runtime_linkage_family,
    update_operational_graph_v13,
)
from .linkage_owner import (
    analyze_linkage_owner_lineage,
    build_public_linkage_owner_report,
    correlate_linkage_owner_lineage,
    update_operational_graph_v14,
)
from .owner_provenance import (
    analyze_owner_ingress_state,
    build_public_owner_ingress_report,
    correlate_owner_ingress_state,
    update_operational_graph_v15,
)
from .segments import CandidateSegment, build_candidate_segments
from .superh import (
    SHInstruction,
    decode_instruction,
    decode_instruction_extended,
    trace_control_flow,
)

__all__ = [
    "AnalysisConfig",
    "BinaryReader",
    "CandidateSegment",
    "ChecksumExpectation",
    "ChecksumMatch",
    "EntropyWindow",
    "FingerprintHit",
    "SHInstruction",
    "analyze_file",
    "analyze_internal_continuation_contract",
    "analyze_accessor_dispatch",
    "analyze_descriptor_lineage",
    "analyze_executable_layout",
    "analyze_fldb_candidate_dataflow",
    "analyze_navigation_storage_boundary",
    "analyze_navigation_dataflow",
    "analyze_navigation_media",
    "analyze_navigation_payloads",
    "analyze_object_dispatch_context",
    "analyze_reference_graph",
    "analyze_relocated_bitmap_atlas",
    "analyze_resource_bundle",
    "analyze_runtime_map",
    "analyze_runtime_slot_lineage",
    "analyze_runtime_linkage_family",
    "analyze_linkage_owner_lineage",
    "analyze_owner_ingress_state",
    "build_candidate_segments",
    "build_public_accessor_dispatch_report",
    "build_operational_graph",
    "build_bounded_interprocedural_graph",
    "build_public_optical_callgraph_report",
    "build_public_navigation_storage_report",
    "build_public_fldb_candidate_report",
    "build_public_descriptor_lineage_report",
    "build_public_global_parser_report",
    "build_public_navigation_dataflow_report",
    "build_public_navigation_media_report",
    "build_public_navigation_payload_report",
    "build_public_operational_report",
    "build_public_object_dispatch_report",
    "build_public_reference_graph",
    "build_public_resource_bundle",
    "build_public_runtime_map",
    "build_public_runtime_slot_report",
    "build_public_runtime_linkage_report",
    "build_public_linkage_owner_report",
    "build_public_owner_ingress_report",
    "build_public_internal_continuation_report",
    "compare_reports",
    "compare_navigation_storage_boundaries",
    "compare_navigation_dataflow",
    "compare_optical_navigation_callgraph",
    "compare_parser_constants",
    "compare_fldb_candidate_dataflow",
    "compare_global_fldb_parser_search",
    "classify_payload_header",
    "correlate_payload_parser_contract",
    "correlate_accessor_dispatch",
    "correlate_corrected_parser_model",
    "correlate_descriptor_lineage",
    "correlate_global_fldb_parser_search",
    "correlate_firmware_and_media",
    "correlate_runtime_slot_lineage",
    "correlate_runtime_linkage_family",
    "correlate_linkage_owner_lineage",
    "correlate_owner_ingress_state",
    "correlate_internal_continuation_contract",
    "correlate_optical_sector_model",
    "correlate_dispatch_context",
    "compare_reference_graphs",
    "crc32_bytes",
    "collect_seed_pairs",
    "decode_instruction",
    "decode_instruction_extended",
    "discover_contract_anchors",
    "entropy_profile",
    "parse_fldb_container",
    "probe_firmware_media_markers",
    "scan_fingerprints",
    "scan_parser_constants",
    "scan_global_fldb_parser_candidates",
    "scan_storage_signatures",
    "shannon_entropy",
    "summarize_code_window",
    "summarize_bounded_entry",
    "summarize_contextual_dispatch_calls",
    "summarize_runtime_neighborhood",
    "trace_control_flow",
    "trace_dispatch_producer",
    "update_operational_graph",
    "update_operational_graph_v3",
    "update_operational_graph_v4",
    "update_operational_graph_v5",
    "update_operational_graph_v6",
    "update_operational_graph_v7",
    "update_operational_graph_v8",
    "update_operational_graph_v9",
    "update_operational_graph_v10",
    "update_operational_graph_v11",
    "update_operational_graph_v12",
    "update_operational_graph_v13",
    "update_operational_graph_v14",
    "update_operational_graph_v15",
    "update_operational_graph_v16",
]

__version__ = "0.21.0"

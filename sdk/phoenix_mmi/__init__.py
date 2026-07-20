"""Phoenix MMI read-only firmware research SDK."""

from .analysis import AnalysisConfig, analyze_file, compare_reports
from .binary import BinaryReader
from .checksum import ChecksumExpectation, ChecksumMatch, crc32_bytes
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
from .parser_contract import (
    compare_parser_constants,
    correlate_payload_parser_contract,
    scan_parser_constants,
    update_operational_graph_v5,
)
from .reference_graph import (
    analyze_reference_graph,
    build_public_reference_graph,
    compare_reference_graphs,
)
from .resource_bundle import analyze_resource_bundle, build_public_resource_bundle
from .runtime_map import analyze_runtime_map, build_public_runtime_map
from .segments import CandidateSegment, build_candidate_segments
from .superh import SHInstruction, decode_instruction, trace_control_flow

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
    "analyze_executable_layout",
    "analyze_navigation_storage_boundary",
    "analyze_navigation_dataflow",
    "analyze_navigation_media",
    "analyze_navigation_payloads",
    "analyze_reference_graph",
    "analyze_relocated_bitmap_atlas",
    "analyze_resource_bundle",
    "analyze_runtime_map",
    "build_candidate_segments",
    "build_operational_graph",
    "build_public_navigation_storage_report",
    "build_public_navigation_dataflow_report",
    "build_public_navigation_media_report",
    "build_public_navigation_payload_report",
    "build_public_operational_report",
    "build_public_reference_graph",
    "build_public_resource_bundle",
    "build_public_runtime_map",
    "compare_reports",
    "compare_navigation_storage_boundaries",
    "compare_navigation_dataflow",
    "compare_parser_constants",
    "classify_payload_header",
    "correlate_payload_parser_contract",
    "correlate_firmware_and_media",
    "compare_reference_graphs",
    "crc32_bytes",
    "decode_instruction",
    "discover_contract_anchors",
    "entropy_profile",
    "parse_fldb_container",
    "probe_firmware_media_markers",
    "scan_fingerprints",
    "scan_parser_constants",
    "scan_storage_signatures",
    "shannon_entropy",
    "summarize_code_window",
    "summarize_runtime_neighborhood",
    "trace_control_flow",
    "update_operational_graph",
    "update_operational_graph_v3",
    "update_operational_graph_v4",
    "update_operational_graph_v5",
]

__version__ = "0.10.0"

"""Phoenix MMI read-only firmware research SDK."""

from .analysis import AnalysisConfig, analyze_file, compare_reports
from .binary import BinaryReader
from .checksum import ChecksumExpectation, ChecksumMatch, crc32_bytes
from .entropy import EntropyWindow, entropy_profile, shannon_entropy
from .fingerprint import FingerprintHit, scan_fingerprints
from .layout import analyze_executable_layout
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
    "analyze_reference_graph",
    "analyze_resource_bundle",
    "analyze_runtime_map",
    "build_candidate_segments",
    "build_public_reference_graph",
    "build_public_resource_bundle",
    "build_public_runtime_map",
    "compare_reports",
    "compare_reference_graphs",
    "crc32_bytes",
    "decode_instruction",
    "entropy_profile",
    "scan_fingerprints",
    "shannon_entropy",
    "trace_control_flow",
]

__version__ = "0.5.0"

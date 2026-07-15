"""Phoenix MMI read-only firmware research SDK."""

from .analysis import AnalysisConfig, analyze_file, compare_reports
from .binary import BinaryReader
from .checksum import ChecksumExpectation, ChecksumMatch, crc32_bytes
from .entropy import EntropyWindow, entropy_profile, shannon_entropy
from .fingerprint import FingerprintHit, scan_fingerprints
from .segments import CandidateSegment, build_candidate_segments
from .layout import analyze_executable_layout
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
    "build_candidate_segments",
    "compare_reports",
    "crc32_bytes",
    "decode_instruction",
    "entropy_profile",
    "scan_fingerprints",
    "shannon_entropy",
    "trace_control_flow",
]

__version__ = "0.2.0"

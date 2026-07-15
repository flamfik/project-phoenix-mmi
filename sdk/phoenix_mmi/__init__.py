"""Phoenix MMI read-only firmware research SDK."""

from .analysis import AnalysisConfig, analyze_file, compare_reports
from .binary import BinaryReader
from .checksum import ChecksumExpectation, ChecksumMatch, crc32_bytes
from .entropy import EntropyWindow, entropy_profile, shannon_entropy
from .fingerprint import FingerprintHit, scan_fingerprints
from .segments import CandidateSegment, build_candidate_segments

__all__ = [
    "AnalysisConfig",
    "BinaryReader",
    "CandidateSegment",
    "ChecksumExpectation",
    "ChecksumMatch",
    "EntropyWindow",
    "FingerprintHit",
    "analyze_file",
    "build_candidate_segments",
    "compare_reports",
    "crc32_bytes",
    "entropy_profile",
    "scan_fingerprints",
    "shannon_entropy",
]

__version__ = "0.1.0"

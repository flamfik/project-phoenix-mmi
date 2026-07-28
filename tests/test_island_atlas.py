from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.island_atlas import (
    analyze_content_island_atlas,
    build_public_content_island_atlas_report,
    compare_island_atlas_grid_control,
    finalize_content_island_atlas,
    update_operational_graph_v29,
)


def _stream(length: int, salt: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(salt + counter.to_bytes(4, "big")).digest()
        )
        counter += 1
    return bytes(output[:length])


def _reader(data: bytes, temporary: str, name: str) -> BinaryReader:
    path = Path(temporary) / name
    path.write_bytes(data)
    return BinaryReader(path)


def _prior(
    left: bytes,
    right: bytes,
    *,
    lower: int = 0x4000,
    upper: int = 0xC000,
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.dual-delta-similarity-comparison/v1",
        "left_artifact_sha256": hashlib.sha256(left).hexdigest(),
        "right_artifact_sha256": hashlib.sha256(right).hexdigest(),
        "classification": {
            "single_dominance_change_model": "CLOSED_BOUNDED_NEGATIVE",
            "grid_control": "REPLICATED_BOUNDED_NEGATIVE",
            "transition_envelope": "UNCHANGED_FROM_SESSION034",
            "exact_section_boundary": "OPEN",
        },
        "search_contract": {
            "envelope_lower": lower,
            "envelope_upper": upper,
            "envelope_width": upper - lower,
            "left_delta": 0x8000,
            "right_delta": -0x3000,
            "left_zone_id": "RZ-012",
            "right_zone_id": "RZ-013",
        },
    }


def _fixture():
    left = bytearray(_stream(0x20000, b"left"))
    right = bytearray(_stream(0x20000, b"right"))
    lower = 0x4000
    tile_size = 0x1000
    pattern = ("left", "left", "right", "right") * 2
    for index, owner in enumerate(pattern):
        start = lower + index * tile_size
        end = start + tile_size
        delta = 0x8000 if owner == "left" else -0x3000
        right[start + delta : end + delta] = left[start:end]
    left_bytes = bytes(left)
    right_bytes = bytes(right)
    return left_bytes, right_bytes, _prior(left_bytes, right_bytes)


def _patched_fixture():
    left, right, _ = _fixture()
    right_array = bytearray(right)
    lower = 0x4000
    mapped_start = lower + 0x8000
    tile = left[lower : lower + 0x1000]
    patched = bytearray()
    for index in range(0, len(tile), 4):
        word = int.from_bytes(tile[index : index + 4], "big")
        patched.extend(((word + 1) & 0xFFFFFFFF).to_bytes(4, "big"))
    right_array[mapped_start : mapped_start + 0x1000] = patched
    right_bytes = bytes(right_array)
    return left, right_bytes, _prior(left, right_bytes)


class ContentIslandAtlasTests(unittest.TestCase):
    def _reports(self):
        left, right, prior = _fixture()
        with TemporaryDirectory() as temporary:
            left_reader = _reader(left, temporary, "left.bin")
            right_reader = _reader(right, temporary, "right.bin")
            primary = analyze_content_island_atlas(
                left_reader, right_reader, prior
            )
            shifted = analyze_content_island_atlas(
                left_reader,
                right_reader,
                prior,
                grid_offset=2048,
            )
        return primary, shifted

    def test_primary_atlas_finds_interleaved_families(self):
        primary, _ = self._reports()
        self.assertEqual(
            primary["summary"]["topology"],
            "MULTIPLE_INTERLEAVED_FAMILIES",
        )
        self.assertEqual(
            primary["summary"]["assignment_counts"]["LEFT_FAMILY"], 4
        )
        self.assertEqual(
            primary["summary"]["assignment_counts"]["RIGHT_FAMILY"], 4
        )
        self.assertEqual(
            primary["summary"]["assignment_change_count"], 3
        )

    def test_half_tile_grid_replicates_multi_island_atlas(self):
        primary, shifted = self._reports()
        control = compare_island_atlas_grid_control(primary, shifted)
        self.assertEqual(
            control["classification"], "REPLICATED_MULTI_ISLAND_ATLAS"
        )
        finalized = finalize_content_island_atlas(primary, shifted)
        self.assertEqual(
            finalized["classification"]["island_atlas"],
            "REPLICATED_MULTIPLE_INTERLEAVED_FAMILIES",
        )

    def test_sparse_one_sided_support_closes_only_multi_island_model(self):
        primary, shifted = self._reports()
        for tile in primary["tiles"]:
            tile["assignment"] = "UNRESOLVED"
        for tile in shifted["tiles"]:
            tile["assignment"] = "UNRESOLVED"
        primary["tiles"][0]["assignment"] = "LEFT_FAMILY"
        shifted["tiles"][0]["assignment"] = "LEFT_FAMILY"
        primary["summary"]["topology"] = "ONE_SIDED_FAMILY_SUPPORT"
        shifted["summary"]["topology"] = "ONE_SIDED_FAMILY_SUPPORT"
        finalized = finalize_content_island_atlas(primary, shifted)
        self.assertEqual(
            finalized["classification"]["island_atlas"],
            "SPARSE_ONE_SIDED_SUPPORT_REPLICATED",
        )
        self.assertEqual(
            finalized["classification"][
                "multiple_interleaved_family_model"
            ],
            "CLOSED_BOUNDED_NEGATIVE",
        )

    def test_repeated_word_difference_candidate_is_anonymous(self):
        left, right, prior = _patched_fixture()
        with TemporaryDirectory() as temporary:
            report = analyze_content_island_atlas(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                prior,
            )
        mapping = report["tiles"][0]["left_mapping"]
        self.assertEqual(
            mapping["classification"],
            "REPEATED_WORD_DELTA_CANDIDATE",
        )
        self.assertTrue(mapping["repeated_word_delta_gate_passed"])
        self.assertFalse(
            mapping["dominant_unequal_word_delta_value_included"]
        )

    def test_search_contract_is_fixed_and_bounded(self):
        primary, _ = self._reports()
        contract = primary["search_contract"]
        self.assertEqual(contract["tile_size"], 4096)
        self.assertEqual(contract["grid_offset"], 0)
        self.assertEqual(contract["left_delta"], 0x8000)
        self.assertEqual(contract["right_delta"], -0x3000)
        self.assertFalse(contract["new_delta_search_performed"])
        self.assertFalse(contract["whole_image_search_performed"])
        self.assertFalse(contract["adaptive_threshold_used"])

    def test_terminal_partial_requires_at_least_half_tile(self):
        left, right, prior = _fixture()
        prior = copy.deepcopy(prior)
        prior["search_contract"]["envelope_upper"] = 0x4000 + 4096 + 2500
        prior["search_contract"]["envelope_width"] = 4096 + 2500
        with TemporaryDirectory() as temporary:
            report = analyze_content_island_atlas(
                _reader(left, temporary, "left.bin"),
                _reader(right, temporary, "right.bin"),
                prior,
            )
        self.assertEqual(len(report["tiles"]), 2)
        self.assertTrue(report["tiles"][-1]["terminal_partial"])
        self.assertEqual(report["tiles"][-1]["length"], 2500)

    def test_public_report_is_detached_and_contains_no_raw_values(self):
        primary, _ = self._reports()
        public = build_public_content_island_atlas_report(primary)
        public["classification"]["exact_section_boundary"] = "changed"
        self.assertEqual(
            primary["classification"]["exact_section_boundary"], "OPEN"
        )
        self.assertTrue(
            all(
                not tile["left_mapping"][
                    "dominant_unequal_word_delta_value_included"
                ]
                for tile in public["tiles"]
            )
        )

    def test_hash_gate_rejects_changed_artifact(self):
        left, right, prior = _fixture()
        changed = bytearray(left)
        changed[-1] ^= 1
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "left principal-image"):
                analyze_content_island_atlas(
                    _reader(bytes(changed), temporary, "left.bin"),
                    _reader(right, temporary, "right.bin"),
                    prior,
                )

    def test_graph_v29_keeps_word_delta_semantics_unproved(self):
        primary, shifted = self._reports()
        finalized = finalize_content_island_atlas(primary, shifted)
        graph = update_operational_graph_v29(
            {
                "schema": "phoenix-mmi.operational-graph/v28",
                "nodes": [],
                "edges": [],
            },
            finalized,
        )
        self.assertEqual(
            graph["schema"], "phoenix-mmi.operational-graph/v29"
        )
        self.assertEqual(
            graph["nodes"][-1]["semantic_status"],
            "CANDIDATE_NOT_RELOCATION_PROOF",
        )


if __name__ == "__main__":
    unittest.main()

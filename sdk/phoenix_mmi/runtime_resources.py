"""Static resource-address references and conservative consumer candidates."""

from __future__ import annotations

from collections import Counter
from typing import Protocol

from .resource_catalog import DecodedEmbeddedResource
from .resource_text import FontCandidate
from .superh import find_pc_relative_referrers


class Reader(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...

    def find_all(
        self,
        needle: bytes,
        *,
        chunk_size: int = 1024 * 1024,
        max_hits: int | None = None,
    ) -> list[int]: ...


def _target_profile(
    reader: Reader, offsets: list[int], *, runtime_base: int
) -> tuple[list[dict[str, int]], set[int]]:
    profiles = []
    referenced_indices: set[int] = set()
    for index, target_offset in enumerate(offsets):
        word_hits = 0
        code_hits = 0
        for value in (target_offset, runtime_base + target_offset):
            if not 0 <= value <= 0xFFFFFFFF:
                continue
            for literal_offset in reader.find_all(
                value.to_bytes(4, "big"), max_hits=128
            ):
                word_hits += 1
                code_hits += len(
                    find_pc_relative_referrers(reader, literal_offset)
                )
        if word_hits:
            referenced_indices.add(index)
        profiles.append(
            {
                "target_index": index,
                "literal_word_occurrence_count": word_hits,
                "pc_relative_code_referrer_count": code_hits,
            }
        )
    return profiles, referenced_indices


def analyze_resource_consumers(
    readers: dict[str, Reader],
    embedded: dict[str, tuple[DecodedEmbeddedResource, ...]],
    fonts: dict[str, tuple[FontCandidate, ...]],
    *,
    runtime_base: int = 0x0C000000,
) -> tuple[dict[str, object], dict[str, object]]:
    if sorted(readers) != ["cd1", "cd3"]:
        raise ValueError("resource consumer analysis requires cd1 and cd3")
    if sorted(embedded) != ["cd1", "cd3"] or sorted(fonts) != ["cd1", "cd3"]:
        raise ValueError("resource and font inputs require cd1 and cd3")
    public_artifacts = []
    private_artifacts = {}
    referenced_digests: dict[str, set[str]] = {}
    for release in ("cd1", "cd3"):
        reader = readers[release]
        resources = embedded[release]
        resource_offsets = [
            item.record.offset
            for item in resources
            if item.record.offset is not None
        ]
        resource_profiles, referenced = _target_profile(
            reader, resource_offsets, runtime_base=runtime_base
        )
        font_profiles, referenced_font_indices = _target_profile(
            reader,
            [item.offset for item in fonts[release]],
            runtime_base=runtime_base,
        )
        referenced_digests[release] = {
            resources[index].record.decoded_sha256 for index in referenced
        }
        public_artifacts.append(
            {
                "artifact": release,
                "embedded_resource_count": len(resources),
                "resources_with_literal_address_words": len(referenced),
                "resource_literal_word_occurrence_count": sum(
                    row["literal_word_occurrence_count"]
                    for row in resource_profiles
                ),
                "resource_pc_relative_code_referrer_count": sum(
                    row["pc_relative_code_referrer_count"]
                    for row in resource_profiles
                ),
                "validated_font_container_count": len(fonts[release]),
                "fonts_with_literal_address_words": len(
                    referenced_font_indices
                ),
                "font_literal_word_occurrence_count": sum(
                    row["literal_word_occurrence_count"]
                    for row in font_profiles
                ),
                "font_pc_relative_code_referrer_count": sum(
                    row["pc_relative_code_referrer_count"]
                    for row in font_profiles
                ),
            }
        )
        private_artifacts[release] = {
            "resource_profiles": resource_profiles,
            "font_profiles": font_profiles,
        }
    evidence_classes = Counter()
    for row in public_artifacts:
        if row["resource_pc_relative_code_referrer_count"]:
            evidence_classes["CODE_COUPLED_RESOURCE_ADDRESS"] += 1
        elif row["resource_literal_word_occurrence_count"]:
            evidence_classes["DATA_WORD_RESOURCE_ADDRESS"] += 1
        else:
            evidence_classes["NO_EXACT_ADDRESS_REFERENCE"] += 1
    public = {
        "schema": "phoenix-mmi.runtime-resource-consumer-matrix/v1",
        "analysis_mode": "exact-address-words-and-pc-relative-referrer-gate",
        "runtime_address_model": {
            "name": "runtime-link-base",
            "status": "CONFIRMED_BOUNDED_STATIC_MODEL",
        },
        "artifacts": public_artifacts,
        "evidence_class_counts": dict(sorted(evidence_classes.items())),
        "cross_version": {
            "shared_referenced_resource_content_count": len(
                referenced_digests["cd1"] & referenced_digests["cd3"]
            ),
            "cd1_only_referenced_resource_content_count": len(
                referenced_digests["cd1"] - referenced_digests["cd3"]
            ),
            "cd3_only_referenced_resource_content_count": len(
                referenced_digests["cd3"] - referenced_digests["cd1"]
            ),
        },
        "classification": {
            "exact_static_resource_address_evidence": "CONFIRMED_BOUNDED",
            "pc_relative_resource_consumer_candidate": (
                "CONFIRMED_STRUCTURAL_CANDIDATE"
                if any(
                    row["resource_pc_relative_code_referrer_count"]
                    for row in public_artifacts
                )
                else "NOT_FOUND_UNDER_EXACT_PC_RELATIVE_MODEL"
            ),
            "renderer_consumer_identity": "NOT_ESTABLISHED",
            "resource_lifecycle": "NOT_ESTABLISHED",
            "runtime_rendering_observed": False,
        },
        "publication_safety": {
            "resource_offsets_included": False,
            "resource_hashes_included": False,
            "font_offsets_included": False,
            "firmware_bytes_included": False,
            "extracted_resources_included": False,
            "runtime_execution_observed": False,
        },
    }
    private = {
        "schema": "phoenix-mmi.runtime-resource-consumer-private/v1",
        "publication_class": "PRIVATE_LOCAL",
        "artifacts": private_artifacts,
    }
    return public, private

"""Read-only executable-layout heuristics for the principal MMI image."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import hashlib

from .binary import BinaryReader
from .superh import find_pc_relative_referrers, trace_control_flow


VXWORKS_MARKERS: tuple[bytes, ...] = (
    b"Copyright 1984-1998 Wind River Systems, Inc.",
    b"VxWorks",
    b"Wind River",
)

VXWORKS_SYMBOL_PROBES: tuple[bytes, ...] = (
    b"sysSymTbl",
    b"symTbl",
    b"usrInit",
    b"usrRoot",
    b"sysInit",
    b"kernelInit",
    b"moduleLib",
    b"loadModule",
    b"taskSpawn",
)


def _fixed_marker_hits(reader: BinaryReader, markers: Iterable[bytes]) -> dict[str, object]:
    result: dict[str, object] = {}
    for marker in markers:
        offsets = reader.find_all(marker)
        result[marker.decode("ascii")] = {"count": len(offsets), "offsets": offsets}
    return result


def _encoded_target_occurrences(
    reader: BinaryReader,
    target: int,
    *,
    flash_base: int,
    max_hits: int = 64,
) -> list[dict[str, object]]:
    occurrences: list[dict[str, object]] = []
    for address_model, value in (("file-offset", target), ("flash-address", flash_base + target)):
        if not 0 <= value <= 0xFFFFFFFF:
            continue
        for occurrence in reader.find_all(value.to_bytes(4, "big"), max_hits=max_hits):
            referrers = find_pc_relative_referrers(reader, occurrence)
            occurrences.append(
                {
                    "address_model": address_model,
                    "literal_offset": occurrence,
                    "pc_relative_referrers": [item.offset for item in referrers],
                }
            )
    return occurrences


def analyze_startup(
    reader: BinaryReader,
    *,
    flash_base: int,
    trace_end: int = 0x10000,
    public_trace_limit: int = 48,
) -> dict[str, object]:
    instructions = trace_control_flow(reader, end=trace_end)
    by_offset = {instruction.offset: instruction for instruction in instructions}
    expected = (
        (0x0, "bra", 0x8),
        (0x2, "nop", None),
        (0x8, "mov.l", None),
        (0xA, "ldc", None),
        (0xC, "mova", 0x1F0),
        (0xE, "ldc.l", None),
        (0x10, "mov.w", None),
        (0x14, "bra", 0x50),
        (0x16, "nop", None),
    )
    matches = []
    for offset, mnemonic, target in expected:
        item = by_offset.get(offset)
        matches.append(
            bool(
                item
                and item.mnemonic == mnemonic
                and (target is None or item.target == target)
            )
        )
    first_load = by_offset.get(0x8)
    literal_instructions = [
        item for item in instructions if item.literal_address is not None
    ]
    address_candidates: list[dict[str, object]] = []
    for item in literal_instructions:
        if item.literal_value is None or item.mnemonic != "mov.l":
            continue
        models = []
        if 0 <= item.literal_value < reader.size:
            models.append({"model": "file-offset", "target_file_offset": item.literal_value})
        if flash_base <= item.literal_value < flash_base + reader.size:
            models.append(
                {
                    "model": "flash-address",
                    "target_file_offset": item.literal_value - flash_base,
                }
            )
        if models:
            address_candidates.append(
                {
                    "instruction_offset": item.offset,
                    "literal_offset": item.literal_address,
                    "models": models,
                }
            )
    banner_is_skipped = bool(
        by_offset.get(0x14)
        and by_offset[0x14].target == 0x50
        and 0x18 <= 0x20 < by_offset[0x14].target
    )
    traced_region_end = (max(by_offset) + 2) if by_offset else 0
    traced_region_sha256 = hashlib.sha256(
        reader.read(0, traced_region_end)
    ).hexdigest()
    return {
        "architecture": "SuperH SH-3 big-endian",
        "entry_file_offset": 0,
        "trace_limit": min(trace_end, reader.size),
        "reachable_instruction_count": len(instructions),
        "maximum_reached_offset": max(by_offset) if by_offset else None,
        "traced_region_end": traced_region_end,
        "traced_region_sha256": traced_region_sha256,
        "unknown_instruction_count": sum(item.mnemonic == "unknown" for item in instructions),
        "flow_counts": dict(sorted(Counter(item.flow for item in instructions).items())),
        "pc_relative_literal_count": sum(
            item.literal_address is not None for item in instructions
        ),
        "pc_relative_literal_offsets": sorted(
            {item.literal_address for item in literal_instructions}
        ),
        "absolute_address_candidates_from_mov_l": address_candidates,
        "startup_pattern_confirmed": all(matches),
        "initial_sr_literal": (
            first_load.literal_value if first_load and first_load.literal_address == 0x4C else None
        ),
        "wind_river_banner_file_offset": 0x20,
        "wind_river_banner_skipped_by_branch": banner_is_skipped,
        "public_trace": [item.to_dict() for item in instructions[:public_trace_limit]],
        "instruction_bytes_included": False,
    }


def analyze_vxworks_layout(reader: BinaryReader, *, flash_base: int) -> dict[str, object]:
    runtime_markers = _fixed_marker_hits(reader, VXWORKS_MARKERS)
    probes = _fixed_marker_hits(reader, VXWORKS_SYMBOL_PROBES)
    present_probes = {
        name: data for name, data in probes.items() if int(data["count"]) > 0
    }
    probe_references: dict[str, object] = {}
    for name, data in present_probes.items():
        per_offset = []
        for offset in data["offsets"]:
            occurrences = _encoded_target_occurrences(reader, offset, flash_base=flash_base)
            if occurrences:
                per_offset.append({"marker_offset": offset, "occurrences": occurrences})
        if per_offset:
            probe_references[name] = per_offset
    canonical_names = {"sysSymTbl", "symTbl", "usrInit", "usrRoot", "sysInit"}
    canonical_found = sorted(canonical_names & set(present_probes))
    return {
        "runtime_markers": runtime_markers,
        "symbol_probe_set": [probe.decode("ascii") for probe in VXWORKS_SYMBOL_PROBES],
        "symbol_probes_present": present_probes,
        "symbol_probe_references": probe_references,
        "canonical_symbol_names_found": canonical_found,
        "symbol_or_module_table_status": (
            "CANDIDATE" if canonical_found and probe_references else "NOT_CONFIRMED"
        ),
        "interpretation": (
            "Fixed-name probes can reject or nominate a table candidate; they do not prove "
            "a VxWorks symbol/module table without a validated record layout."
        ),
    }


def analyze_resource_references(
    reader: BinaryReader,
    resources: list[dict[str, object]],
    filler_runs: list[dict[str, object]],
    *,
    flash_base: int,
) -> dict[str, object]:
    if not resources:
        return {"status": "NOT_TESTED", "reason": "no validated resource metadata"}
    starts = [int(resource["offset"]) for resource in resources]
    ends = [int(resource["offset"]) + int(resource["length"]) for resource in resources]
    cluster_start = min(starts)
    cluster_end = max(ends)
    target_labels: dict[int, list[str]] = {
        cluster_start: ["cluster-start"],
        cluster_end: ["cluster-end"],
    }
    for index, offset in enumerate(starts):
        target_labels.setdefault(offset, []).append(f"resource-{index:02d}-start")

    direct_candidates = []
    for target, labels in sorted(target_labels.items()):
        occurrences = _encoded_target_occurrences(reader, target, flash_base=flash_base)
        if occurrences:
            direct_candidates.append(
                {"labels": labels, "target_file_offset": target, "occurrences": occurrences}
            )

    preceding = [run for run in filler_runs if int(run["end"]) <= cluster_start]
    following = [run for run in filler_runs if int(run["offset"]) >= cluster_end]
    previous_run = max(preceding, key=lambda run: int(run["end"])) if preceding else None
    next_run = min(following, key=lambda run: int(run["offset"])) if following else None
    island = None
    if previous_run and next_run:
        island_start = int(previous_run["end"])
        island_end = int(next_run["offset"])
        island = {
            "status": "PROBABLE_RESOURCE_ISLAND",
            "offset": island_start,
            "end": island_end,
            "length": island_end - island_start,
            "resource_cluster_offset_within_island": cluster_start - island_start,
        }
    return {
        "status": "TESTED",
        "address_models_tested": ["big-endian file offset", "big-endian flash-base + offset"],
        "flash_base": flash_base,
        "resource_count": len(resources),
        "cluster": {
            "offset": cluster_start,
            "end": cluster_end,
            "length": cluster_end - cluster_start,
        },
        "preceding_filler": previous_run,
        "gap_after_preceding_filler": (
            cluster_start - int(previous_run["end"]) if previous_run else None
        ),
        "following_filler": next_run,
        "gap_before_following_filler": (
            int(next_run["offset"]) - cluster_end if next_run else None
        ),
        "filler_bounded_island": island,
        "direct_reference_candidates": direct_candidates,
        "direct_reference_candidate_count": len(direct_candidates),
        "interpretation": (
            "Zero exact candidates is a bounded negative result for the two tested absolute "
            "address encodings. Relative, indexed or runtime-built resource tables remain possible."
        ),
    }


def analyze_executable_layout(
    reader: BinaryReader,
    *,
    flash_base: int,
    resources: list[dict[str, object]],
    filler_runs: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.executable-layout/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "filename": reader.path.name,
            "size_bytes": reader.size,
            "sha256": reader.sha256(),
            "flash_base_from_metainfo": flash_base,
        },
        "startup": analyze_startup(reader, flash_base=flash_base),
        "vxworks": analyze_vxworks_layout(reader, flash_base=flash_base),
        "resources": analyze_resource_references(
            reader,
            resources,
            filler_runs,
            flash_base=flash_base,
        ),
        "publication_safety": {
            "payload_bytes_included": False,
            "instruction_bytes_included": False,
            "raw_strings_included": False,
            "resources_exported": False,
        },
    }

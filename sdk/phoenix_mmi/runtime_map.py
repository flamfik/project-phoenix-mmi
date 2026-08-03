"""Bounded runtime-address mapping for MMI principal-image research.

The module never executes firmware and never infers a target owner from an
address alone.  Address models are explicit, competing models remain visible,
and cross-version equality is reported separately from structural mapping.
"""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import asdict, dataclass
import hashlib
import re
from typing import Iterable

from .binary import BinaryReader
from .superh import SHInstruction, decode_instruction


@dataclass(frozen=True)
class AddressModel:
    name: str
    base: int
    rationale: str

    def map(self, address: int) -> int:
        return address - self.base

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def default_address_models(
    *, runtime_base: int = 0x0C000000, flash_base: int = 0x00060000
) -> tuple[AddressModel, ...]:
    """Return only independently motivated address models."""

    return (
        AddressModel(
            "raw-file-address",
            0,
            "Treat the stored value directly as a file offset.",
        ),
        AddressModel(
            "metainfo-flash-address",
            flash_base,
            "Subtract METAINFO FlashStartAddress.",
        ),
        AddressModel(
            "runtime-base-minus-flash",
            runtime_base - flash_base,
            "Test a runtime base shifted down by FlashStartAddress.",
        ),
        AddressModel(
            "runtime-link-base",
            runtime_base,
            "Subtract the runtime base observed in bounded MOV.L/JSR code probes.",
        ),
        AddressModel(
            "runtime-base-plus-flash",
            runtime_base + flash_base,
            "Test a runtime base shifted up by FlashStartAddress.",
        ),
    )


def _pointer_runs(bundle_report: dict[str, object]) -> list[list[int]]:
    raw_runs = bundle_report.get("_internal_pointer_runs")
    if not isinstance(raw_runs, list):
        raise ValueError("resource-bundle report has no internal pointer runs")
    return [
        [int(value) for value in run["values"]]
        for run in raw_runs
    ]


def _mov_l_destination(instruction: SHInstruction) -> int | None:
    if instruction.mnemonic != "mov.l" or instruction.literal_value is None:
        return None
    match = re.search(r",r(\d+)$", instruction.operands)
    return int(match.group(1)) if match else None


def find_link_base_evidence(
    reader: BinaryReader,
    *,
    runtime_base: int = 0x0C000000,
    search_end: int = 0x2000,
    lookahead_halfwords: int = 4,
) -> dict[str, object]:
    """Find bounded MOV.L base loads followed by indirect call-target loads."""

    end = min(reader.size - 1, search_end)
    base_loads: list[dict[str, object]] = []
    call_sequences: list[dict[str, object]] = []
    for offset in range(0, end, 2):
        instruction = decode_instruction(reader, offset)
        if instruction.mnemonic != "mov.l" or instruction.literal_value != runtime_base:
            continue
        destination = _mov_l_destination(instruction)
        base_loads.append(
            {
                "instruction_offset": offset,
                "literal_offset": instruction.literal_address,
                "destination_register": destination,
            }
        )
        for distance in range(1, lookahead_halfwords + 1):
            load_offset = offset + distance * 2
            if load_offset + 3 >= end:
                break
            target_load = decode_instruction(reader, load_offset)
            target_register = _mov_l_destination(target_load)
            target = target_load.literal_value
            if (
                target_register is None
                or target is None
                or not runtime_base <= target < runtime_base + reader.size
            ):
                continue
            call = decode_instruction(reader, load_offset + 2)
            if call.mnemonic != "jsr" or call.operands != f"@r{target_register}":
                continue
            call_sequences.append(
                {
                    "base_load_offset": offset,
                    "base_literal_offset": instruction.literal_address,
                    "base_destination_register": destination,
                    "target_load_offset": load_offset,
                    "target_literal_offset": target_load.literal_address,
                    "target_runtime_address": target,
                    "target_file_offset": target - runtime_base,
                    "call_offset": load_offset + 2,
                    "call_register": target_register,
                }
            )
            break
    return {
        "runtime_base": runtime_base,
        "search_start": 0,
        "search_end": end,
        "base_literal_load_count": len(base_loads),
        "base_literal_loads": base_loads,
        "coherent_indirect_call_sequence_count": len(call_sequences),
        "coherent_indirect_call_sequences": call_sequences,
        "instruction_bytes_included": False,
        "interpretation": (
            "A base literal plus a same-range target load and matching JSR is stronger "
            "evidence than a bare 32-bit occurrence, but remains a bounded static probe."
        ),
    }


def _region_name(
    offset: int,
    *,
    size: int,
    startup_end: int,
    browser_island: dict[str, object],
    browser_core: dict[str, object],
    filler_runs: Iterable[dict[str, object]],
) -> str:
    if not 0 <= offset < size:
        return "out-of-image"
    if offset == 0:
        return "image-entry"
    if offset < startup_end:
        return "startup-prefix"
    for run in filler_runs:
        if int(run["offset"]) <= offset < int(run["end"]):
            return "long-filler-run"
    core_start = int(browser_core["offset"])
    core_end = int(browser_core["end"])
    island_start = int(browser_island["offset"])
    island_end = int(browser_island["end"])
    if core_start <= offset < core_end:
        return "browser-resource-core"
    if island_start <= offset < island_end:
        return "browser-post-cluster"
    if offset < island_start:
        return "pre-browser-unresolved"
    return "post-browser-unresolved"


def evaluate_address_model(
    reader: BinaryReader,
    runs: list[list[int]],
    model: AddressModel,
    *,
    browser_island: dict[str, object],
    browser_core: dict[str, object],
    filler_runs: Iterable[dict[str, object]],
    startup_end: int = 0x10000,
) -> dict[str, object]:
    values = [value for run in runs for value in run]
    mapped = [model.map(value) for value in values]
    in_bounds = [offset for offset in mapped if 0 <= offset < reader.size]
    region_counts = Counter(
        _region_name(
            offset,
            size=reader.size,
            startup_end=startup_end,
            browser_island=browser_island,
            browser_core=browser_core,
            filler_runs=filler_runs,
        )
        for offset in mapped
    )
    return {
        "model": model.to_dict(),
        "target_count": len(values),
        "unique_runtime_address_count": len(set(values)),
        "in_image_count": len(in_bounds),
        "out_of_image_count": len(values) - len(in_bounds),
        "in_image_four_byte_aligned_count": sum(offset % 4 == 0 for offset in in_bounds),
        "maps_model_base_value_to_entry": model.map(model.base) == 0 and model.base in values,
        "mapped_minimum": min(in_bounds) if in_bounds else None,
        "mapped_maximum": max(in_bounds) if in_bounds else None,
        "region_counts": dict(sorted(region_counts.items())),
    }


def _summarize_selected_run(
    reader: BinaryReader,
    values: list[int],
    model: AddressModel,
    *,
    browser_island: dict[str, object],
    browser_core: dict[str, object],
    filler_runs: Iterable[dict[str, object]],
) -> dict[str, object]:
    mapped = [model.map(value) for value in values]
    in_bounds = [offset for offset in mapped if 0 <= offset < reader.size]
    unique = sorted(set(in_bounds))
    strides = [right - left for left, right in zip(unique, unique[1:])]
    stride_counts = Counter(strides)
    stride_mode, stride_support = (
        stride_counts.most_common(1)[0] if stride_counts else (None, 0)
    )
    regions = Counter(
        _region_name(
            offset,
            size=reader.size,
            startup_end=0x10000,
            browser_island=browser_island,
            browser_core=browser_core,
            filler_runs=filler_runs,
        )
        for offset in mapped
    )
    return {
        "entry_count": len(values),
        "unique_entry_count": len(set(values)),
        "in_image_count": len(in_bounds),
        "four_byte_aligned_count": sum(offset % 4 == 0 for offset in in_bounds),
        "mapped_minimum": min(in_bounds) if in_bounds else None,
        "mapped_maximum": max(in_bounds) if in_bounds else None,
        "unique_target_stride_mode": stride_mode,
        "unique_target_stride_mode_support": stride_support,
        "region_counts": dict(sorted(regions.items())),
    }


def analyze_runtime_map(
    reader: BinaryReader,
    bundle_report: dict[str, object],
    *,
    filler_runs: Iterable[dict[str, object]],
    runtime_base: int = 0x0C000000,
    flash_base: int = 0x00060000,
) -> dict[str, object]:
    """Evaluate explicit models and retain target values only in the local report."""

    runs = _pointer_runs(bundle_report)
    filler_runs = list(filler_runs)
    browser_island = bundle_report["island"]
    browser_core = bundle_report["core_bundle"]
    models = default_address_models(runtime_base=runtime_base, flash_base=flash_base)
    model_reports = [
        evaluate_address_model(
            reader,
            runs,
            model,
            browser_island=browser_island,
            browser_core=browser_core,
            filler_runs=filler_runs,
        )
        for model in models
    ]
    selected = next(model for model in models if model.name == "runtime-link-base")
    selected_report = next(
        report for report in model_reports if report["model"]["name"] == selected.name
    )
    link_evidence = find_link_base_evidence(reader, runtime_base=runtime_base)
    base_is_present = any(runtime_base in run for run in runs)
    selection_confirmed = bool(
        link_evidence["coherent_indirect_call_sequence_count"]
        and selected_report["in_image_count"] == selected_report["target_count"]
        and selected_report["maps_model_base_value_to_entry"]
        and base_is_present
    )
    return {
        "schema": "phoenix-mmi.runtime-address-map/v1",
        "analysis_mode": "read-only-static",
        "artifact": {
            "filename": reader.path.name,
            "sha256": reader.sha256(),
            "size_bytes": reader.size,
        },
        "inputs": {
            "runtime_base_candidate": runtime_base,
            "metainfo_flash_base": flash_base,
            "pointer_run_count_signature": [len(run) for run in runs],
            "pointer_entry_count": sum(len(run) for run in runs),
        },
        "region_boundaries": {
            "startup_end": 0x10000,
            "browser_core_offset": int(browser_core["offset"]),
            "browser_core_end": int(browser_core["end"]),
            "browser_island_offset": int(browser_island["offset"]),
            "browser_island_end": int(browser_island["end"]),
        },
        "link_base_evidence": link_evidence,
        "address_model_evaluations": model_reports,
        "selected_model": {
            "name": selected.name,
            "base": selected.base,
            "status": (
                "CONFIRMED_BOUNDED_STATIC_MODEL"
                if selection_confirmed
                else "PROBABLE"
            ),
            "selection_was_score_optimized": False,
            "selection_basis": [
                "bounded coherent MOV.L/JSR sequences",
                "all pointer-run values map inside the principal image",
                "the exact base value maps to the confirmed image entry",
            ],
        },
        "selected_model_runs": [
            _summarize_selected_run(
                reader,
                values,
                selected,
                browser_island=browser_island,
                browser_core=browser_core,
                filler_runs=filler_runs,
            )
            for values in runs
        ],
        "ownership": {
            "browser_resource_target_count": (
                selected_report["region_counts"].get("browser-resource-core", 0)
                + selected_report["region_counts"].get("browser-post-cluster", 0)
            ),
            "status": "NOT_CONFIRMED",
            "interpretation": (
                "Mapping a stored table to earlier principal-image regions does not identify "
                "the code or subsystem that owns the table."
            ),
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "target_window_bytes_included": False,
            "raw_strings_included": False,
            "raw_pointer_run_values_included": False,
            "code_probe_addresses_included": True,
        },
        "_internal_pointer_runs": runs,
    }


def build_public_runtime_map(report: dict[str, object]) -> dict[str, object]:
    public = copy.deepcopy(report)
    public.pop("_internal_pointer_runs", None)
    return public


def _mapped_region(report: dict[str, object], offset: int) -> str:
    artifact_size = int(report["artifact"]["size_bytes"])
    if not 0 <= offset < artifact_size:
        return "out-of-image"
    if offset == 0:
        return "image-entry"
    boundaries = report["region_boundaries"]
    if offset < int(boundaries["startup_end"]):
        return "startup-prefix"
    if int(boundaries["browser_core_offset"]) <= offset < int(
        boundaries["browser_core_end"]
    ):
        return "browser-resource-core"
    if int(boundaries["browser_island_offset"]) <= offset < int(
        boundaries["browser_island_end"]
    ):
        return "browser-post-cluster"
    if offset < int(boundaries["browser_island_offset"]):
        return "pre-browser-unresolved"
    return "post-browser-unresolved"


def _detect_relocated_record_block(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    pairs: list[tuple[int, int]],
    *,
    runtime_base: int,
    minimum_records: int = 3,
) -> dict[str, object] | None:
    deltas = Counter(right - left for left, right in pairs)
    if not deltas:
        return None
    delta_mode, delta_support = deltas.most_common(1)[0]
    selected = sorted(
        {(left - runtime_base, right - runtime_base) for left, right in pairs if right - left == delta_mode}
    )
    if len(selected) < minimum_records:
        return None
    left_offsets = [left for left, _ in selected]
    right_offsets = [right for _, right in selected]
    left_steps = [b - a for a, b in zip(left_offsets, left_offsets[1:])]
    right_steps = [b - a for a, b in zip(right_offsets, right_offsets[1:])]
    if not left_steps or len(set(left_steps)) != 1 or left_steps != right_steps:
        return None
    stride = left_steps[0]
    if stride <= 0 or stride > 256:
        return None
    if any(
        left < 0
        or right < 0
        or left + stride > left_reader.size
        or right + stride > right_reader.size
        for left, right in selected
    ):
        return None
    if any(
        left_reader.read(left, stride) != right_reader.read(right, stride)
        for left, right in selected
    ):
        return None
    left_start = left_offsets[0]
    right_start = right_offsets[0]
    length = len(selected) * stride
    if left_start + length > left_reader.size or right_start + length > right_reader.size:
        return None
    left_block = left_reader.read(left_start, length)
    right_block = right_reader.read(right_start, length)
    if left_block != right_block:
        return None
    return {
        "runtime_address_delta": delta_mode,
        "delta_support_entry_count": delta_support,
        "unique_record_count": len(selected),
        "record_stride": stride,
        "block_length": length,
        "left_file_offset": left_start,
        "right_file_offset": right_start,
        "block_sha256": hashlib.sha256(left_block).hexdigest(),
        "blocks_equal": True,
        "raw_bytes_included": False,
    }


def compare_runtime_maps(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    left: dict[str, object],
    right: dict[str, object],
    *,
    window_sizes: tuple[int, ...] = (4, 16, 64),
) -> dict[str, object]:
    left_runs = left["_internal_pointer_runs"]
    right_runs = right["_internal_pointer_runs"]
    signatures = ([len(run) for run in left_runs], [len(run) for run in right_runs])
    if signatures[0] != signatures[1]:
        raise ValueError("pointer-run count signatures differ")
    left_models = {
        item["model"]["name"]: int(item["model"]["base"])
        for item in left["address_model_evaluations"]
    }
    right_models = {
        item["model"]["name"]: int(item["model"]["base"])
        for item in right["address_model_evaluations"]
    }
    if left_models != right_models:
        raise ValueError("address-model sets differ")
    flat_pairs = [
        (int(left_value), int(right_value))
        for left_run, right_run in zip(left_runs, right_runs)
        for left_value, right_value in zip(left_run, right_run)
    ]
    model_comparisons = []
    for name, base in left_models.items():
        in_bounds_pairs = []
        exact = Counter()
        for left_value, right_value in flat_pairs:
            left_offset = left_value - base
            right_offset = right_value - base
            in_bounds = (
                0 <= left_offset < left_reader.size
                and 0 <= right_offset < right_reader.size
            )
            if not in_bounds:
                continue
            in_bounds_pairs.append((left_offset, right_offset))
            for size in window_sizes:
                if left_reader.read(left_offset, size) == right_reader.read(right_offset, size):
                    exact[size] += 1
        model_comparisons.append(
            {
                "model": name,
                "base": base,
                "both_in_image_count": len(in_bounds_pairs),
                "exact_target_window_counts": {
                    str(size): exact[size] for size in window_sizes
                },
            }
        )
    runtime_base = int(left["selected_model"]["base"])
    per_run = []
    blocks = []
    for index, (left_run, right_run) in enumerate(zip(left_runs, right_runs)):
        pairs = [(int(a), int(b)) for a, b in zip(left_run, right_run)]
        exact = Counter()
        unique_exact: dict[int, set[tuple[int, int]]] = {
            size: set() for size in window_sizes
        }
        region_pairs = Counter()
        both_in_bounds = 0
        for left_value, right_value in pairs:
            left_offset = left_value - runtime_base
            right_offset = right_value - runtime_base
            if not (
                0 <= left_offset < left_reader.size
                and 0 <= right_offset < right_reader.size
            ):
                continue
            both_in_bounds += 1
            region_pairs[
                f"{_mapped_region(left, left_offset)} -> {_mapped_region(right, right_offset)}"
            ] += 1
            for size in window_sizes:
                if left_reader.read(left_offset, size) == right_reader.read(right_offset, size):
                    exact[size] += 1
                    unique_exact[size].add((left_offset, right_offset))
        valid_pairs = [
            (left_value, right_value)
            for left_value, right_value in pairs
            if 0 <= left_value - runtime_base < left_reader.size
            and 0 <= right_value - runtime_base < right_reader.size
        ]
        block = _detect_relocated_record_block(
            left_reader,
            right_reader,
            valid_pairs,
            runtime_base=runtime_base,
        )
        if block:
            block["run_index"] = index
            blocks.append(block)
        per_run.append(
            {
                "run_index": index,
                "entry_count": len(pairs),
                "unique_pair_count": len(set(pairs)),
                "both_in_image_count": both_in_bounds,
                "exact_target_window_counts": {
                    str(size): exact[size] for size in window_sizes
                },
                "unique_exact_target_window_counts": {
                    str(size): len(unique_exact[size]) for size in window_sizes
                },
                "region_pair_counts": dict(sorted(region_pairs.items())),
                "evidence_status": (
                    "CONFIRMED_RELOCATED_RECORD_BLOCK"
                    if block
                    else (
                        "PARTIAL_EXACT_TARGETS"
                        if exact[max(window_sizes)]
                        else "MAPPED_WITHOUT_EXACT_CROSS_VERSION_TARGET"
                    )
                ),
            }
        )
    selected_model_comparison = next(
        item for item in model_comparisons if item["model"] == "runtime-link-base"
    )
    left_calls = left["link_base_evidence"]["coherent_indirect_call_sequences"]
    right_calls = right["link_base_evidence"]["coherent_indirect_call_sequences"]
    code_probe_pairs = list(zip(left_calls, right_calls))
    probe_exact = Counter()
    for left_call, right_call in code_probe_pairs:
        left_offset = int(left_call["target_file_offset"])
        right_offset = int(right_call["target_file_offset"])
        if not (
            0 <= left_offset < left_reader.size
            and 0 <= right_offset < right_reader.size
        ):
            continue
        for size in window_sizes:
            if left_reader.read(left_offset, size) == right_reader.read(right_offset, size):
                probe_exact[size] += 1
    return {
        "schema": "phoenix-mmi.runtime-address-map-comparison/v1",
        "left": left["artifact"]["label"],
        "right": right["artifact"]["label"],
        "pointer_run_count_signature": signatures[0],
        "address_model_comparisons": model_comparisons,
        "selected_model": {
            "name": "runtime-link-base",
            "base": runtime_base,
            "both_in_image_count": selected_model_comparison["both_in_image_count"],
            "exact_target_window_counts": selected_model_comparison[
                "exact_target_window_counts"
            ],
        },
        "link_base_evidence_comparison": {
            "left_call_sequence_count": len(left_calls),
            "right_call_sequence_count": len(right_calls),
            "structural_offset_match_count": sum(
                left_call["base_load_offset"] == right_call["base_load_offset"]
                and left_call["target_load_offset"] == right_call["target_load_offset"]
                and left_call["call_offset"] == right_call["call_offset"]
                for left_call, right_call in code_probe_pairs
            ),
            "same_target_file_offset_count": sum(
                left_call["target_file_offset"] == right_call["target_file_offset"]
                for left_call, right_call in code_probe_pairs
            ),
            "exact_target_window_counts": {
                str(size): probe_exact[size] for size in window_sizes
            },
        },
        "per_run": per_run,
        "relocated_record_blocks": blocks,
        "ownership_status": "NOT_CONFIRMED",
        "interpretation": (
            "The selected model is independently supported by code probes. Exact relocated "
            "targets confirm one record block, not the ownership of every mapped run."
        ),
        "publication_safety": {
            "firmware_bytes_included": False,
            "target_window_bytes_included": False,
            "raw_strings_included": False,
            "raw_pointer_run_values_included": False,
            "code_probe_addresses_included": True,
        },
    }

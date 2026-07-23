"""Bounded interprocedural SH call graph for optical/navigation research.

Session 015 accepts only direct BSR targets or register targets whose value can
be traced to an in-image PC-relative literal.  Record-neighborhood pointers are
seeds, never function claims by themselves.  No instruction bytes, raw strings,
absolute runtime addresses or firmware payloads are returned.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import hashlib
import re

from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .superh import SHInstruction, decode_instruction_extended


_REGISTER = re.compile(r"r(\d+)")
_REGISTER_MOVE = re.compile(r"r(\d+),r(\d+)$")
_IMMEDIATE_MOVE = re.compile(r"#(-?\d+),r(\d+)$")
_IMMEDIATE_ADD = re.compile(r"#(-?\d+),r(\d+)$")
_PC_DESTINATION = re.compile(r"@\([^)]*,pc\),r(\d+)$")
_MEMORY_DESTINATION = re.compile(r"@\((\d+),r(\d+)\),r(\d+)$")
_INDIRECT_DESTINATION = re.compile(r"@r(\d+)\+?,r(\d+)$")
_ADDRESS = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)


def _decode_window(
    reader: BinaryReader, entry: int, *, maximum_bytes: int = 0x180
) -> list[SHInstruction]:
    if entry < 0 or entry >= reader.size or entry & 1:
        return []
    end = min(reader.size, entry + maximum_bytes) & ~1
    instructions = []
    for offset in range(entry, end, 2):
        instruction = decode_instruction_extended(reader, offset)
        instructions.append(instruction)
        if instruction.flow == "return" and len(instructions) >= 4:
            if instruction.delayed and offset + 2 < end:
                instructions.append(decode_instruction_extended(reader, offset + 2))
            break
    return instructions


def _normalized_shape(instructions: list[SHInstruction]) -> str:
    rows = [
        "|".join(
            (
                item.mnemonic,
                _ADDRESS.sub("<address>", item.operands),
                item.flow,
                "delayed" if item.delayed else "plain",
            )
        )
        for item in instructions
    ]
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def _destination_register(instruction: SHInstruction) -> int | None:
    if instruction.mnemonic in {
        "cmp/eq",
        "cmp/hs",
        "cmp/ge",
        "cmp/hi",
        "cmp/gt",
        "cmp/str",
        "tst",
    }:
        return None
    if instruction.mnemonic == "mova":
        return 0
    if instruction.mnemonic in {"add", "sub", "and", "or", "xor", "mov", "mov.b", "mov.w", "mov.l", "swap.b", "swap.w", "xtrct"}:
        match = re.search(r",r(\d+)$", instruction.operands)
        return int(match.group(1)) if match is not None else None
    if instruction.mnemonic == "shlr2":
        match = re.fullmatch(r"r(\d+)", instruction.operands)
        return int(match.group(1)) if match is not None else None
    return None


def _origin_class(origin: dict[str, object]) -> str:
    return str(origin.get("status", "UNKNOWN"))


def _trace_register(
    instructions: list[SHInstruction],
    before_index: int,
    register: int,
    *,
    image_size: int,
    depth: int = 0,
) -> dict[str, object]:
    """Trace one register conservatively through a linear bounded prefix."""

    if depth > 16:
        return {"status": "DEPTH_LIMIT"}
    for index in range(before_index - 1, -1, -1):
        instruction = instructions[index]
        if instruction.flow in {"call", "indirect-call"}:
            if register == 0:
                return {
                    "status": "CALL_RETURN",
                    "producer_call_site_offset": instruction.offset,
                }
            if register <= 7:
                return {"status": "CALLER_SAVED_CLOBBER"}

        move = _REGISTER_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and move is not None:
            source, destination = map(int, move.groups())
            if destination == register:
                traced = _trace_register(
                    instructions,
                    index,
                    source,
                    image_size=image_size,
                    depth=depth + 1,
                )
                return {
                    **traced,
                    "derivation_depth": int(traced.get("derivation_depth", 0)) + 1,
                }

        immediate = _IMMEDIATE_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and immediate is not None:
            value, destination = map(int, immediate.groups())
            if destination == register:
                return {"status": "CONSTANT", "value": value, "derivation_depth": 1}

        add = _IMMEDIATE_ADD.fullmatch(instruction.operands)
        if instruction.mnemonic == "add" and add is not None:
            value, destination = map(int, add.groups())
            if destination == register:
                traced = _trace_register(
                    instructions,
                    index,
                    register,
                    image_size=image_size,
                    depth=depth + 1,
                )
                if traced.get("status") == "CONSTANT":
                    return {
                        "status": "CONSTANT",
                        "value": int(traced["value"]) + value,
                        "derivation_depth": int(traced.get("derivation_depth", 0)) + 1,
                    }
                return {
                    "status": "DERIVED_POINTER_OR_VALUE",
                    "base_status": _origin_class(traced),
                    "immediate_delta": value,
                    "derivation_depth": int(traced.get("derivation_depth", 0)) + 1,
                }

        pc_destination = _PC_DESTINATION.fullmatch(instruction.operands)
        if (
            instruction.mnemonic in {"mov.l", "mov.w"}
            and pc_destination is not None
            and int(pc_destination.group(1)) == register
            and instruction.literal_value is not None
        ):
            value = int(instruction.literal_value)
            if RUNTIME_BASE <= value < RUNTIME_BASE + image_size:
                return {
                    "status": "IN_IMAGE_POINTER",
                    "target_file_offset": value - RUNTIME_BASE,
                    "derivation_depth": 1,
                }
            if -0x10000 <= value <= 0x10000:
                return {"status": "CONSTANT", "value": value, "derivation_depth": 1}
            return {"status": "NON_IMAGE_LITERAL", "value_included": False}

        if instruction.mnemonic == "mova" and register == 0 and instruction.target is not None:
            return {
                "status": "IN_IMAGE_POINTER",
                "target_file_offset": int(instruction.target),
                "derivation_depth": 1,
            }

        displaced = _MEMORY_DESTINATION.fullmatch(instruction.operands)
        if instruction.mnemonic in {"mov.b", "mov.w", "mov.l"} and displaced is not None:
            displacement, base, destination = map(int, displaced.groups())
            if destination == register:
                base_origin = _trace_register(
                    instructions,
                    index,
                    base,
                    image_size=image_size,
                    depth=depth + 1,
                )
                return {
                    "status": "MEMORY_FIELD",
                    "base_status": _origin_class(base_origin),
                    "base_register": f"r{base}",
                    "displacement": displacement,
                    "derivation_depth": int(base_origin.get("derivation_depth", 0)) + 1,
                }

        indirect = _INDIRECT_DESTINATION.fullmatch(instruction.operands)
        if instruction.mnemonic in {"mov.b", "mov.w", "mov.l"} and indirect is not None:
            base, destination = map(int, indirect.groups())
            if destination == register:
                base_origin = _trace_register(
                    instructions,
                    index,
                    base,
                    image_size=image_size,
                    depth=depth + 1,
                )
                return {
                    "status": "MEMORY_DEREFERENCE",
                    "base_status": _origin_class(base_origin),
                    "base_register": f"r{base}",
                    "derivation_depth": int(base_origin.get("derivation_depth", 0)) + 1,
                }

        if _destination_register(instruction) == register:
            return {"status": "UNSUPPORTED_WRITE"}

    if 4 <= register <= 7:
        return {"status": "ENTRY_ARGUMENT", "register": f"r{register}"}
    return {"status": "NO_DEFINITION"}


def _resolve_call(
    instructions: list[SHInstruction], index: int, *, image_size: int
) -> dict[str, object]:
    instruction = instructions[index]
    if instruction.flow == "call" and instruction.target is not None:
        target = int(instruction.target)
        return {
            "status": "RESOLVED_DIRECT_BSR" if 0 <= target < image_size else "OUT_OF_IMAGE_DIRECT_BSR",
            "target_file_offset": target if 0 <= target < image_size else None,
        }
    if instruction.mnemonic != "jsr":
        return {"status": "NOT_A_CALL"}
    match = re.fullmatch(r"@r(\d+)", instruction.operands)
    if match is None:
        return {"status": "UNSUPPORTED_CALL_FORM"}
    register = int(match.group(1))
    origin = _trace_register(
        instructions, index, register, image_size=image_size
    )
    target = origin.get("target_file_offset")
    if origin.get("status") == "IN_IMAGE_POINTER" and isinstance(target, int):
        return {
            "status": "RESOLVED_REGISTER_FROM_IN_IMAGE_LITERAL",
            "target_file_offset": target,
            "target_register": f"r{register}",
        }
    return {
        "status": "UNRESOLVED_INDIRECT_CALL",
        "target_register": f"r{register}",
        "target_origin": _origin_class(origin),
    }


def _argument_origin(
    instructions: list[SHInstruction], index: int, register: int, *, image_size: int
) -> dict[str, object]:
    prefix = list(instructions[:index])
    if index + 1 < len(instructions) and instructions[index].delayed:
        prefix.append(instructions[index + 1])
    return _trace_register(
        prefix, len(prefix), register, image_size=image_size
    )


def _result_use(
    instructions: list[SHInstruction], index: int
) -> dict[str, object]:
    start = index + (2 if instructions[index].delayed else 1)
    captured: set[int] = {0}
    tested = False
    dereference_count = 0
    stored_count = 0
    for probe in range(start, min(len(instructions), start + 16)):
        item = instructions[probe]
        if item.flow in {"call", "indirect-call"}:
            break
        if item.mnemonic == "tst" and item.operands == "r0,r0":
            tested = True
        move = _REGISTER_MOVE.fullmatch(item.operands)
        if item.mnemonic == "mov" and move is not None:
            source, destination = map(int, move.groups())
            if source in captured:
                captured.add(destination)
        if item.mnemonic in {"mov.b", "mov.w", "mov.l"}:
            for register in captured:
                if re.search(rf"@(?:\([^)]*,)?r{register}(?:\+|\))?", item.operands):
                    if item.operands.startswith("@"):
                        dereference_count += 1
                    elif ",@" in item.operands:
                        stored_count += 1
    return {
        "tested_immediately_or_locally": tested,
        "captured_register_count": len(captured - {0}),
        "dereference_count_before_next_call": dereference_count,
        "store_count_before_next_call": stored_count,
    }


def summarize_bounded_entry(
    reader: BinaryReader,
    entry: int,
    *,
    source: str,
    maximum_bytes: int = 0x180,
) -> dict[str, object]:
    """Summarize one explicitly seeded code window without asserting a function."""

    instructions = _decode_window(reader, entry, maximum_bytes=maximum_bytes)
    known = sum(item.mnemonic != "unknown" for item in instructions)
    calls = []
    for index, instruction in enumerate(instructions):
        if instruction.flow not in {"call", "indirect-call"}:
            continue
        resolution = _resolve_call(instructions, index, image_size=reader.size)
        arguments = {
            f"r{register}": _argument_origin(
                instructions, index, register, image_size=reader.size
            )
            for register in range(4, 8)
        }
        calls.append(
            {
                "call_site_offset": instruction.offset,
                "relative_call_offset": instruction.offset - entry,
                "resolution": resolution,
                "arguments": arguments,
                "result_use": _result_use(instructions, index),
                "delay_slot_accounted_for": instruction.delayed,
            }
        )

    producer_forwarding: dict[int, list[dict[str, object]]] = defaultdict(list)
    for call in calls:
        for register, origin in call["arguments"].items():
            producer = origin.get("producer_call_site_offset")
            if isinstance(producer, int):
                producer_forwarding[producer].append(
                    {
                        "consumer_call_site_offset": call["call_site_offset"],
                        "argument_register": register,
                    }
                )
    for call in calls:
        call["result_forwarded_to"] = producer_forwarding.get(
            int(call["call_site_offset"]), []
        )

    prologue = any(
        item.mnemonic == "sts.l" and item.operands == "pr,@-r15"
        for item in instructions[:12]
    )
    returns = sum(item.flow == "return" for item in instructions)
    resolved = sum(
        str(call["resolution"]["status"]).startswith("RESOLVED")
        for call in calls
    )
    unresolved_indirect = sum(
        call["resolution"]["status"] == "UNRESOLVED_INDIRECT_CALL"
        for call in calls
    )
    known_ratio = round(known / len(instructions), 6) if instructions else 0.0
    code_gate = bool(
        known_ratio >= 0.70
        and (
            (prologue and returns)
            or (returns and resolved)
            or (prologue and resolved)
        )
    )
    return {
        "entry_file_offset": entry,
        "seed_source": source,
        "window_length": len(instructions) * 2,
        "instruction_count": len(instructions),
        "known_instruction_count": known,
        "known_ratio": known_ratio,
        "normalized_shape_sha256": _normalized_shape(instructions),
        "prologue_save_pr_in_first_12_instructions": prologue,
        "return_count": returns,
        "call_count": len(calls),
        "resolved_static_call_count": resolved,
        "unresolved_indirect_call_count": unresolved_indirect,
        "bounded_code_gate_passed": code_gate,
        "calls": calls,
        "function_boundary_asserted": False,
        "instruction_bytes_included": False,
    }


def _record_pointers(reader: BinaryReader, anchor: int) -> dict[int, int]:
    start = max(0, anchor - 0x80)
    end = min(reader.size, anchor + 0x80)
    first = start + ((-start) % 4)
    result = {}
    for offset in range(first, end - 3, 4):
        value = int.from_bytes(reader.read(offset, 4), "big")
        if RUNTIME_BASE <= value < RUNTIME_BASE + reader.size:
            result[offset - anchor] = value - RUNTIME_BASE
    return result


def collect_seed_pairs(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    navigation_contract: dict[str, object],
) -> dict[str, object]:
    """Build navigation and optical code-entry seed pairs conservatively."""

    navigation: dict[tuple[int, int], dict[str, object]] = {}
    rejected_navigation_targets = 0
    for window in navigation_contract.get("callsite_window_pairs", []):
        for call in window.get("resolved_call_pairs", []):
            left = call.get("left_target_file_offset")
            right = call.get("right_target_file_offset")
            if not isinstance(left, int) or not isinstance(right, int):
                continue
            if call.get("target_window_shape_equal") is not True:
                rejected_navigation_targets += 1
                continue
            item = navigation.setdefault(
                (left, right),
                {
                    "left_entry": left,
                    "right_entry": right,
                    "source": "NAVIGATION_CONFIRMED_TARGET_PAIR",
                    "occurrence_count": 0,
                },
            )
            item["occurrence_count"] = int(item["occurrence_count"]) + 1

    optical: dict[tuple[int, int], dict[str, object]] = {}
    pointer_slot_count = 0
    for pair in navigation_contract.get("neighborhood_pairs", []):
        if pair.get("category") != "optical-service":
            continue
        left = _record_pointers(left_reader, int(pair["left_anchor_offset"]))
        right = _record_pointers(right_reader, int(pair["right_anchor_offset"]))
        for relative in sorted(left.keys() & right.keys()):
            pointer_slot_count += 1
            key = (left[relative], right[relative])
            item = optical.setdefault(
                key,
                {
                    "left_entry": key[0],
                    "right_entry": key[1],
                    "source": "OPTICAL_RECORD_POINTER_PAIR",
                    "occurrences": [],
                },
            )
            item["occurrences"].append(
                {
                    "anchor_id": pair["anchor_id"],
                    "relative_slot": relative,
                }
            )

    accepted_optical = []
    for item in optical.values():
        left_summary = summarize_bounded_entry(
            left_reader, int(item["left_entry"]), source=str(item["source"])
        )
        right_summary = summarize_bounded_entry(
            right_reader, int(item["right_entry"]), source=str(item["source"])
        )
        if left_summary["bounded_code_gate_passed"] and right_summary["bounded_code_gate_passed"]:
            accepted_optical.append(
                {
                    **item,
                    "occurrence_count": len(item["occurrences"]),
                    "left_code": left_summary,
                    "right_code": right_summary,
                    "classification": "CONFIRMED_RECORD_POINTER_PAIRED_BOUNDED_CODE",
                }
            )

    navigation_rows = []
    for item in navigation.values():
        left_summary = summarize_bounded_entry(
            left_reader, int(item["left_entry"]), source=str(item["source"])
        )
        right_summary = summarize_bounded_entry(
            right_reader, int(item["right_entry"]), source=str(item["source"])
        )
        navigation_rows.append(
            {
                **item,
                "left_code": left_summary,
                "right_code": right_summary,
                "classification": "CONFIRMED_SESSION010_CALL_TARGET_PAIR",
            }
        )

    return {
        "navigation_seed_pairs": sorted(
            navigation_rows, key=lambda item: int(item["left_entry"])
        ),
        "accepted_optical_seed_pairs": sorted(
            accepted_optical, key=lambda item: int(item["left_entry"])
        ),
        "census": {
            "navigation_unique_shape_equal_target_pair_count": len(navigation_rows),
            "navigation_rejected_shape_unequal_target_count": rejected_navigation_targets,
            "optical_paired_pointer_slot_count": pointer_slot_count,
            "optical_unique_pointer_pair_count": len(optical),
            "optical_bounded_code_seed_pair_count": len(accepted_optical),
            "optical_rejected_non_code_or_weak_pair_count": len(optical) - len(accepted_optical),
        },
    }


def _call_signature(call: dict[str, object]) -> tuple[object, ...]:
    return (
        call["resolution"]["status"],
        tuple(
            _origin_class(call["arguments"][f"r{register}"])
            for register in range(4, 8)
        ),
        bool(call["result_use"]["tested_immediately_or_locally"]),
        bool(call["result_use"]["dereference_count_before_next_call"]),
        bool(call["result_forwarded_to"]),
    )


def _paired_calls(
    left: dict[str, object], right: dict[str, object]
) -> list[dict[str, object]]:
    rows = []
    for ordinal, (left_call, right_call) in enumerate(
        zip(left["calls"], right["calls"])
    ):
        signature_equal = _call_signature(left_call) == _call_signature(right_call)
        left_target = left_call["resolution"].get("target_file_offset")
        right_target = right_call["resolution"].get("target_file_offset")
        rows.append(
            {
                "ordinal": ordinal,
                "left_call_site_offset": left_call["call_site_offset"],
                "right_call_site_offset": right_call["call_site_offset"],
                "left_relative_call_offset": left_call["relative_call_offset"],
                "right_relative_call_offset": right_call["relative_call_offset"],
                "signature_equal": signature_equal,
                "left_target_file_offset": left_target,
                "right_target_file_offset": right_target,
                "paired_resolved_target": bool(
                    signature_equal
                    and isinstance(left_target, int)
                    and isinstance(right_target, int)
                ),
                "argument_role_classes": {
                    f"r{register}": (
                        _origin_class(left_call["arguments"][f"r{register}"]),
                        _origin_class(right_call["arguments"][f"r{register}"]),
                    )
                    for register in range(4, 8)
                },
                "left_result_use": copy.deepcopy(left_call["result_use"]),
                "right_result_use": copy.deepcopy(right_call["result_use"]),
                "left_result_forwarded_to": copy.deepcopy(left_call["result_forwarded_to"]),
                "right_result_forwarded_to": copy.deepcopy(right_call["result_forwarded_to"]),
            }
        )
    return rows


def _contains_sector_constant(call: dict[str, object]) -> bool:
    return any(
        origin.get("status") == "CONSTANT" and origin.get("value") == 2048
        for origin in call["arguments"].values()
    )


def _paired_argument_constants(
    left_call: dict[str, object], right_call: dict[str, object]
) -> dict[str, list[int]]:
    constants = {}
    for register in range(4, 8):
        name = f"r{register}"
        left = left_call["arguments"][name]
        right = right_call["arguments"][name]
        if (
            left.get("status") == "CONSTANT"
            and right.get("status") == "CONSTANT"
            and isinstance(left.get("value"), int)
            and isinstance(right.get("value"), int)
        ):
            constants[name] = [int(left["value"]), int(right["value"])]
    return constants


def build_bounded_interprocedural_graph(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    seeds: dict[str, object],
    *,
    maximum_depth: int = 2,
    maximum_node_pairs: int = 128,
) -> dict[str, object]:
    """Expand only same-ordinal, same-signature resolved call pairs."""

    queue = []
    for domain, key in (
        ("navigation", "navigation_seed_pairs"),
        ("optical", "accepted_optical_seed_pairs"),
    ):
        for item in seeds[key]:
            queue.append(
                (
                    domain,
                    0,
                    int(item["left_entry"]),
                    int(item["right_entry"]),
                    item["left_code"],
                    item["right_code"],
                    str(item["classification"]),
                )
            )

    nodes: dict[tuple[str, int, int], dict[str, object]] = {}
    edges = []
    edge_keys: set[tuple[object, ...]] = set()
    while queue and len(nodes) < maximum_node_pairs:
        domain, depth, left_entry, right_entry, left_code, right_code, source = queue.pop(0)
        key = (domain, left_entry, right_entry)
        if key in nodes:
            nodes[key]["seed_sources"] = sorted(set(nodes[key]["seed_sources"] + [source]))
            continue
        call_pairs = _paired_calls(left_code, right_code)
        node = {
            "domain": domain,
            "depth": depth,
            "left_entry_file_offset": left_entry,
            "right_entry_file_offset": right_entry,
            "seed_sources": [source],
            "left_known_ratio": left_code["known_ratio"],
            "right_known_ratio": right_code["known_ratio"],
            "normalized_shape_equal": left_code["normalized_shape_sha256"] == right_code["normalized_shape_sha256"],
            "left_call_count": left_code["call_count"],
            "right_call_count": right_code["call_count"],
            "left_unresolved_indirect_call_count": left_code[
                "unresolved_indirect_call_count"
            ],
            "right_unresolved_indirect_call_count": right_code[
                "unresolved_indirect_call_count"
            ],
            "paired_call_count": len(call_pairs),
            "same_signature_call_count": sum(item["signature_equal"] for item in call_pairs),
            "paired_resolved_target_count": sum(item["paired_resolved_target"] for item in call_pairs),
            "function_boundary_asserted": False,
        }
        nodes[key] = node
        for call_pair in call_pairs:
            if not call_pair["paired_resolved_target"]:
                continue
            left_target = int(call_pair["left_target_file_offset"])
            right_target = int(call_pair["right_target_file_offset"])
            edge = {
                "domain": domain,
                "depth": depth,
                "left_caller": left_entry,
                "right_caller": right_entry,
                "left_callee": left_target,
                "right_callee": right_target,
                "left_call_site_offset": call_pair["left_call_site_offset"],
                "right_call_site_offset": call_pair["right_call_site_offset"],
                "argument_role_classes": call_pair["argument_role_classes"],
                "result_forwarded": bool(
                    call_pair["left_result_forwarded_to"]
                    and call_pair["right_result_forwarded_to"]
                ),
                "result_dereferenced": bool(
                    call_pair["left_result_use"]["dereference_count_before_next_call"]
                    and call_pair["right_result_use"]["dereference_count_before_next_call"]
                ),
                "sector_size_2048_argument": False,
                "status": "CONFIRMED_PAIRED_RESOLVED_STATIC_CALL",
            }
            left_call = left_code["calls"][int(call_pair["ordinal"])]
            right_call = right_code["calls"][int(call_pair["ordinal"])]
            edge["paired_argument_constants"] = _paired_argument_constants(
                left_call, right_call
            )
            edge["sector_size_2048_argument"] = bool(
                _contains_sector_constant(left_call)
                and _contains_sector_constant(right_call)
            )
            edge_key = (
                domain,
                edge["left_call_site_offset"],
                edge["right_call_site_offset"],
                left_target,
                right_target,
            )
            if edge_key in edge_keys:
                continue
            edge_keys.add(edge_key)
            edges.append(edge)
            if depth >= maximum_depth:
                continue
            child_left = summarize_bounded_entry(
                left_reader, left_target, source="PAIRED_RESOLVED_STATIC_CALL"
            )
            child_right = summarize_bounded_entry(
                right_reader, right_target, source="PAIRED_RESOLVED_STATIC_CALL"
            )
            if not (
                child_left["bounded_code_gate_passed"]
                and child_right["bounded_code_gate_passed"]
            ):
                continue
            queue.append(
                (
                    domain,
                    depth + 1,
                    left_target,
                    right_target,
                    child_left,
                    child_right,
                    "PAIRED_RESOLVED_STATIC_CALL",
                )
            )

    navigation_pairs = {
        (int(node["left_entry_file_offset"]), int(node["right_entry_file_offset"]))
        for node in nodes.values()
        if node["domain"] == "navigation"
    }
    optical_pairs = {
        (int(node["left_entry_file_offset"]), int(node["right_entry_file_offset"]))
        for node in nodes.values()
        if node["domain"] == "optical"
    }
    intersection = sorted(navigation_pairs & optical_pairs)
    direct_edges = [
        edge
        for edge in edges
        if edge["domain"] == "navigation"
        and (int(edge["left_callee"]), int(edge["right_callee"])) in optical_pairs
    ]
    sector_edges = [edge for edge in edges if edge["sector_size_2048_argument"]]
    constant_counts = Counter(
        (register, values[0], values[1])
        for edge in edges
        for register, values in edge["paired_argument_constants"].items()
    )
    return {
        "schema": "phoenix-mmi.bounded-optical-callgraph/v1",
        "analysis_mode": "read-only-static-bounded-interprocedural",
        "limits": {
            "maximum_depth": maximum_depth,
            "maximum_node_pairs": maximum_node_pairs,
            "same_ordinal_and_signature_required": True,
            "object_dispatch_targets_resolved": False,
        },
        "nodes": sorted(
            nodes.values(),
            key=lambda item: (
                str(item["domain"]),
                int(item["depth"]),
                int(item["left_entry_file_offset"]),
            ),
        ),
        "edges": edges,
        "classification": {
            "node_pair_count": len(nodes),
            "edge_pair_count": len(edges),
            "navigation_node_pair_count": len(navigation_pairs),
            "optical_node_pair_count": len(optical_pairs),
            "cross_domain_shared_node_pair_count": len(intersection),
            "direct_navigation_to_optical_edge_count": len(direct_edges),
            "sector_size_2048_argument_edge_count": len(sector_edges),
            "left_unresolved_indirect_call_count": sum(
                int(node["left_unresolved_indirect_call_count"])
                for node in nodes.values()
            ),
            "right_unresolved_indirect_call_count": sum(
                int(node["right_unresolved_indirect_call_count"])
                for node in nodes.values()
            ),
            "paired_argument_constant_counts": [
                {
                    "register": register,
                    "left_value": left,
                    "right_value": right,
                    "edge_count": count,
                }
                for (register, left, right), count in sorted(constant_counts.items())
            ],
            "sector_read_abi": (
                "CANDIDATE_REQUIRES_FIELD_ROLE_VALIDATION" if sector_edges else "OPEN"
            ),
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
        },
        "cross_domain_shared_pairs": [
            {"left_entry_file_offset": left, "right_entry_file_offset": right}
            for left, right in intersection
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "instruction_bytes_included": False,
            "absolute_runtime_addresses_included": False,
            "raw_strings_included": False,
            "local_paths_included": False,
            "map_payload_included": False,
        },
    }


def compare_optical_navigation_callgraph(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    navigation_contract: dict[str, object],
) -> dict[str, object]:
    seeds = collect_seed_pairs(left_reader, right_reader, navigation_contract)
    graph = build_bounded_interprocedural_graph(
        left_reader, right_reader, seeds
    )
    return {
        "schema": "phoenix-mmi.optical-navigation-callgraph-comparison/v1",
        "analysis_mode": "read-only-static-bounded-interprocedural",
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "seed_census": copy.deepcopy(seeds["census"]),
        "navigation_seed_pairs": [
            {
                "left_entry_file_offset": item["left_entry"],
                "right_entry_file_offset": item["right_entry"],
                "occurrence_count": item["occurrence_count"],
                "classification": item["classification"],
            }
            for item in seeds["navigation_seed_pairs"]
        ],
        "optical_seed_pairs": [
            {
                "left_entry_file_offset": item["left_entry"],
                "right_entry_file_offset": item["right_entry"],
                "occurrence_count": item["occurrence_count"],
                "anchor_ids": sorted(
                    {str(row["anchor_id"]) for row in item["occurrences"]}
                ),
                "classification": item["classification"],
            }
            for item in seeds["accepted_optical_seed_pairs"]
        ],
        "graph": graph,
        "classification": copy.deepcopy(graph["classification"]),
        "interpretation": (
            "The bounded graph includes only cross-version record-pointer seeds and "
            "same-ordinal static calls with equal argument/result signatures. It does "
            "not resolve object dispatch. A sector ABI or optical buffer owner is "
            "promoted only when independent argument and provenance evidence converges."
        ),
        "publication_safety": copy.deepcopy(graph["publication_safety"]),
    }


def update_operational_graph_v8(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v8"
    graph["nodes"] = [
        node for node in graph["nodes"] if node["id"] != "optical-interprocedural-search"
    ]
    graph["nodes"].append(
        {
            "id": "optical-interprocedural-search",
            "label": "Bounded navigation/optical SH call-graph search",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "direct_edge_result": (
                "NOT_FOUND_UNDER_TESTED_STATIC_CALL_MODEL"
                if comparison["classification"]["direct_navigation_to_optical_edge_count"] == 0
                else "CANDIDATE_FOUND_REQUIRES_VALIDATION"
            ),
            "evidence": ["S015-01", "S015-02", "RQ-037", "RQ-041"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "optical-interprocedural-search"
            and edge["target"] == "fldb-parser-routine"
        )
    ]
    graph["edges"].append(
        {
            "source": "optical-interprocedural-search",
            "target": "fldb-parser-routine",
            "relation": "traced bounded static call pairs; parser/sector ABI remain unresolved",
            "status": "BOUNDED_NEGATIVE",
        }
    )
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED") for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE") for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(node["status"] == "OPEN" for node in graph["nodes"])
    graph["bounded_negative_edge_count"] = sum(
        edge["status"] == "BOUNDED_NEGATIVE" for edge in graph["edges"]
    )
    graph["interpretation"] = (
        "Session 015 builds a depth-bounded SH call graph from confirmed navigation "
        "targets and code-gated optical record pointers. Unresolved object dispatch "
        "prevents a complete optical chain; sector ABI and buffer ownership stay open."
    )
    return graph


def correlate_optical_sector_model(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.optical-sector-correlation/v1",
        "analysis_mode": "read-only-static-bounded-interprocedural",
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "correlation": {
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": comparison["classification"]["sector_read_abi"],
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "partition_consumer": "OPEN",
            "dynamic_compatibility": "NOT_ESTABLISHED",
        },
        "operational_graph": update_operational_graph_v8(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_optical_callgraph_report(
    report: dict[str, object]
) -> dict[str, object]:
    return copy.deepcopy(report)

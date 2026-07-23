"""Bounded predecessor-context and object-dispatch analysis for Session 016.

The analyzer extends Session 015 without changing its original graph.  It may
recover a literal-backed call target from a bounded predecessor window, or
describe a dynamic memory path symbolically.  A matching memory path is
structural evidence only: it is never promoted to a concrete method target.
"""

from __future__ import annotations

from collections import Counter
import copy
import re

from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .optical_callgraph import (
    build_bounded_interprocedural_graph,
    collect_seed_pairs,
    compare_optical_navigation_callgraph,
    summarize_bounded_entry,
)
from .superh import SHInstruction, decode_instruction_extended


_REGISTER_MOVE = re.compile(r"r(\d+),r(\d+)$")
_IMMEDIATE_MOVE = re.compile(r"#(-?\d+),r(\d+)$")
_IMMEDIATE_ADD = re.compile(r"#(-?\d+),r(\d+)$")
_REGISTER_ADD = re.compile(r"r(\d+),r(\d+)$")
_PC_DESTINATION = re.compile(r"@\([^)]*,pc\),r(\d+)$")
_MEMORY_DESTINATION = re.compile(r"@\((\d+),r(\d+)\),r(\d+)$")
_INDIRECT_DESTINATION = re.compile(r"@r(\d+)\+?,r(\d+)$")
_CALL_REGISTER = re.compile(r"@r(\d+)$")


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
    if instruction.mnemonic in {
        "add",
        "sub",
        "and",
        "or",
        "xor",
        "mov",
        "mov.b",
        "mov.w",
        "mov.l",
        "swap.b",
        "swap.w",
        "xtrct",
    }:
        match = re.search(r",r(\d+)$", instruction.operands)
        return int(match.group(1)) if match is not None else None
    if instruction.mnemonic == "shlr2":
        match = re.fullmatch(r"r(\d+)", instruction.operands)
        return int(match.group(1)) if match is not None else None
    return None


def _bounded_context(
    reader: BinaryReader,
    entry: int,
    *,
    maximum_backward_bytes: int = 0x100,
    maximum_forward_bytes: int = 0x180,
) -> tuple[list[SHInstruction], dict[str, object]]:
    """Decode a linear context while exposing, not hiding, its boundary limits."""

    lower = max(0, entry - maximum_backward_bytes) & ~1
    prefix = [
        decode_instruction_extended(reader, offset)
        for offset in range(lower, entry, 2)
    ]
    last_return = next(
        (item for item in reversed(prefix) if item.flow == "return"), None
    )
    base = last_return.offset + 4 if last_return is not None else lower
    eligible = [item for item in prefix if item.offset >= base]
    prologue = next(
        (
            item
            for item in reversed(eligible)
            if item.mnemonic == "sts.l" and item.operands == "pr,@-r15"
        ),
        None,
    )
    if prologue is not None:
        start = prologue.offset
        reason = "LATEST_SAVE_PR_PROLOGUE"
    elif last_return is not None:
        start = base
        reason = "AFTER_LATEST_RETURN_DELAY_SLOT"
    else:
        start = lower
        reason = "BACKWARD_LIMIT"

    end = min(reader.size, entry + maximum_forward_bytes) & ~1
    instructions: list[SHInstruction] = []
    for offset in range(start, end, 2):
        instruction = decode_instruction_extended(reader, offset)
        instructions.append(instruction)
        if offset >= entry and instruction.flow == "return":
            if instruction.delayed and offset + 2 < end:
                instructions.append(decode_instruction_extended(reader, offset + 2))
            break
    return instructions, {
        "context_start_file_offset": start,
        "predecessor_bytes_included": entry - start,
        "context_start_reason": reason,
        "maximum_backward_bytes": maximum_backward_bytes,
        "function_boundary_asserted": False,
        "path_dominance_asserted": False,
    }


def _trace_expression(
    instructions: list[SHInstruction],
    before_index: int,
    register: int,
    *,
    image_size: int,
    depth: int = 0,
    active: frozenset[tuple[int, int]] = frozenset(),
) -> dict[str, object]:
    if depth > 24:
        return {"kind": "DEPTH_LIMIT"}
    key = (before_index, register)
    if key in active:
        return {"kind": "CYCLE"}
    active = active | {key}

    for index in range(before_index - 1, -1, -1):
        instruction = instructions[index]
        if instruction.flow in {"call", "indirect-call"}:
            if register == 0:
                return {"kind": "CALL_RETURN"}
            if register <= 7:
                return {"kind": "CALLER_SAVED_CLOBBER"}

        move = _REGISTER_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and move is not None:
            source, destination = map(int, move.groups())
            if destination == register:
                return _trace_expression(
                    instructions,
                    index,
                    source,
                    image_size=image_size,
                    depth=depth + 1,
                    active=active,
                )

        immediate = _IMMEDIATE_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and immediate is not None:
            value, destination = map(int, immediate.groups())
            if destination == register:
                return {"kind": "CONSTANT", "value": value}

        immediate_add = _IMMEDIATE_ADD.fullmatch(instruction.operands)
        if instruction.mnemonic == "add" and immediate_add is not None:
            value, destination = map(int, immediate_add.groups())
            if destination == register:
                return {
                    "kind": "ADD",
                    "left": _trace_expression(
                        instructions,
                        index,
                        register,
                        image_size=image_size,
                        depth=depth + 1,
                        active=active,
                    ),
                    "right": {"kind": "CONSTANT", "value": value},
                }

        register_add = _REGISTER_ADD.fullmatch(instruction.operands)
        if instruction.mnemonic == "add" and register_add is not None:
            source, destination = map(int, register_add.groups())
            if destination == register:
                return {
                    "kind": "ADD",
                    "left": _trace_expression(
                        instructions,
                        index,
                        register,
                        image_size=image_size,
                        depth=depth + 1,
                        active=active,
                    ),
                    "right": _trace_expression(
                        instructions,
                        index,
                        source,
                        image_size=image_size,
                        depth=depth + 1,
                        active=active,
                    ),
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
                    "kind": "IN_IMAGE_POINTER",
                    "target_file_offset": value - RUNTIME_BASE,
                }
            if -0x10000 <= value <= 0x10000:
                return {"kind": "CONSTANT", "value": value}
            return {"kind": "NON_IMAGE_LITERAL"}

        if instruction.mnemonic == "mova" and register == 0 and instruction.target is not None:
            return {
                "kind": "IN_IMAGE_POINTER",
                "target_file_offset": int(instruction.target),
            }

        displaced = _MEMORY_DESTINATION.fullmatch(instruction.operands)
        if instruction.mnemonic in {"mov.b", "mov.w", "mov.l"} and displaced is not None:
            displacement, base, destination = map(int, displaced.groups())
            if destination == register:
                return {
                    "kind": "LOAD",
                    "width_bits": {"mov.b": 8, "mov.w": 16, "mov.l": 32}[
                        instruction.mnemonic
                    ],
                    "displacement": displacement,
                    "base": _trace_expression(
                        instructions,
                        index,
                        base,
                        image_size=image_size,
                        depth=depth + 1,
                        active=active,
                    ),
                }

        indirect = _INDIRECT_DESTINATION.fullmatch(instruction.operands)
        if instruction.mnemonic in {"mov.b", "mov.w", "mov.l"} and indirect is not None:
            base, destination = map(int, indirect.groups())
            if destination == register:
                return {
                    "kind": "LOAD",
                    "width_bits": {"mov.b": 8, "mov.w": 16, "mov.l": 32}[
                        instruction.mnemonic
                    ],
                    "displacement": 0,
                    "base": _trace_expression(
                        instructions,
                        index,
                        base,
                        image_size=image_size,
                        depth=depth + 1,
                        active=active,
                    ),
                }

        if _destination_register(instruction) == register:
            return {
                "kind": "UNSUPPORTED_WRITE",
                "mnemonic": instruction.mnemonic,
            }

    if 4 <= register <= 7:
        return {"kind": "ENTRY_ARGUMENT", "register": f"r{register}"}
    return {"kind": "NO_DEFINITION"}


def _canonical_expression(expression: dict[str, object]) -> str:
    kind = str(expression.get("kind", "UNKNOWN"))
    if kind == "ENTRY_ARGUMENT":
        return f"ENTRY:{expression['register']}"
    if kind == "CONSTANT":
        return f"CONST:{int(expression['value'])}"
    if kind == "IN_IMAGE_POINTER":
        return "IN_IMAGE_POINTER"
    if kind == "LOAD":
        return (
            f"LOAD{int(expression['width_bits'])}"
            f"[{int(expression['displacement'])}]"
            f"({_canonical_expression(expression['base'])})"
        )
    if kind == "ADD":
        return (
            f"ADD({_canonical_expression(expression['left'])},"
            f"{_canonical_expression(expression['right'])})"
        )
    if kind == "UNSUPPORTED_WRITE":
        return f"UNSUPPORTED_WRITE:{expression.get('mnemonic', 'unknown')}"
    return kind


def _resolve_static_expression(
    reader: BinaryReader, expression: dict[str, object], *, depth: int = 0
) -> dict[str, object]:
    if depth > 24:
        return {"status": "DEPTH_LIMIT"}
    kind = expression.get("kind")
    if kind == "CONSTANT":
        return {"status": "CONSTANT", "value": int(expression["value"])}
    if kind == "IN_IMAGE_POINTER":
        return {
            "status": "RESOLVED_IN_IMAGE_POINTER",
            "target_file_offset": int(expression["target_file_offset"]),
        }
    if kind == "ADD":
        left = _resolve_static_expression(reader, expression["left"], depth=depth + 1)
        right = _resolve_static_expression(reader, expression["right"], depth=depth + 1)
        if left.get("status") == "RESOLVED_IN_IMAGE_POINTER" and right.get("status") == "CONSTANT":
            target = int(left["target_file_offset"]) + int(right["value"])
        elif right.get("status") == "RESOLVED_IN_IMAGE_POINTER" and left.get("status") == "CONSTANT":
            target = int(right["target_file_offset"]) + int(left["value"])
        elif left.get("status") == "CONSTANT" and right.get("status") == "CONSTANT":
            return {"status": "CONSTANT", "value": int(left["value"]) + int(right["value"])}
        else:
            return {"status": "DYNAMIC_OR_UNSUPPORTED"}
        if 0 <= target < reader.size:
            return {"status": "RESOLVED_IN_IMAGE_POINTER", "target_file_offset": target}
        return {"status": "OUT_OF_IMAGE"}
    if kind == "LOAD":
        base = _resolve_static_expression(reader, expression["base"], depth=depth + 1)
        if base.get("status") != "RESOLVED_IN_IMAGE_POINTER":
            return {"status": "DYNAMIC_OR_UNSUPPORTED"}
        address = int(base["target_file_offset"]) + int(expression["displacement"])
        width_bits = int(expression["width_bits"])
        width = width_bits // 8
        if address < 0 or address + width > reader.size:
            return {"status": "OUT_OF_IMAGE"}
        value = int.from_bytes(
            reader.read(address, width),
            "big",
            signed=width_bits in {8, 16},
        )
        if width_bits == 32 and RUNTIME_BASE <= value < RUNTIME_BASE + reader.size:
            return {
                "status": "RESOLVED_IN_IMAGE_POINTER",
                "target_file_offset": value - RUNTIME_BASE,
            }
        return {"status": "CONSTANT", "value": value}
    return {"status": "DYNAMIC_OR_UNSUPPORTED"}


def _collect_load_offsets(expression: dict[str, object]) -> list[dict[str, int]]:
    rows: list[dict[str, int]] = []
    kind = expression.get("kind")
    if kind == "LOAD":
        rows.append(
            {
                "width_bits": int(expression["width_bits"]),
                "displacement": int(expression["displacement"]),
            }
        )
        rows.extend(_collect_load_offsets(expression["base"]))
    elif kind == "ADD":
        rows.extend(_collect_load_offsets(expression["left"]))
        rows.extend(_collect_load_offsets(expression["right"]))
    return rows


def _collect_constants(expression: dict[str, object]) -> list[int]:
    if expression.get("kind") == "CONSTANT":
        return [int(expression["value"])]
    values = []
    for key in ("base", "left", "right"):
        child = expression.get(key)
        if isinstance(child, dict):
            values.extend(_collect_constants(child))
    return sorted(set(values))


def _contains_kind(expression: dict[str, object], wanted: str) -> bool:
    if expression.get("kind") == wanted:
        return True
    for key in ("base", "left", "right"):
        child = expression.get(key)
        if isinstance(child, dict) and _contains_kind(child, wanted):
            return True
    return False


def _terminal_kinds(expression: dict[str, object]) -> list[str]:
    children = [
        child
        for key in ("base", "left", "right")
        if isinstance((child := expression.get(key)), dict)
    ]
    if not children:
        return [str(expression.get("kind", "UNKNOWN"))]
    return sorted({kind for child in children for kind in _terminal_kinds(child)})


def summarize_contextual_dispatch_calls(
    reader: BinaryReader,
    entry: int,
    original_summary: dict[str, object],
    *,
    maximum_backward_bytes: int = 0x100,
) -> dict[str, object]:
    instructions, context = _bounded_context(
        reader, entry, maximum_backward_bytes=maximum_backward_bytes
    )
    index_by_offset = {item.offset: index for index, item in enumerate(instructions)}
    calls = []
    for original_call in original_summary["calls"]:
        site = int(original_call["call_site_offset"])
        index = index_by_offset.get(site)
        if index is None:
            continue
        instruction = instructions[index]
        match = _CALL_REGISTER.fullmatch(instruction.operands)
        if instruction.mnemonic != "jsr" or match is None:
            continue
        target_register = int(match.group(1))
        target_expression = _trace_expression(
            instructions, index, target_register, image_size=reader.size
        )
        target_resolution = _resolve_static_expression(reader, target_expression)

        argument_prefix = list(instructions[:index])
        if instruction.delayed and index + 1 < len(instructions):
            argument_prefix.append(instructions[index + 1])
        arguments = {}
        for register in range(4, 8):
            expression = _trace_expression(
                argument_prefix,
                len(argument_prefix),
                register,
                image_size=reader.size,
            )
            resolution = _resolve_static_expression(reader, expression)
            arguments[f"r{register}"] = {
                "path": _canonical_expression(expression),
                "static_status": resolution["status"],
                **(
                    {"constant": int(resolution["value"])}
                    if resolution.get("status") == "CONSTANT"
                    else {}
                ),
                "load_offsets": _collect_load_offsets(expression),
                "path_constants": _collect_constants(expression),
            }

        target = target_resolution.get("target_file_offset")
        target_code_gate = False
        target_code_evidence = None
        if target_resolution.get("status") == "RESOLVED_IN_IMAGE_POINTER" and isinstance(target, int):
            target_summary = summarize_bounded_entry(
                reader, target, source="SESSION016_CONTEXT_RECOVERY"
            )
            target_code_gate = bool(target_summary["bounded_code_gate_passed"])
            target_code_evidence = {
                "known_ratio": target_summary["known_ratio"],
                "prologue_save_pr_in_first_12_instructions": target_summary[
                    "prologue_save_pr_in_first_12_instructions"
                ],
                "return_count": target_summary["return_count"],
                "resolved_static_call_count": target_summary[
                    "resolved_static_call_count"
                ],
                "unresolved_indirect_call_count": target_summary[
                    "unresolved_indirect_call_count"
                ],
                "bounded_code_gate_passed": target_code_gate,
                "function_boundary_asserted": False,
            }
        calls.append(
            {
                "call_site_offset": site,
                "relative_call_offset": site - entry,
                "target_register": f"r{target_register}",
                "target_path": _canonical_expression(target_expression),
                "target_load_offsets": _collect_load_offsets(target_expression),
                "target_contains_entry_argument": _contains_kind(
                    target_expression, "ENTRY_ARGUMENT"
                ),
                "target_contains_call_return": _contains_kind(
                    target_expression, "CALL_RETURN"
                ),
                "target_terminal_kinds": _terminal_kinds(target_expression),
                "target_static_status": target_resolution["status"],
                **(
                    {"target_file_offset": int(target)}
                    if isinstance(target, int)
                    else {}
                ),
                "target_code_gate_passed": target_code_gate,
                **(
                    {"target_code_evidence": target_code_evidence}
                    if target_code_evidence is not None
                    else {}
                ),
                "arguments": arguments,
                "delay_slot_accounted_for": instruction.delayed,
            }
        )
    return {
        "entry_file_offset": entry,
        **context,
        "calls": calls,
        "instruction_bytes_included": False,
    }


def _descriptor_contract(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object] | None:
    if left["target_path"] != right["target_path"]:
        return None
    if left["target_static_status"] == "RESOLVED_IN_IMAGE_POINTER":
        return None
    if "LOAD" not in left["target_path"]:
        return None
    target_offsets = left["target_load_offsets"]
    if target_offsets != right["target_load_offsets"]:
        return None
    receiver = left["arguments"]["r4"]
    right_receiver = right["arguments"]["r4"]
    if receiver["path"] != right_receiver["path"]:
        return None
    selector_left = left["arguments"]["r5"].get("constant")
    selector_right = right["arguments"]["r5"].get("constant")
    if selector_left != selector_right:
        return None
    return {
        "target_memory_path": copy.deepcopy(target_offsets),
        "receiver_memory_path": copy.deepcopy(receiver["load_offsets"]),
        "receiver_path_constants": copy.deepcopy(receiver["path_constants"]),
        "receiver_path_equal": True,
        "selector_register": "r5" if isinstance(selector_left, int) else None,
        "selector_value": selector_left if isinstance(selector_left, int) else None,
        "target_terminal_kinds": copy.deepcopy(left["target_terminal_kinds"]),
        "vtable_semantics_asserted": False,
        "method_semantics_asserted": False,
    }


def analyze_object_dispatch_context(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    navigation_contract: dict[str, object],
) -> dict[str, object]:
    base = compare_optical_navigation_callgraph(
        left_reader, right_reader, navigation_contract
    )
    seeds = collect_seed_pairs(left_reader, right_reader, navigation_contract)
    graph = build_bounded_interprocedural_graph(left_reader, right_reader, seeds)

    unique: dict[tuple[int, int], dict[str, object]] = {}
    for node in graph["nodes"]:
        left_entry = int(node["left_entry_file_offset"])
        right_entry = int(node["right_entry_file_offset"])
        left_original = summarize_bounded_entry(
            left_reader, left_entry, source="SESSION016_BASE_NODE"
        )
        right_original = summarize_bounded_entry(
            right_reader, right_entry, source="SESSION016_BASE_NODE"
        )
        left_context = summarize_contextual_dispatch_calls(
            left_reader, left_entry, left_original
        )
        right_context = summarize_contextual_dispatch_calls(
            right_reader, right_entry, right_original
        )
        left_by_site = {int(item["call_site_offset"]): item for item in left_context["calls"]}
        right_by_site = {int(item["call_site_offset"]): item for item in right_context["calls"]}
        for left_call, right_call in zip(left_original["calls"], right_original["calls"]):
            if (
                left_call["resolution"]["status"] != "UNRESOLVED_INDIRECT_CALL"
                or right_call["resolution"]["status"] != "UNRESOLVED_INDIRECT_CALL"
            ):
                continue
            left_site = int(left_call["call_site_offset"])
            right_site = int(right_call["call_site_offset"])
            if left_site not in left_by_site or right_site not in right_by_site:
                continue
            left_row = left_by_site[left_site]
            right_row = right_by_site[right_site]
            key = (left_site, right_site)
            row = unique.setdefault(
                key,
                {
                    "domain": str(node["domain"]),
                    "left_call_site_offset": left_site,
                    "right_call_site_offset": right_site,
                    "left_context_start_reason": left_context["context_start_reason"],
                    "right_context_start_reason": right_context["context_start_reason"],
                    "left_predecessor_bytes_included": left_context[
                        "predecessor_bytes_included"
                    ],
                    "right_predecessor_bytes_included": right_context[
                        "predecessor_bytes_included"
                    ],
                    "left": copy.deepcopy(left_row),
                    "right": copy.deepcopy(right_row),
                    "source_node_depths": [],
                },
            )
            row["source_node_depths"] = sorted(
                set(row["source_node_depths"] + [int(node["depth"])])
            )

    rows = []
    for row in unique.values():
        left = row["left"]
        right = row["right"]
        target_path_equal = left["target_path"] == right["target_path"]
        resolved_pair = bool(
            left["target_static_status"] == "RESOLVED_IN_IMAGE_POINTER"
            and right["target_static_status"] == "RESOLVED_IN_IMAGE_POINTER"
        )
        code_gated_pair = bool(
            resolved_pair
            and left["target_code_gate_passed"]
            and right["target_code_gate_passed"]
        )
        descriptor = _descriptor_contract(left, right)
        row["target_path_equal"] = target_path_equal
        row["paired_contextual_static_target"] = resolved_pair
        row["paired_contextual_target_code_gate"] = code_gated_pair
        row["matched_dynamic_descriptor_contract"] = descriptor is not None
        row["descriptor_contract"] = descriptor
        row["classification"] = (
            "CONFIRMED_PAIRED_CONTEXTUAL_LITERAL_CALL_TARGET"
            if resolved_pair
            else (
                "CONFIRMED_CROSS_VERSION_DYNAMIC_DESCRIPTOR_STRUCTURE"
                if descriptor is not None
                else "UNRESOLVED_CONTEXT_EXPRESSION"
            )
        )
        rows.append(row)

    rows.sort(key=lambda item: (item["domain"], item["left_call_site_offset"]))
    static_rows = [item for item in rows if item["paired_contextual_static_target"]]
    code_gated_static_rows = [
        item for item in static_rows if item["paired_contextual_target_code_gate"]
    ]
    descriptor_rows = [item for item in rows if item["matched_dynamic_descriptor_contract"]]
    base_node_pairs = {
        (int(node["left_entry_file_offset"]), int(node["right_entry_file_offset"]))
        for node in graph["nodes"]
    }
    recovered_pairs = {
        (
            int(item["left"]["target_file_offset"]),
            int(item["right"]["target_file_offset"]),
        )
        for item in static_rows
    }
    optical_node_pairs = {
        (int(node["left_entry_file_offset"]), int(node["right_entry_file_offset"]))
        for node in graph["nodes"]
        if node["domain"] == "optical"
    }
    recovered_navigation_to_optical = [
        item
        for item in static_rows
        if item["domain"] == "navigation"
        and (
            int(item["left"]["target_file_offset"]),
            int(item["right"]["target_file_offset"]),
        )
        in optical_node_pairs
    ]
    selector_counts = Counter(
        (
            item["descriptor_contract"].get("selector_register"),
            item["descriptor_contract"].get("selector_value"),
        )
        for item in descriptor_rows
    )
    descriptor_shapes = {
        (
            item["left"]["target_path"],
            item["left"]["arguments"]["r4"]["path"],
            item["descriptor_contract"].get("selector_register"),
            item["descriptor_contract"].get("selector_value"),
        )
        for item in descriptor_rows
    }
    context_start_counts = Counter(
        (
            item["left_context_start_reason"],
            item["right_context_start_reason"],
        )
        for item in rows
    )
    return {
        "schema": "phoenix-mmi.object-dispatch-context-comparison/v1",
        "analysis_mode": "read-only-static-bounded-predecessor-context",
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "limits": {
            "maximum_backward_bytes": 0x100,
            "original_session015_nodes_only": True,
            "same_ordinal_unresolved_pair_required": True,
            "linear_predecessor_trace": True,
            "path_dominance_asserted": False,
            "dynamic_target_resolved": False,
            "function_boundary_asserted": False,
        },
        "base_session015_classification": copy.deepcopy(base["classification"]),
        "dispatch_pairs": rows,
        "classification": {
            "unique_paired_unresolved_callsite_count": len(rows),
            "paired_contextual_static_target_count": len(static_rows),
            "paired_contextual_target_code_gate_count": len(code_gated_static_rows),
            "matched_dynamic_descriptor_contract_count": len(descriptor_rows),
            "unique_dynamic_descriptor_shape_count": len(descriptor_shapes),
            "remaining_unresolved_context_expression_count": len(rows)
            - len(static_rows)
            - len(descriptor_rows),
            "new_recovered_target_pair_count": len(recovered_pairs - base_node_pairs),
            "new_graph_expandable_target_pair_count": len(
                {
                    (
                        int(item["left"]["target_file_offset"]),
                        int(item["right"]["target_file_offset"]),
                    )
                    for item in code_gated_static_rows
                }
                - base_node_pairs
            ),
            "recovered_target_pair_already_in_graph_count": len(
                recovered_pairs & base_node_pairs
            ),
            "recovered_navigation_to_optical_edge_count": len(
                recovered_navigation_to_optical
            ),
            "selector_constant_counts": [
                {
                    "register": register,
                    "value": value,
                    "dispatch_pair_count": count,
                }
                for (register, value), count in sorted(selector_counts.items())
            ],
            "context_start_reason_counts": [
                {
                    "left_reason": left_reason,
                    "right_reason": right_reason,
                    "dispatch_pair_count": count,
                }
                for (left_reason, right_reason), count in sorted(
                    context_start_counts.items()
                )
            ],
            "descriptor_semantics": "STRUCTURAL_ONLY",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
        },
        "interpretation": (
            "Bounded predecessor context recovers literal-backed targets that were "
            "loaded before a Session 015 seed and describes equal dynamic descriptor "
            "paths without resolving them. No recovered edge establishes a navigation-"
            "to-optical bridge, sector ABI, buffer owner or FLDB parser."
        ),
        "publication_safety": {
            "firmware_bytes_included": False,
            "instruction_bytes_included": False,
            "absolute_runtime_addresses_included": False,
            "raw_strings_included": False,
            "local_paths_included": False,
            "map_payload_included": False,
        },
    }


def update_operational_graph_v9(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v9"
    graph["nodes"] = [
        node for node in graph["nodes"] if node["id"] != "object-dispatch-context-recovery"
    ]
    graph["nodes"].append(
        {
            "id": "object-dispatch-context-recovery",
            "label": "Bounded predecessor-context and dynamic descriptor analysis",
            "status": "CONFIRMED_BOUNDED_ANALYSIS",
            "contextual_static_target_pairs": comparison["classification"][
                "paired_contextual_static_target_count"
            ],
            "graph_expandable_target_pairs": comparison["classification"][
                "new_graph_expandable_target_pair_count"
            ],
            "dynamic_descriptor_contract_pairs": comparison["classification"][
                "matched_dynamic_descriptor_contract_count"
            ],
            "dynamic_target_status": "UNRESOLVED",
            "evidence": ["S016-01", "S016-02", "RQ-044", "RQ-045"],
        }
    )
    graph["edges"] = [
        edge
        for edge in graph["edges"]
        if not (
            edge["source"] == "object-dispatch-context-recovery"
            and edge["target"] == "fldb-parser-routine"
        )
    ]
    graph["edges"].append(
        {
            "source": "object-dispatch-context-recovery",
            "target": "fldb-parser-routine",
            "relation": (
                "recovers bounded static targets and descriptor structure; no parser, "
                "sector ABI or cross-domain dispatch target"
            ),
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
    graph["interpretation"] = comparison["interpretation"]
    return graph


def correlate_dispatch_context(
    prior_correlation: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.object-dispatch-correlation/v1",
        "analysis_mode": comparison["analysis_mode"],
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "correlation": {
            "actual_fldb_parser": "OPEN",
            "sector_read_abi": "OPEN",
            "optical_buffer_owner": "OPEN",
            "optical_buffer_provenance": "OPEN",
            "partition_consumer": "OPEN",
            "dynamic_compatibility": "NOT_ESTABLISHED",
        },
        "operational_graph": update_operational_graph_v9(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_object_dispatch_report(
    report: dict[str, object]
) -> dict[str, object]:
    return copy.deepcopy(report)

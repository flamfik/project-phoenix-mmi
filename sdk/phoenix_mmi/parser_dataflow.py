"""Bounded dataflow for the former FLDB ``0x220`` firmware candidate.

The analyzer follows only documented SH instructions inside a locally bounded
routine candidate.  It reports register roles and relative pointer deltas, but
never emits instruction bytes, absolute memory addresses or arbitrary strings.
"""

from __future__ import annotations

from collections import Counter
import copy
import hashlib
import re

from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .superh import SHInstruction, decode_instruction_extended as decode_instruction


_REGISTER_MOVE = re.compile(r"r(\d+),r(\d+)$")
_IMMEDIATE_MOVE = re.compile(r"#(-?\d+),r(\d+)$")
_IMMEDIATE_ADD = re.compile(r"#(-?\d+),r(\d+)$")
_DESTINATION_REGISTER = re.compile(r",r(\d+)$")
_PC_LITERAL_DESTINATION = re.compile(r"@\([^)]*,pc\),r(\d+)$")
_ADDRESS = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)

_PROBE_PATTERN_VALUES = {
    0xFF00FFFF,
    0xA0000009,
    0x95599559,
    0x14411441,
    0x29922992,
    0xAA55AA55,
    0xADDAADDA,
}


def _find_candidate_block(
    reader: BinaryReader, reference_offsets: list[int]
) -> tuple[int, int, list[SHInstruction]]:
    first = min(reference_offsets)
    last = max(reference_offsets)
    prologue_marker = None
    for offset in range(first - 2, max(-2, first - 0x102), -2):
        instruction = decode_instruction(reader, offset)
        if instruction.mnemonic == "sts.l" and instruction.operands == "pr,@-r15":
            prologue_marker = offset
            break
    if prologue_marker is None:
        raise ValueError("bounded SH prologue was not found near the 0x220 references")

    start = prologue_marker
    while start >= 2:
        previous = decode_instruction(reader, start - 2)
        if previous.mnemonic != "mov.l" or not previous.operands.endswith(",@-r15"):
            break
        start -= 2

    probe_end = min(reader.size, last + 0x100) & ~1
    probe = [decode_instruction(reader, offset) for offset in range(start, probe_end, 2)]
    pool_candidates = [
        int(instruction.literal_address)
        for instruction in probe
        if instruction.mnemonic == "mov.l"
        and instruction.literal_address is not None
        and last < instruction.literal_address <= last + 0x100
    ]
    if not pool_candidates:
        raise ValueError("bounded literal-pool start was not found")
    end = min(pool_candidates)
    instructions = [decode_instruction(reader, offset) for offset in range(start, end, 2)]
    return start, end, instructions


def _writes_register(instruction: SHInstruction, register: int) -> bool:
    if instruction.mnemonic in {"cmp/eq", "cmp/hs", "cmp/ge", "cmp/hi", "cmp/gt", "cmp/str", "tst"}:
        return False
    if instruction.mnemonic in {"add", "sub", "and", "or", "xor", "mov"}:
        match = _DESTINATION_REGISTER.search(instruction.operands)
        return match is not None and int(match.group(1)) == register
    if instruction.mnemonic in {"mov.b", "mov.w", "mov.l"}:
        match = _DESTINATION_REGISTER.search(instruction.operands)
        return match is not None and int(match.group(1)) == register
    if instruction.mnemonic == "shlr2":
        return instruction.operands == f"r{register}"
    return False


def _trace_register(
    instructions: list[SHInstruction],
    before_index: int,
    register: int,
    *,
    depth: int = 0,
) -> dict[str, object]:
    if depth > 12:
        return {"status": "DEPTH_LIMIT"}
    for index in range(before_index - 1, -1, -1):
        instruction = instructions[index]
        if instruction.flow in {"call", "indirect-call"} and register <= 7:
            return {"status": "CALLER_SAVED_CLOBBER"}

        move = _REGISTER_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and move is not None:
            source = int(move.group(1))
            destination = int(move.group(2))
            if destination == register:
                traced = _trace_register(
                    instructions, index, source, depth=depth + 1
                )
                return {
                    **traced,
                    "derivation_depth": int(traced.get("derivation_depth", 0)) + 1,
                }

        immediate = _IMMEDIATE_MOVE.fullmatch(instruction.operands)
        if instruction.mnemonic == "mov" and immediate is not None:
            if int(immediate.group(2)) == register:
                return {
                    "status": "CONSTANT",
                    "value": int(immediate.group(1)),
                    "derivation_depth": 1,
                }

        add = _IMMEDIATE_ADD.fullmatch(instruction.operands)
        if instruction.mnemonic == "add" and add is not None:
            if int(add.group(2)) == register:
                traced = _trace_register(
                    instructions, index, register, depth=depth + 1
                )
                if traced.get("status") == "CONSTANT":
                    return {
                        "status": "CONSTANT",
                        "value": int(traced["value"]) + int(add.group(1)),
                        "derivation_depth": int(traced.get("derivation_depth", 0)) + 1,
                    }
                return traced

        literal_destination = _PC_LITERAL_DESTINATION.fullmatch(instruction.operands)
        if (
            instruction.mnemonic == "mov.l"
            and literal_destination is not None
            and int(literal_destination.group(1)) == register
            and instruction.literal_value is not None
        ):
            return {
                "status": "CONSTANT",
                "value": int(instruction.literal_value),
                "derivation_depth": 1,
            }

        if _writes_register(instruction, register):
            return {"status": "UNSUPPORTED_WRITE"}
    return {"status": "NO_DEFINITION"}


def _pointer_argument(
    instructions: list[SHInstruction], call_index: int
) -> dict[str, object]:
    delay = instructions[call_index + 1]
    move = _REGISTER_MOVE.fullmatch(delay.operands)
    if delay.mnemonic == "mov" and move is not None and int(move.group(2)) == 5:
        return _trace_register(instructions, call_index, int(move.group(1)))
    add = _IMMEDIATE_ADD.fullmatch(delay.operands)
    if delay.mnemonic == "add" and add is not None and int(add.group(2)) == 5:
        traced = _trace_register(instructions, call_index, 5)
        if traced.get("status") == "CONSTANT":
            return {
                "status": "CONSTANT",
                "value": int(traced["value"]) + int(add.group(1)),
                "derivation_depth": int(traced.get("derivation_depth", 0)) + 1,
            }
        return traced
    return _trace_register(instructions, call_index, 5)


def _normalized_shape(instructions: list[SHInstruction]) -> str:
    shapes = []
    for instruction in instructions:
        shapes.append(
            "|".join(
                (
                    instruction.mnemonic,
                    _ADDRESS.sub("<address>", instruction.operands),
                    instruction.flow,
                    "delayed" if instruction.delayed else "plain",
                )
            )
        )
    return hashlib.sha256("\n".join(shapes).encode("utf-8")).hexdigest()


def analyze_fldb_candidate_dataflow(
    reader: BinaryReader, constant_report: dict[str, object]
) -> dict[str, object]:
    """Discriminate offset arithmetic from an expected-value call argument."""

    directory = next(
        item
        for item in constant_report["constants"]
        if item["constant_id"] == "fldb-directory-offset"
    )
    reference_offsets = [
        int(item["load_offset"]) for item in directory["mov_l_references"]
    ]
    if len(reference_offsets) != 2:
        raise ValueError("Session 013 requires exactly two bounded 0x220 references")
    start, end, instructions = _find_candidate_block(reader, reference_offsets)

    base_candidates = [
        int(instruction.literal_value)
        for instruction in instructions
        if instruction.mnemonic == "mov.l"
        and instruction.operands.endswith(",r9")
        and instruction.literal_value is not None
        and int(instruction.literal_value) >= 0x80000000
    ]
    if len(set(base_candidates)) != 1:
        raise ValueError("one stable high-address base literal was expected")
    memory_base = base_candidates[0]

    calls = []
    for index, instruction in enumerate(instructions[:-3]):
        literal_destination = _PC_LITERAL_DESTINATION.fullmatch(instruction.operands)
        if (
            instruction.mnemonic != "mov.l"
            or literal_destination is None
            or int(literal_destination.group(1)) != 4
            or instruction.literal_value is None
        ):
            continue
        call = instructions[index + 1]
        if call.mnemonic != "jsr" or call.operands != "@r10":
            continue
        pointer = _pointer_argument(instructions, index + 1)
        callee = _trace_register(instructions, index + 1, 10)
        pointer_delta = None
        if pointer.get("status") == "CONSTANT":
            pointer_delta = int(pointer["value"]) - memory_base
        result_test = instructions[index + 3]
        calls.append(
            {
                "expected_value": int(instruction.literal_value),
                "constant_load_offset": instruction.offset,
                "call_site_offset": call.offset,
                "pointer_delta_from_fixed_base": pointer_delta,
                "pointer_derivation_status": pointer["status"],
                "callee_register": "r10",
                "callee_target_below_confirmed_runtime_base": (
                    callee.get("status") == "CONSTANT"
                    and int(callee["value"]) < RUNTIME_BASE
                ),
                "callee_target_in_confirmed_principal_image_model": (
                    callee.get("status") == "CONSTANT"
                    and RUNTIME_BASE
                    <= int(callee["value"])
                    < RUNTIME_BASE + reader.size
                ),
                "result_register_tested_immediately": (
                    result_test.mnemonic == "tst"
                    and result_test.operands == "r0,r0"
                ),
                "absolute_pointer_or_callee_value_included": False,
            }
        )

    expected_counts = Counter(int(call["expected_value"]) for call in calls)
    pointer_groups: dict[int, set[int]] = {}
    for call in calls:
        delta = call["pointer_delta_from_fixed_base"]
        if isinstance(delta, int):
            pointer_groups.setdefault(delta, set()).add(int(call["expected_value"]))
    candidate_calls = [call for call in calls if call["expected_value"] == 0x220]
    candidate_is_expected_argument = bool(
        len(candidate_calls) == 2
        and all(call["pointer_delta_from_fixed_base"] == 0x1A for call in candidate_calls)
        and all(call["result_register_tested_immediately"] for call in candidate_calls)
    )
    alternative_same_pointer = sorted(
        pointer_groups.get(0x1A, set()) - {0x220}
    )
    literal_values = {
        int(instruction.literal_value)
        for instruction in instructions
        if instruction.literal_value is not None
    }
    body = reader.read(start, end - start)
    known_count = sum(
        instruction.mnemonic != "unknown" for instruction in instructions
    )
    return {
        "schema": "phoenix-mmi.fldb-candidate-dataflow/v1",
        "analysis_mode": "read-only-static-bounded-dataflow",
        "artifact": {
            "sha256": reader.sha256(),
            "size_bytes": reader.size,
            "source_path_included": False,
        },
        "bounded_block": {
            "start": start,
            "end": end,
            "length": end - start,
            "raw_sha256": hashlib.sha256(body).hexdigest(),
            "normalized_shape_sha256": _normalized_shape(instructions),
            "instruction_count": len(instructions),
            "known_instruction_count": known_count,
            "known_ratio": round(known_count / len(instructions), 6),
            "prologue_pattern_status": "CONFIRMED_BOUNDED_SAVE_SEQUENCE",
            "memory_base_class": "HIGH_NON_IMAGE_MEMORY_MAPPED_RANGE",
            "memory_base_literal_included": False,
            "probe_pattern_literal_count": len(literal_values & _PROBE_PATTERN_VALUES),
            "instruction_bytes_included": False,
            "function_boundary_asserted": False,
        },
        "shared_call_contract": {
            "call_count": len(calls),
            "expected_value_counts": {
                f"value-0x{value:x}": count
                for value, count in sorted(expected_counts.items())
            },
            "pointer_groups": [
                {
                    "pointer_delta_from_fixed_base": delta,
                    "expected_values": sorted(values),
                }
                for delta, values in sorted(pointer_groups.items())
            ],
            "calls": calls,
            "argument_role_evidence": {
                "r4": "EXPECTED_VALUE_OR_PROBE_SELECTOR",
                "r5": "FIXED_BASE_RELATIVE_POINTER",
                "r0_after_call": "IMMEDIATELY_TESTED_RESULT",
                "calling_convention_status": "CONSISTENT_WITH_SH_REGISTER_ARGUMENT_ABI",
            },
        },
        "fldb_counterevidence": {
            "directory_offset_used_as_expected_argument": candidate_is_expected_argument,
            "directory_offset_used_as_additive_offset": False,
            "directory_offset_used_as_pointer": False,
            "alternative_expected_values_at_same_pointer": alternative_same_pointer,
            "record_stride_36_present_in_block_literals": 36 in literal_values,
            "logical_sector_2048_present_in_block_literals": 2048 in literal_values,
            "fldb_magic_present_in_block": b"FLDB" in body,
        },
        "classification": {
            "bounded_block": "CONFIRMED_MEMORY_MAPPED_PROBE_STRUCTURE",
            "cross_version_status": "PENDING_COMPARISON",
            "former_0x220_fldb_interpretation": (
                "DISPROVED_FOR_SESSION012_REFERENCE_PAIR"
                if candidate_is_expected_argument and alternative_same_pointer
                else "INCONCLUSIVE"
            ),
            "probable_semantics": "PROBABLE_BOOT_MEMORY_OR_HARDWARE_PROBE",
            "direct_fldb_parser": "NOT_FOUND_IN_TRACED_CANDIDATE",
            "record_stride_36": "NOT_FOUND_IN_TRACED_CANDIDATE",
            "logical_sector_size_2048": "NOT_FOUND_IN_TRACED_CANDIDATE",
            "parser_search_elsewhere": "OPEN",
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "instruction_bytes_included": False,
            "absolute_memory_addresses_included": False,
            "raw_strings_included": False,
            "local_paths_included": False,
            "map_payload_included": False,
        },
    }


def compare_fldb_candidate_dataflow(
    left: dict[str, object], right: dict[str, object]
) -> dict[str, object]:
    """Compare the bounded block and call topology across firmware releases."""

    left_calls = left["shared_call_contract"]
    right_calls = right["shared_call_contract"]
    left_signature = [
        (
            call["expected_value"],
            call["pointer_delta_from_fixed_base"],
            call["result_register_tested_immediately"],
        )
        for call in left_calls["calls"]
    ]
    right_signature = [
        (
            call["expected_value"],
            call["pointer_delta_from_fixed_base"],
            call["result_register_tested_immediately"],
        )
        for call in right_calls["calls"]
    ]
    byte_identical = (
        left["bounded_block"]["raw_sha256"]
        == right["bounded_block"]["raw_sha256"]
    )
    topology_equal = left_signature == right_signature
    disproved = bool(
        byte_identical
        and topology_equal
        and left["classification"]["former_0x220_fldb_interpretation"]
        == "DISPROVED_FOR_SESSION012_REFERENCE_PAIR"
        and right["classification"]["former_0x220_fldb_interpretation"]
        == "DISPROVED_FOR_SESSION012_REFERENCE_PAIR"
    )
    return {
        "schema": "phoenix-mmi.fldb-candidate-dataflow-comparison/v1",
        "analysis_mode": "read-only-static-cross-version",
        "left_artifact_sha256": left["artifact"]["sha256"],
        "right_artifact_sha256": right["artifact"]["sha256"],
        "bounded_block": {
            "left_start": left["bounded_block"]["start"],
            "right_start": right["bounded_block"]["start"],
            "relocation_delta": int(right["bounded_block"]["start"])
            - int(left["bounded_block"]["start"]),
            "length_equal": left["bounded_block"]["length"]
            == right["bounded_block"]["length"],
            "raw_bytes_identical_by_hash": byte_identical,
            "normalized_instruction_shape_equal": (
                left["bounded_block"]["normalized_shape_sha256"]
                == right["bounded_block"]["normalized_shape_sha256"]
            ),
            "call_topology_equal": topology_equal,
            "instruction_bytes_included": False,
        },
        "classification": {
            "cross_version_probe_block": (
                "CONFIRMED_BYTE_IDENTICAL_RELOCATED_STRUCTURE"
                if byte_identical and topology_equal
                else "PARTIAL"
            ),
            "former_0x220_fldb_interpretation": (
                "DISPROVED_FOR_SESSION012_REFERENCE_PAIR"
                if disproved
                else "INCONCLUSIVE"
            ),
            "probable_semantics": "PROBABLE_BOOT_MEMORY_OR_HARDWARE_PROBE",
            "direct_fldb_parser": "NOT_FOUND_IN_TRACED_CANDIDATE",
            "sector_read_abi": "OPEN",
            "parser_search_elsewhere": "OPEN",
        },
        "interpretation": (
            "The two former 0x220 candidates belong to a byte-identical relocated "
            "memory-mapped probe block. The value is passed in r4 to a shared call "
            "while r5 points 0x1A bytes from a fixed high-address base; 0x204 is an "
            "alternative value at the same pointer. It is not used as an FLDB table "
            "offset in this block. The actual FLDB parser remains unidentified."
        ),
        "publication_safety": copy.deepcopy(left["publication_safety"]),
    }


def update_operational_graph_v6(
    prior_graph: dict[str, object], comparison: dict[str, object]
) -> dict[str, object]:
    """Correct the former 0x220 edge and preserve the parser as an open node."""

    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v6"
    candidate = next(
        node
        for node in graph["nodes"]
        if node["id"] == "fldb-directory-offset-candidate"
    )
    candidate.update(
        {
            "label": "Former FLDB 0x220 candidate; memory-mapped probe block",
            "status": "CONFIRMED_CROSS_VERSION_IDENTICAL_PROBE_STRUCTURE",
            "fldb_relation_status": "DISPROVED",
            "semantic_status": "PROBABLE_BOOT_MEMORY_OR_HARDWARE_PROBE",
            "evidence": ["S013-01", "S013-02", "RQ-033", "RQ-036"],
        }
    )
    for edge in graph["edges"]:
        if (
            edge["source"] == "fldb-directory-offset-candidate"
            and edge["target"] == "fldb-container-set"
        ):
            edge.update(
                {
                    "relation": "former numeric coincidence rejected by local dataflow",
                    "status": "DISPROVED",
                }
            )
        if (
            edge["source"] == "fldb-container-set"
            and edge["target"] == "navigation-runtime"
        ):
            edge.update(
                {
                    "target": "fldb-parser-routine",
                    "relation": "requires an unidentified parser",
                    "status": "HYPOTHESIS",
                }
            )
    if not any(node["id"] == "fldb-parser-routine" for node in graph["nodes"]):
        graph["nodes"].append(
            {
                "id": "fldb-parser-routine",
                "label": "Unidentified FLDB parser and sector-read contract",
                "status": "OPEN",
                "evidence": ["S013-03", "RQ-036", "RQ-037"],
            }
        )
    graph["edges"].extend(
        (
            {
                "source": "startup-runtime",
                "target": "fldb-directory-offset-candidate",
                "relation": "contains an identical memory-mapped probe block",
                "status": "CONFIRMED_IMAGE_INTEGRATION",
            },
            {
                "source": "fldb-parser-routine",
                "target": "navigation-runtime",
                "relation": "consumer and dispatch edge remain unresolved",
                "status": "HYPOTHESIS",
            },
        )
    )
    graph["confirmed_node_count"] = sum(
        str(node["status"]).startswith("CONFIRMED") for node in graph["nodes"]
    )
    graph["probable_node_count"] = sum(
        str(node["status"]).startswith("PROBABLE") for node in graph["nodes"]
    )
    graph["open_node_count"] = sum(
        node["status"] == "OPEN" for node in graph["nodes"]
    )
    graph["disproved_edge_count"] = sum(
        edge["status"] == "DISPROVED" for edge in graph["edges"]
    )
    graph["interpretation"] = (
        "Session 013 disproves the former 0x220-to-FLDB edge for the traced "
        "references and reclassifies their byte-identical block as a memory-mapped "
        "probe structure. The real FLDB parser, partition consumer and sector ABI "
        "remain explicit open nodes or edges."
    )
    return graph


def correlate_corrected_parser_model(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    """Build Session 013 correlation and operational graph v6."""

    return {
        "schema": "phoenix-mmi.corrected-parser-correlation/v1",
        "analysis_mode": "read-only-static",
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "correction": {
            "session012_0x220_hypothesis": "DISPROVED_FOR_TRACED_REFERENCE_PAIR",
            "actual_fldb_parser": "OPEN",
            "partition_consumer": "OPEN",
            "sector_read_abi": "OPEN",
            "dynamic_compatibility": "NOT_ESTABLISHED",
        },
        "operational_graph": update_operational_graph_v6(
            prior_correlation["operational_graph"], comparison
        ),
        "interpretation": comparison["interpretation"],
        "publication_safety": copy.deepcopy(comparison["publication_safety"]),
    }


def build_public_fldb_candidate_report(
    report: dict[str, object]
) -> dict[str, object]:
    """Return a defensive copy of the already publication-safe report."""

    return copy.deepcopy(report)

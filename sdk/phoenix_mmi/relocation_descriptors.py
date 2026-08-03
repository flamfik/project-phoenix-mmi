"""Bounded section-reorder descriptor search for Session 033.

The search is deliberately seeded by the two support zones surrounding the
single Session 032 section-reorder bracket.  It does not enumerate arbitrary
whole-image integer tuples.  A promoted candidate needs multiple coherent
records, exact seed coverage, a syntactic PC-relative table-reference form and a
matching candidate in the other firmware release.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
from itertools import permutations

from .binary import BinaryReader
from .navigation_storage import RUNTIME_BASE
from .runtime_slot import FLASH_BASE


_MAXIMUM_COPY_LENGTH = 0x400000
_MAXIMUM_TABLE_RECORDS = 128
_TRAILING_FLAG_VALUES = frozenset((0, 1, 2, 4, 0xFFFFFFFF))
_ADDRESS_MODELS = (
    ("raw-file-offset", 0),
    ("metainfo-flash", FLASH_BASE),
    ("runtime-link", RUNTIME_BASE),
)
_FIELD_ORDERS = tuple(permutations(("source", "destination", "length")))
_RECORD_WIDTHS = (12, 16)
_SEED_ALIGNMENTS = (4, 0x100, 0x1000)


def _find_all(data: bytes, needle: bytes) -> list[int]:
    offsets = []
    cursor = 0
    while True:
        cursor = data.find(needle, cursor)
        if cursor < 0:
            return offsets
        offsets.append(cursor)
        cursor += 1


def _align_down(value: int, alignment: int) -> int:
    return value - (value % alignment)


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _zone_boundary_seeds(
    zone: dict[str, object],
) -> list[tuple[str, int]]:
    rows = [
        ("start-exact", int(zone["start"])),
        ("end-exact", int(zone["end"])),
    ]
    for alignment in _SEED_ALIGNMENTS:
        rows.extend(
            [
                (
                    f"start-align-down-{alignment}",
                    _align_down(int(zone["start"]), alignment),
                ),
                (
                    f"start-align-up-{alignment}",
                    _align_up(int(zone["start"]), alignment),
                ),
                (
                    f"end-align-down-{alignment}",
                    _align_down(int(zone["end"]), alignment),
                ),
                (
                    f"end-align-up-{alignment}",
                    _align_up(int(zone["end"]), alignment),
                ),
            ]
        )
    return list(dict.fromkeys(rows))


def _zone_length_seeds(
    zone: dict[str, object],
) -> list[tuple[str, int]]:
    rows = [("length-exact", int(zone["length"]))]
    for alignment in _SEED_ALIGNMENTS:
        start = _align_down(int(zone["start"]), alignment)
        end = _align_up(int(zone["end"]), alignment)
        rows.append((f"aligned-envelope-{alignment}", end - start))
    return list(dict.fromkeys(rows))


def _validate_prior(prior: dict[str, object]) -> dict[str, object]:
    if prior.get("schema") != (
        "phoenix-mmi.relocation-breakpoint-comparison/v1"
    ):
        raise ValueError("unsupported Session 032 comparison schema")
    brackets = [
        row
        for row in prior.get("breakpoint_brackets", [])
        if row.get("classification") == "SECTION_REORDER_BRACKET"
    ]
    if len(brackets) != 1:
        raise ValueError("exactly one section-reorder bracket is required")
    bracket = brackets[0]
    zones = {
        row["zone_id"]: row for row in prior.get("support_zones", [])
    }
    if bracket["left_zone_id"] not in zones:
        raise ValueError("left reorder support zone is absent")
    if bracket["right_zone_id"] not in zones:
        raise ValueError("right reorder support zone is absent")
    if bracket.get("right_order_monotonic") is not False:
        raise ValueError("prior bracket does not prove a right-side reorder")
    return {
        "bracket": bracket,
        "zones": (
            zones[bracket["left_zone_id"]],
            zones[bracket["right_zone_id"]],
        ),
    }


def _disc_zones(
    validated: dict[str, object], *, side: str
) -> list[dict[str, object]]:
    prefix = "left" if side == "left" else "right"
    rows = []
    for zone in validated["zones"]:
        start = int(zone[f"{prefix}_start"])
        end = int(zone[f"{prefix}_end"])
        if not 0 <= start < end:
            raise ValueError(f"invalid {side} support-zone geometry")
        rows.append(
            {
                "zone_id": zone["zone_id"],
                "source_id": zone["source_id"],
                "start": start,
                "end": end,
                "length": end - start,
                "evidence_class": zone["evidence_class"],
            }
        )
    return rows


def _seed_occurrences(
    data: bytes, zones: list[dict[str, object]]
) -> tuple[dict[tuple[str, int], list[int]], dict[str, object]]:
    occurrences: dict[tuple[str, int], list[int]] = {}
    rows = []
    for zone in zones:
        for boundary_name, boundary in _zone_boundary_seeds(zone):
            for model_name, base in _ADDRESS_MODELS:
                offsets = _find_all(
                    data, (base + boundary).to_bytes(4, "big")
                )
                occurrences[(model_name, boundary)] = offsets
                rows.append(
                    {
                        "zone_id": zone["zone_id"],
                        "seed_kind": boundary_name,
                        "address_model": model_name,
                        "occurrence_count": len(offsets),
                    }
                )
        for length_name, length in _zone_length_seeds(zone):
            length_offsets = _find_all(data, length.to_bytes(4, "big"))
            occurrences[("scalar", length)] = length_offsets
            rows.append(
                {
                    "zone_id": zone["zone_id"],
                    "seed_kind": length_name,
                    "address_model": "scalar",
                    "occurrence_count": len(length_offsets),
                }
            )
    boundary_seed_count = sum(
        len(_zone_boundary_seeds(zone)) for zone in zones
    )
    length_seed_count = sum(
        len(_zone_length_seeds(zone)) for zone in zones
    )
    return occurrences, {
        "tested_zone_count": len(zones),
        "tested_boundary_seed_count": boundary_seed_count,
        "tested_address_model_count": len(_ADDRESS_MODELS),
        "tested_scalar_length_seed_count": length_seed_count,
        "seed_alignments": list(_SEED_ALIGNMENTS),
        "total_occurrence_count": sum(
            int(row["occurrence_count"]) for row in rows
        ),
        "matched_seed_variant_count": sum(
            bool(row["occurrence_count"]) for row in rows
        ),
        "rows": rows,
    }


def _decode_record(
    data: bytes,
    *,
    offset: int,
    width: int,
    order: tuple[str, str, str],
    source_model: tuple[str, int],
    destination_model: tuple[str, int],
) -> dict[str, object] | None:
    if offset < 0 or offset + width > len(data) or offset % 4:
        return None
    words = [
        int.from_bytes(data[offset + index : offset + index + 4], "big")
        for index in range(0, 12, 4)
    ]
    fields = dict(zip(order, words))
    source = int(fields["source"]) - source_model[1]
    destination = int(fields["destination"]) - destination_model[1]
    length = int(fields["length"])
    if not 4 <= length <= _MAXIMUM_COPY_LENGTH or length % 4:
        return None
    if source == destination:
        return None
    if not 0 <= source <= len(data) - length:
        return None
    if not 0 <= destination <= len(data) - length:
        return None
    trailing_flag = None
    if width == 16:
        trailing_flag = int.from_bytes(data[offset + 12 : offset + 16], "big")
        if trailing_flag not in _TRAILING_FLAG_VALUES:
            return None
    return {
        "record_file_offset": offset,
        "source": source,
        "destination": destination,
        "length": length,
        "trailing_flag": trailing_flag,
    }


def _interval_overlaps(
    start: int, length: int, zone: dict[str, object]
) -> bool:
    return start < int(zone["end"]) and start + length > int(zone["start"])


def _interval_covers(
    start: int, length: int, zone: dict[str, object]
) -> bool:
    return start <= int(zone["start"]) and (
        start + length >= int(zone["end"])
    )


def _non_overlapping(records: list[dict[str, object]], field: str) -> bool:
    intervals = sorted(
        (int(row[field]), int(row[field]) + int(row["length"]))
        for row in records
    )
    return all(
        intervals[index - 1][1] <= intervals[index][0]
        for index in range(1, len(intervals))
    )


def _pc_relative_reference_index(
    data: bytes,
) -> dict[int, list[dict[str, object]]]:
    rows: dict[int, list[dict[str, object]]] = defaultdict(list)
    for offset in range(0, len(data) - 2, 2):
        word = int.from_bytes(data[offset : offset + 2], "big")
        if word & 0xF000 != 0xD000:
            continue
        literal = (offset & ~3) + 4 + (word & 0xFF) * 4
        if literal + 4 > len(data):
            continue
        value = int.from_bytes(data[literal : literal + 4], "big")
        for model_name, base in _ADDRESS_MODELS:
            target = value - base
            if 0 <= target < len(data):
                rows[target].append(
                    {
                        "instruction_file_offset": offset,
                        "literal_file_offset": literal,
                        "address_model": model_name,
                    }
                )
    return dict(rows)


def _pc_relative_table_references(
    index: dict[int, list[dict[str, object]]], table_start: int
) -> dict[str, object]:
    reference_offsets = index.get(table_start, [])
    counts = Counter(
        str(row["address_model"]) for row in reference_offsets
    )
    return {
        "reference_count": len(reference_offsets),
        "address_model_counts": dict(sorted(counts.items())),
        "references": copy.deepcopy(reference_offsets),
    }


def _record_seed_zones(
    record: dict[str, object],
    zones: list[dict[str, object]],
) -> set[str]:
    seeded = set()
    for zone in zones:
        boundaries = {
            value for _, value in _zone_boundary_seeds(zone)
        }
        lengths = {value for _, value in _zone_length_seeds(zone)}
        if (
            int(record["source"]) in boundaries
            or int(record["destination"]) in boundaries
            or int(record["length"]) in lengths
        ):
            seeded.add(str(zone["zone_id"]))
    return seeded


def _record_coverage(
    records: list[dict[str, object]],
    zones: list[dict[str, object]],
) -> list[dict[str, object]]:
    rows = []
    for zone in zones:
        roles = []
        covering_records = []
        for ordinal, record in enumerate(records):
            record_roles = []
            if _interval_covers(
                int(record["source"]), int(record["length"]), zone
            ):
                record_roles.append("source")
            if _interval_covers(
                int(record["destination"]), int(record["length"]), zone
            ):
                record_roles.append("destination")
            if record_roles:
                roles.extend(record_roles)
                covering_records.append(
                    {
                        "record_ordinal": ordinal,
                        "roles": record_roles,
                        "length": record["length"],
                        "source_start_relative_to_zone": (
                            int(record["source"]) - int(zone["start"])
                        ),
                        "destination_start_relative_to_zone": (
                            int(record["destination"])
                            - int(zone["start"])
                        ),
                    }
                )
        rows.append(
            {
                "zone_id": zone["zone_id"],
                "covered": bool(covering_records),
                "roles": sorted(set(roles)),
                "covering_records": covering_records,
            }
        )
    return rows


def _expand_table(
    data: bytes,
    *,
    record_start: int,
    width: int,
    order: tuple[str, str, str],
    source_model: tuple[str, int],
    destination_model: tuple[str, int],
) -> list[dict[str, object]]:
    start = record_start
    for _ in range(_MAXIMUM_TABLE_RECORDS - 1):
        previous = start - width
        if (
            _decode_record(
                data,
                offset=previous,
                width=width,
                order=order,
                source_model=source_model,
                destination_model=destination_model,
            )
            is None
        ):
            break
        start = previous
    records = []
    cursor = start
    while len(records) < _MAXIMUM_TABLE_RECORDS:
        record = _decode_record(
            data,
            offset=cursor,
            width=width,
            order=order,
            source_model=source_model,
            destination_model=destination_model,
        )
        if record is None:
            break
        records.append(record)
        cursor += width
    return records


def _candidate_signature(candidate: dict[str, object]) -> tuple[object, ...]:
    coverage = []
    for zone in candidate["zone_coverage"]:
        covering = zone["covering_records"]
        coverage.append(
            (
                tuple(zone["roles"]),
                tuple(
                    (
                        row["length"],
                        tuple(row["roles"]),
                        (
                            row["source_start_relative_to_zone"]
                            if "source" in row["roles"]
                            else None
                        ),
                        (
                            row["destination_start_relative_to_zone"]
                            if "destination" in row["roles"]
                            else None
                        ),
                    )
                    for row in covering
                ),
            )
        )
    return (
        candidate["record_width"],
        candidate["field_order"],
        candidate["source_address_model"],
        candidate["destination_address_model"],
        candidate["record_count"],
        tuple(candidate["length_vector"]),
        tuple(candidate["trailing_flag_vector"]),
        tuple(coverage),
    )


def _scan_disc(
    reader: BinaryReader,
    zones: list[dict[str, object]],
) -> dict[str, object]:
    data = reader.read(0, reader.size)
    seed_occurrences, seed_census = _seed_occurrences(data, zones)
    reference_index = _pc_relative_reference_index(data)
    expected_zone_ids = {str(zone["zone_id"]) for zone in zones}
    candidates: dict[tuple[object, ...], dict[str, object]] = {}
    valid_seeded_records = set()
    decode_attempts = 0

    for width in _RECORD_WIDTHS:
        for order in _FIELD_ORDERS:
            source_index = order.index("source")
            destination_index = order.index("destination")
            length_index = order.index("length")
            for source_model in _ADDRESS_MODELS:
                for destination_model in _ADDRESS_MODELS:
                    starts = set()
                    for zone in zones:
                        for _, boundary in _zone_boundary_seeds(zone):
                            for occurrence in seed_occurrences[
                                (source_model[0], boundary)
                            ]:
                                starts.add(occurrence - source_index * 4)
                            for occurrence in seed_occurrences[
                                (destination_model[0], boundary)
                            ]:
                                starts.add(
                                    occurrence - destination_index * 4
                                )
                        for _, length in _zone_length_seeds(zone):
                            for occurrence in seed_occurrences[
                                ("scalar", length)
                            ]:
                                starts.add(
                                    occurrence - length_index * 4
                                )
                    for record_start in sorted(starts):
                        decode_attempts += 1
                        seed_record = _decode_record(
                            data,
                            offset=record_start,
                            width=width,
                            order=order,
                            source_model=source_model,
                            destination_model=destination_model,
                        )
                        if seed_record is None:
                            continue
                        valid_seeded_records.add(
                            (
                                record_start,
                                width,
                                order,
                                source_model[0],
                                destination_model[0],
                            )
                        )
                        records = _expand_table(
                            data,
                            record_start=record_start,
                            width=width,
                            order=order,
                            source_model=source_model,
                            destination_model=destination_model,
                        )
                        if len(records) < 2:
                            continue
                        table_start = int(records[0]["record_file_offset"])
                        key = (
                            table_start,
                            width,
                            order,
                            source_model[0],
                            destination_model[0],
                        )
                        seeded_zones = set().union(
                            *(
                                _record_seed_zones(record, zones)
                                for record in records
                            )
                        )
                        coverage = _record_coverage(records, zones)
                        coherent = (
                            seeded_zones == expected_zone_ids
                            and all(row["covered"] for row in coverage)
                            and _non_overlapping(records, "source")
                            and _non_overlapping(records, "destination")
                        )
                        references = (
                            _pc_relative_table_references(
                                reference_index, table_start
                            )
                            if coherent
                            else {
                                "reference_count": 0,
                                "address_model_counts": {},
                                "references": [],
                            }
                        )
                        candidate = {
                            "table_start_file_offset": table_start,
                            "table_end_file_offset": (
                                table_start + len(records) * width
                            ),
                            "record_width": width,
                            "field_order": "-".join(order),
                            "source_address_model": source_model[0],
                            "destination_address_model": destination_model[0],
                            "record_count": len(records),
                            "length_vector": [
                                row["length"] for row in records
                            ],
                            "trailing_flag_vector": [
                                row["trailing_flag"] for row in records
                            ],
                            "seeded_zone_ids": sorted(seeded_zones),
                            "zone_coverage": coverage,
                            "source_intervals_non_overlapping": (
                                _non_overlapping(records, "source")
                            ),
                            "destination_intervals_non_overlapping": (
                                _non_overlapping(records, "destination")
                            ),
                            "coherent_two_zone_geometry": coherent,
                            "pc_relative_table_references": references,
                            "promoted": (
                                coherent
                                and int(references["reference_count"]) > 0
                            ),
                            "runtime_behavior_asserted": False,
                            "descriptor_semantics_asserted": False,
                        }
                        candidates[key] = candidate

    rows = sorted(
        candidates.values(),
        key=lambda row: (
            int(row["table_start_file_offset"]),
            int(row["record_width"]),
            str(row["field_order"]),
            str(row["source_address_model"]),
            str(row["destination_address_model"]),
        ),
    )
    coherent = [
        row for row in rows if row["coherent_two_zone_geometry"]
    ]
    promoted = [row for row in coherent if row["promoted"]]
    summary = {
        "record_width_distribution": {
            str(key): value
            for key, value in sorted(
                Counter(int(row["record_width"]) for row in rows).items()
            )
        },
        "field_order_distribution": dict(
            sorted(Counter(str(row["field_order"]) for row in rows).items())
        ),
        "address_model_pair_distribution": dict(
            sorted(
                Counter(
                    (
                        f"{row['source_address_model']}->"
                        f"{row['destination_address_model']}"
                    )
                    for row in rows
                ).items()
            )
        ),
        "record_count_distribution": {
            str(key): value
            for key, value in sorted(
                Counter(int(row["record_count"]) for row in rows).items()
            )
        },
    }
    return {
        "artifact_sha256": reader.sha256(),
        "artifact_size": reader.size,
        "zones": copy.deepcopy(zones),
        "seed_census": seed_census,
        "bounded_decode_attempt_count": decode_attempts,
        "valid_seeded_single_record_count": len(
            valid_seeded_records
        ),
        "multi_record_seeded_candidate_count": len(rows),
        "coherent_two_zone_candidate_count": len(coherent),
        "referenced_promoted_candidate_count": len(promoted),
        "multi_record_candidate_summary": summary,
        "candidates": coherent,
    }


def _pair_candidates(
    left: dict[str, object], right: dict[str, object]
) -> list[dict[str, object]]:
    left_rows = [
        row for row in left["candidates"] if row["promoted"]
    ]
    right_by_signature: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for row in right["candidates"]:
        if row["promoted"]:
            right_by_signature.setdefault(
                _candidate_signature(row), []
            ).append(row)
    pairs = []
    for left_row in left_rows:
        for right_row in right_by_signature.get(
            _candidate_signature(left_row), []
        ):
            pairs.append(
                {
                    "pair_id": f"RD-{len(pairs) + 1:03d}",
                    "left_table_start_file_offset": left_row[
                        "table_start_file_offset"
                    ],
                    "right_table_start_file_offset": right_row[
                        "table_start_file_offset"
                    ],
                    "record_width": left_row["record_width"],
                    "field_order": left_row["field_order"],
                    "source_address_model": left_row[
                        "source_address_model"
                    ],
                    "destination_address_model": left_row[
                        "destination_address_model"
                    ],
                    "record_count": left_row["record_count"],
                    "length_vector": left_row["length_vector"],
                    "zone_geometry_equal": True,
                    "both_tables_pc_relative_referenced": True,
                    "runtime_behavior_asserted": False,
                    "descriptor_semantics_asserted": False,
                }
            )
    return pairs


def update_operational_graph_v26(
    prior_graph: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    graph = copy.deepcopy(prior_graph)
    graph["schema"] = "phoenix-mmi.operational-graph/v26"
    graph["nodes"].extend(
        [
            {
                "id": "reorder-zone-descriptor-seeds",
                "status": "CONFIRMED",
                "evidence": (
                    "Two Session 032 support zones bound the only confirmed "
                    "section-reorder bracket."
                ),
            },
            {
                "id": "bilateral-reorder-descriptor-table",
                "status": (
                    "PROBABLE"
                    if comparison["bilateral_descriptor_pairs"]
                    else "BOUNDED_NEGATIVE"
                ),
                "evidence": comparison["interpretation"],
            },
        ]
    )
    graph["edges"].extend(
        [
            {
                "source": "relocation-support-zones",
                "target": "reorder-zone-descriptor-seeds",
                "status": "CONFIRMED",
                "relation": "bounds",
            },
            {
                "source": "reorder-zone-descriptor-seeds",
                "target": "bilateral-reorder-descriptor-table",
                "status": (
                    "PROBABLE"
                    if comparison["bilateral_descriptor_pairs"]
                    else "BOUNDED_NEGATIVE"
                ),
                "relation": "bounded-search",
            },
        ]
    )
    return graph


def analyze_relocation_descriptors(
    left_reader: BinaryReader,
    right_reader: BinaryReader,
    prior: dict[str, object],
) -> dict[str, object]:
    """Search the Session 032 reorder bracket under a closed grammar."""

    validated = _validate_prior(prior)
    if left_reader.sha256() != prior.get("left_artifact_sha256"):
        raise ValueError("left principal-image hash differs from Session 032")
    if right_reader.sha256() != prior.get("right_artifact_sha256"):
        raise ValueError("right principal-image hash differs from Session 032")

    left = _scan_disc(
        left_reader, _disc_zones(validated, side="left")
    )
    right = _scan_disc(
        right_reader, _disc_zones(validated, side="right")
    )
    pairs = _pair_candidates(left, right)
    classification = {
        "section_reorder_anchor": "CONFIRMED_PRIOR_BOUNDED_STRUCTURAL",
        "closed_address_model_count": len(_ADDRESS_MODELS),
        "closed_field_order_count": len(_FIELD_ORDERS),
        "closed_record_width_count": len(_RECORD_WIDTHS),
        "left_coherent_two_zone_candidate_count": left[
            "coherent_two_zone_candidate_count"
        ],
        "right_coherent_two_zone_candidate_count": right[
            "coherent_two_zone_candidate_count"
        ],
        "left_referenced_promoted_candidate_count": left[
            "referenced_promoted_candidate_count"
        ],
        "right_referenced_promoted_candidate_count": right[
            "referenced_promoted_candidate_count"
        ],
        "bilateral_descriptor_pair_count": len(pairs),
        "coherent_reorder_descriptor_table": (
            "PROBABLE_BILATERAL_STRUCTURAL"
            if pairs
            else "CLOSED_BOUNDED_NEGATIVE"
        ),
        "exact_section_boundary": "OPEN",
        "loader_transform": "OPEN",
        "runtime_execution_observed": False,
    }
    interpretation = (
        "At least one bilateral, PC-relative referenced multi-record table "
        "matches both reorder zones under the closed source/destination/"
        "length grammar. Static descriptor semantics remain probable."
        if pairs
        else (
            "No bilateral table passes the closed multi-record geometry, "
            "two-zone seed, PC-relative reference and cross-release gates. "
            "This is a bounded negative; other record widths, encodings, "
            "indirection and external loader metadata remain open."
        )
    )
    return {
        "schema": "phoenix-mmi.relocation-descriptor-comparison/v1",
        "analysis_mode": (
            "read-only-static-section-reorder-seeded-descriptor-search"
        ),
        "left_artifact_sha256": left_reader.sha256(),
        "right_artifact_sha256": right_reader.sha256(),
        "source_session032_schema": prior["schema"],
        "reorder_bracket": copy.deepcopy(validated["bracket"]),
        "search_contract": {
            "address_models": [
                {"name": name, "base_disclosed": False}
                for name, _ in _ADDRESS_MODELS
            ],
            "record_widths": list(_RECORD_WIDTHS),
            "zone_seed_alignments": list(_SEED_ALIGNMENTS),
            "field_orders": ["-".join(order) for order in _FIELD_ORDERS],
            "maximum_copy_length": _MAXIMUM_COPY_LENGTH,
            "trailing_flag_values_disclosed": False,
            "minimum_record_count": 2,
            "both_zone_closed_seed_required": True,
            "both_zone_interval_coverage_required": True,
            "non_overlapping_source_and_destination_required": True,
            "pc_relative_table_reference_required": True,
            "bilateral_equal_geometry_required": True,
            "arbitrary_whole_image_tuple_scan_performed": False,
        },
        "left": left,
        "right": right,
        "bilateral_descriptor_pairs": pairs,
        "classification": classification,
        "interpretation": interpretation,
        "limits": [
            "Only 12-byte records and 16-byte records with a closed trailing-flag set are tested.",
            "Only big-endian words and three independently motivated address models are tested.",
            "Exact zone endpoints are seeds; the exact section boundary is not assumed.",
            "PC-relative MOV.L references are modeled; computed, memory-loaded and external references are not.",
            "The MOV.L reference census is syntactic and does not assert that each matched halfword is executed code.",
            "A zero result does not exclude compressed, indirect, variable-width or external loader metadata.",
            "Static geometry does not prove runtime execution or copy semantics.",
        ],
        "publication_safety": {
            "firmware_bytes_included": False,
            "raw_pointer_values_included": False,
            "absolute_runtime_addresses_included": False,
            "raw_strings_included": False,
            "local_paths_included": False,
            "extracted_resources_included": False,
        },
    }


def correlate_relocation_descriptors(
    prior_correlation: dict[str, object],
    comparison: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.relocation-descriptor-correlation/v1",
        "analysis_mode": comparison["analysis_mode"],
        "firmware": copy.deepcopy(comparison["classification"]),
        "media": copy.deepcopy(prior_correlation["media"]),
        "cross_domain_descriptor_edge": "NOT_ASSERTED",
        "interpretation": comparison["interpretation"],
        "operational_graph": update_operational_graph_v26(
            prior_correlation["operational_graph"], comparison
        ),
        "publication_safety": copy.deepcopy(
            comparison["publication_safety"]
        ),
    }


def build_public_relocation_descriptor_report(
    report: dict[str, object],
) -> dict[str, object]:
    return copy.deepcopy(report)

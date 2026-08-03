"""Confidence-graded knowledge and blocker matrix for M6."""

from __future__ import annotations


NAVIGATION_KNOWLEDGE_SCHEMA = "phoenix-mmi.navigation-knowledge-matrix/v1"


def build_navigation_knowledge_matrix(
    evidence: dict[str, object],
) -> dict[str, object]:
    """Separate confirmed structure from unresolved target semantics."""

    if evidence.get("schema") != "phoenix-mmi.navigation-evidence-ledger/v1":
        raise ValueError("unsupported evidence ledger")
    rows = [
        _row("optical-filesystem", "storage", "CONFIRMED", "Session 011"),
        _row("outer-fldb-container", "container", "CONFIRMED", "Session 011"),
        _row(
            "fixed-record-table",
            "container",
            "CONFIRMED",
            "Session 011",
        ),
        _row(
            "payload-family-headers",
            "payload",
            "CONFIRMED_STRUCTURE_ONLY",
            "Session 012",
        ),
        _row(
            "cross-family-partition-domain",
            "payload",
            "CONFIRMED_STRUCTURE_ONLY",
            "Session 012",
        ),
        _row("routing-graph-grammar", "semantics", "OPEN", "M6 blocker"),
        _row("coordinate-encoding", "semantics", "OPEN", "M6 blocker"),
        _row("spatial-index-semantics", "semantics", "OPEN", "M6 blocker"),
        _row("firmware-inner-consumer", "runtime", "OPEN", "Sessions 009-042"),
        _row("sector-read-abi", "runtime", "OPEN", "Sessions 010-018"),
        _row("proprietary-write-model", "writer", "OPEN", "M6 blocker"),
        _row("proprietary-integrity-model", "integrity", "OPEN", "M6 blocker"),
        _row("target-memory-timing-budget", "runtime", "OPEN", "M6 blocker"),
        _row("recovery-validation", "safety", "OPEN", "M7 prerequisite"),
    ]
    blockers = [
        row["knowledge_id"]
        for row in rows
        if row["status"] == "OPEN"
        and row["domain"] in {"semantics", "runtime", "writer", "integrity", "safety"}
    ]
    matrix = {
        "schema": NAVIGATION_KNOWLEDGE_SCHEMA,
        "matrix_version": "m6-session104-v1",
        "rows": rows,
        "summary": {
            "row_count": len(rows),
            "confirmed_or_structural_count": sum(
                row["status"].startswith("CONFIRMED") for row in rows
            ),
            "open_count": sum(row["status"] == "OPEN" for row in rows),
            "direct_replacement_blocker_count": len(blockers),
        },
        "direct_replacement_gate": {
            "required_closed_items": blockers,
            "passed": False,
            "status": "BLOCKED_INSUFFICIENT_FORMAT_AND_RUNTIME_EVIDENCE",
        },
        "classification": {
            "outer_format_knowledge": "SUFFICIENT_FOR_READ_ONLY_INVENTORY",
            "inner_format_knowledge": "INSUFFICIENT_FOR_WRITER",
            "runtime_knowledge": "INSUFFICIENT_FOR_TARGET_INTEGRATION",
        },
        "publication_safety": {
            "map_payload_bytes_included": False,
            "raw_proprietary_names_included": False,
            "source_offsets_included": False,
            "installable_artifacts_included": False,
        },
    }
    validate_navigation_knowledge_matrix(matrix)
    return matrix


def _row(
    knowledge_id: str, domain: str, status: str, evidence: str
) -> dict[str, str]:
    return {
        "knowledge_id": knowledge_id,
        "domain": domain,
        "status": status,
        "evidence": evidence,
    }


def validate_navigation_knowledge_matrix(matrix: dict[str, object]) -> None:
    if matrix.get("schema") != NAVIGATION_KNOWLEDGE_SCHEMA:
        raise ValueError("unsupported navigation knowledge matrix")
    rows = matrix.get("rows")
    if not isinstance(rows, list) or len(rows) != 14:
        raise ValueError("navigation knowledge row set differs")
    if len({row["knowledge_id"] for row in rows}) != len(rows):
        raise ValueError("duplicate navigation knowledge row")
    gate = matrix.get("direct_replacement_gate")
    if not isinstance(gate, dict) or (
        gate.get("passed") is not False
        or not str(gate.get("status", "")).startswith("BLOCKED")
    ):
        raise ValueError("direct replacement gate was weakened")
    by_id = {row["knowledge_id"]: row for row in rows}
    for item in (
        "routing-graph-grammar",
        "coordinate-encoding",
        "proprietary-write-model",
        "proprietary-integrity-model",
        "firmware-inner-consumer",
    ):
        if by_id[item]["status"] != "OPEN":
            raise ValueError("unresolved target knowledge was promoted")

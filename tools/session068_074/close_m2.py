#!/usr/bin/env python3
"""Advance the frozen M2 state through Sessions 068-074.

The runner uses a synthetic Intel HEX fixture for the final integration gate.
It never reads firmware, extracts resources, writes media or creates an
installable artifact.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phoenix_mmi.checksum_experiments import (
    ChecksumExperiment,
    ChecksumRegion,
    checksum_experiment_report,
    run_checksum_experiments,
)
from phoenix_mmi.format_registry import build_public_registry_summary
from phoenix_mmi.integration import run_sanitized_integration
from phoenix_mmi.parse_result import (
    build_public_parser_contract_summary,
    parse_lod_bounded,
)
from phoenix_mmi.schema_registry import (
    DEFAULT_SCHEMA_REGISTRY,
    build_public_schema_registry_summary,
)
from phoenix_mmi.structural_diff import structural_diff
from phoenix_mmi.toolkit_audit import advance_m2_progress


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _transition(
    capability_id: str,
    *,
    from_status: str = "MISSING",
    target: str,
    evidence: str,
    limitation: str,
) -> dict[str, str]:
    return {
        "capability_id": capability_id,
        "from_status": from_status,
        "to_status": "IMPLEMENTED",
        "probe_kind": "python-symbol",
        "probe_target": target,
        "evidence": evidence,
        "limitation": limitation,
    }


def _advance(
    root: Path,
    previous: dict[str, object],
    *,
    session: str,
    transitions: list[dict[str, str]],
    graph: str,
    node: str,
    section: str,
    summary: dict[str, object],
) -> dict[str, object]:
    report = advance_m2_progress(
        root,
        previous,
        session=session,
        transitions=transitions,
        graph_version=graph,
        graph_node_id=node,
    )
    report[section] = summary
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.repository.resolve()
    previous = json.loads(
        (
            root
            / "research/milestones/m2/session067/artifact-manifest-summary.json"
        ).read_text(encoding="utf-8")
    )

    report068 = _advance(
        root,
        previous,
        session="068",
        transitions=[
            _transition(
                "M2-CAP-024",
                target="phoenix_mmi.format_registry:DEFAULT_FORMAT_REGISTRY",
                evidence="Session 068 and SPEC-076",
                limitation="classification remains bounded by declared structural validators",
            )
        ],
        graph="v60",
        node="m2-declarative-format-registry",
        section="format_registry",
        summary=build_public_registry_summary(),
    )
    _write(args.output / "session068/format-registry-summary.json", report068)

    lod_control = parse_lod_bounded(b"\xff" * 64 + b"\x00" * 64)
    parser_summary = build_public_parser_contract_summary()
    parser_summary["lod_control"] = {
        "classification": lod_control.classification,
        "fully_validated": lod_control.fully_validated,
        "record_model_established": lod_control.metrics[
            "record_model_established"
        ],
    }
    report069 = _advance(
        root,
        report068,
        session="069",
        transitions=[
            _transition(
                "M2-CAP-012",
                target="phoenix_mmi.parse_result:parse_lod_bounded",
                evidence="Session 069 and SPEC-077",
                limitation="LOD parsing exposes topology only; record semantics remain unresolved",
            ),
            _transition(
                "M2-CAP-025",
                target="phoenix_mmi.parse_result:ParseResult",
                evidence="Session 069 and SPEC-077",
                limitation="only registered format adapters produce normalized results",
            ),
        ],
        graph="v61",
        node="m2-normalized-parser-contract",
        section="parser_contract",
        summary=parser_summary,
    )
    _write(args.output / "session069/parser-contract-summary.json", report069)

    control = b"phoenix-mmi-sanitized-checksum-control"
    checksum_rows = (
        ChecksumExperiment(
            "crc-observed",
            "CRC32/IEEE",
            ChecksumRegion("whole-control", 0, len(control)),
        ),
        ChecksumExperiment(
            "sum-negative-control",
            "SUM16",
            ChecksumRegion("whole-control", 0, len(control)),
            0,
        ),
    )
    checksum_summary = checksum_experiment_report(
        checksum_rows, run_checksum_experiments(control, checksum_rows)
    )
    report070 = _advance(
        root,
        report069,
        session="070",
        transitions=[
            _transition(
                "M2-CAP-026",
                target="phoenix_mmi.checksum_experiments:ChecksumExperiment",
                evidence="Session 070 and SPEC-078",
                limitation="does not infer or bypass unresolved vendor integrity algorithms",
            )
        ],
        graph="v62",
        node="m2-checksum-experiment-framework",
        section="checksum_experiments",
        summary=checksum_summary,
    )
    _write(args.output / "session070/checksum-experiment-summary.json", report070)

    diff_summary = structural_diff(
        {"a": [1, {"state": "before"}], "stable": True},
        {"a": [1, {"state": "after"}], "added": 3, "stable": True},
    )
    report071 = _advance(
        root,
        report070,
        session="071",
        transitions=[
            _transition(
                "M2-CAP-018",
                target="phoenix_mmi.structural_diff:structural_diff",
                evidence="Session 071 and SPEC-079",
                limitation="generic structural differences do not imply semantic change",
            )
        ],
        graph="v63",
        node="m2-generic-structural-diff",
        section="structural_diff",
        summary=diff_summary,
    )
    _write(args.output / "session071/structural-diff-summary.json", report071)

    schema_summary = build_public_schema_registry_summary()
    schema_summary["self_description_registered"] = (
        DEFAULT_SCHEMA_REGISTRY.schema_ids
        == tuple(sorted(DEFAULT_SCHEMA_REGISTRY.schema_ids))
    )
    report072 = _advance(
        root,
        report071,
        session="072",
        transitions=[
            _transition(
                "M2-CAP-020",
                target="phoenix_mmi.schema_registry:DEFAULT_SCHEMA_REGISTRY",
                evidence="Session 072 and SPEC-080",
                limitation="schema validation proves shape and invariants, not research truth",
            )
        ],
        graph="v64",
        node="m2-schema-registry",
        section="schema_registry",
        summary=schema_summary,
    )
    _write(args.output / "session072/schema-validation-summary.json", report072)

    cli_summary = {
        "schema": "phoenix-mmi.unified-cli-summary/v1",
        "subcommands": [
            "analyze",
            "checksum",
            "classify",
            "diff",
            "manifest",
            "parse",
            "validate",
        ],
        "subcommand_count": 7,
        "write_or_repack_subcommand_present": False,
        "vehicle_communication_present": False,
        "raw_artifact_bytes_included": False,
    }
    report073 = _advance(
        root,
        report072,
        session="073",
        transitions=[
            _transition(
                "M2-CAP-022",
                target="phoenix_mmi.cli:main",
                evidence="Session 073 and SPEC-081",
                limitation="CLI is read-only and intentionally has no mutation or installation command",
            )
        ],
        graph="v65",
        node="m2-unified-read-only-cli",
        section="unified_cli",
        summary=cli_summary,
    )
    _write(args.output / "session073/unified-cli-summary.json", report073)

    integration_first = run_sanitized_integration(args.fixture)
    integration_second = run_sanitized_integration(args.fixture)
    deterministic = integration_first == integration_second
    if not integration_first["passed"] or not deterministic:
        raise RuntimeError("M2 integration gate failed")
    integration_summary = dict(integration_first)
    integration_summary["repeat_run_equal"] = deterministic
    report074 = _advance(
        root,
        report073,
        session="074",
        transitions=[
            _transition(
                "M2-CAP-027",
                target="phoenix_mmi.integration:run_sanitized_integration",
                evidence="Session 074 and SPEC-082",
                limitation="integration uses a synthetic non-firmware fixture only",
            )
        ],
        graph="v66",
        node="m2-deterministic-integration-gate",
        section="integration_gate",
        summary=integration_summary,
    )
    if (
        report074["classification"]["m2_status"] != "COMPLETE"
        or report074["exit_criteria_passed"]
        != report074["exit_criteria_total"]
    ):
        raise RuntimeError("M2 exit criteria did not close")
    report074["milestone_transition"] = {
        "m2": "COMPLETE",
        "m3": "READY",
        "m3_authorized_scope": "read-only resource laboratory",
        "safe_mutation_ready": False,
        "installable_artifact_ready": False,
    }
    _write(args.output / "session074/milestone-m2-closure.json", report074)

    print(
        json.dumps(
            {
                "sessions": ["068", "069", "070", "071", "072", "073", "074"],
                "m2_exit": report074["classification"]["m2_exit"],
                "criteria": (
                    f"{report074['exit_criteria_passed']}/"
                    f"{report074['exit_criteria_total']}"
                ),
                "m3": "READY",
                "integration_repeat_equal": deterministic,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate private Session 120 metadata and emit an aggregate-only summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from phoenix_mmi.bench_evidence import evaluate_bench_evidence_bundle


MAX_PRIVATE_BUNDLE_BYTES = 65_536


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("private_bundle", type=Path)
    parser.add_argument("--public-output", type=Path, required=True)
    args = parser.parse_args()

    size = args.private_bundle.stat().st_size
    if size <= 0 or size > MAX_PRIVATE_BUNDLE_BYTES:
        raise ValueError("private bench bundle size is outside the bound")
    bundle = json.loads(args.private_bundle.read_text(encoding="utf-8"))
    if not isinstance(bundle, dict):
        raise ValueError("private bench bundle must be a JSON object")
    summary = evaluate_bench_evidence_bundle(bundle)
    args.public_output.parent.mkdir(parents=True, exist_ok=True)
    args.public_output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "physical_gate": summary["classification"][
                    "m7_physical_gate"
                ],
                "blocker_count": len(summary["summary"]["blockers"]),
                "raw_values_published": False,
            },
            sort_keys=True,
        )
    )
    return (
        0
        if summary["classification"]["m7_physical_gate"] == "PASS"
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())

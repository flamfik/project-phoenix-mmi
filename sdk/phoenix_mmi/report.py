"""JSON and Markdown report generation."""

from __future__ import annotations

import json
from pathlib import Path


def write_json(report: dict[str, object], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def render_markdown(report: dict[str, object]) -> str:
    artifact = report["artifact"]
    entropy = report["entropy"]["summary"]
    fingerprints = report["fingerprints"]
    checksums = report["checksums"]
    lines = [
        f"# Static analysis: {artifact['label']}",
        "",
        "- Mode: `read-only-static`",
        f"- Size: `{artifact['size_bytes']}` bytes",
        f"- SHA-256: `{artifact['sha256']}`",
        f"- Header (64-byte window) SHA-256: `{artifact['header_sha256']}`",
        "",
        "## Fingerprints",
        "",
        f"Observed `{fingerprints['hit_count']}` signature hits. Hits are candidates until structure validates them.",
        "",
    ]
    for name, count in fingerprints["counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(
        [
            "",
            "## Entropy",
            "",
            f"- Windows: `{entropy.get('window_count', 0)}`",
            f"- Mean: `{entropy.get('mean', 'n/a')}`",
            f"- Range: `{entropy.get('minimum', 'n/a')}` to `{entropy.get('maximum', 'n/a')}`",
            "",
            "## Strings",
            "",
            f"- Printable records: `{report['strings']['record_count']}`",
            f"- Technical markers: `{', '.join(report['strings']['technical_markers']) or 'none'}`",
            "- Arbitrary raw strings are intentionally omitted.",
            "",
            "## Candidate segmentation",
            "",
            f"`{report['candidate_segments']['count']}` analytical candidates; status: `HYPOTHESIS`.",
            "",
            "## Checksum correlation",
            "",
            f"- Status: `{checksums['status']}`",
            f"- Algorithm tested: `{checksums['algorithm_tested']}`",
        ]
    )
    if checksums["status"] == "TESTED":
        lines.extend(
            [
                f"- Matched indices: `{checksums['matched_indices']}`",
                f"- Unmatched indices: `{checksums['unmatched_indices']}`",
                "",
                checksums["interpretation"],
            ]
        )
    lines.extend(
        [
            "",
            "## Publication safety",
            "",
            "This report contains hashes, offsets, aggregate measurements and signature metadata only. It contains no firmware payload or exported embedded resource.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown(report: dict[str, object], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown(report), encoding="utf-8")
    return destination


def build_public_summary(report: dict[str, object]) -> dict[str, object]:
    """Reduce a full local report to reviewable, non-payload evidence."""

    validated_resources = []
    for hit in report["fingerprints"]["hits"]:
        details = hit.get("details") or {}
        if hit["category"] != "resource" or details.get("validated") is not True:
            continue
        validated_resources.append(
            {
                "format": hit["name"],
                "offset": hit["offset"],
                "length": details.get("length"),
                "width": details.get("width"),
                "height": details.get("height"),
                "sha256": details.get("sha256"),
            }
        )

    validated_counts = report["fingerprints"]["validated_counts"]
    artifact = dict(report["artifact"])
    return {
        "schema": "phoenix-mmi.public-summary/v1",
        "analysis_mode": report["analysis_mode"],
        "artifact": artifact,
        "header": {
            "length": artifact["header_length"],
            "sha256": artifact["header_sha256"],
            "validated_magic_at_offset_zero": sorted(
                {
                    hit["name"]
                    for hit in report["fingerprints"]["hits"]
                    if hit["offset"] == 0
                    and hit.get("details")
                    and hit["details"].get("validated") is True
                }
            ),
        },
        "fingerprints": {
            "validated_counts": validated_counts,
            "validated_resources": validated_resources,
            "validated_non_resource_count": sum(
                count
                for name, count in validated_counts.items()
                if name
                not in {"JPEG", "GIF87a", "GIF89a", "PNG", "BMP", "TrueType font", "OpenType font"}
            ),
        },
        "entropy": {
            "window_size": report["entropy"]["window_size"],
            "step": report["entropy"]["step"],
            "summary": report["entropy"]["summary"],
            "transitions": report["entropy"]["transitions"],
        },
        "filler_runs": report["filler_runs"],
        "strings": {
            "record_count": report["strings"]["record_count"],
            "encodings": report["strings"]["encodings"],
            "category_hits": report["strings"]["category_hits"],
            "technical_markers": report["strings"]["technical_markers"],
            "technical_marker_hits": report["strings"]["technical_marker_hits"],
            "raw_strings_included": False,
        },
        "checksums": {
            "algorithm_tested": report["checksums"]["algorithm_tested"],
            "expected_count": len(report["checksums"].get("expected", [])),
            "matched_indices": report["checksums"].get("matched_indices", []),
            "unmatched_indices": report["checksums"].get("unmatched_indices", []),
            "sequential_layouts": report["checksums"].get("sequential_layouts", []),
        },
        "publication_safety": report["publication_safety"],
    }

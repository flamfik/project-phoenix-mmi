from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
import zlib

from phoenix_mmi.checksum_experiments import (
    ChecksumExperiment,
    ChecksumRegion,
    run_checksum_experiments,
)
from phoenix_mmi.cli import main
from phoenix_mmi.format_registry import DEFAULT_FORMAT_REGISTRY, FormatRegistry
from phoenix_mmi.integration import run_sanitized_integration
from phoenix_mmi.parse_result import parse_artifact, parse_lod_bounded
from phoenix_mmi.schema_registry import DEFAULT_SCHEMA_REGISTRY
from phoenix_mmi.structural_diff import structural_diff


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sanitized-intel-hex.hex"


class FormatRegistryTests(unittest.TestCase):
    def test_registry_is_deterministic(self) -> None:
        self.assertEqual(
            DEFAULT_FORMAT_REGISTRY.to_dict(),
            DEFAULT_FORMAT_REGISTRY.to_dict(),
        )

    def test_registry_has_unique_rules(self) -> None:
        value = DEFAULT_FORMAT_REGISTRY.to_dict()
        ids = [row["rule_id"] for row in value["rules"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_intel_fixture_is_confirmed(self) -> None:
        hits = DEFAULT_FORMAT_REGISTRY.classify(
            FIXTURE.read_bytes(), path=FIXTURE.name
        )
        self.assertEqual(hits[0].family, "INTEL_HEX_TEXT")
        self.assertEqual(hits[0].status, "CONFIRMED")

    def test_invalid_intel_is_not_confirmed(self) -> None:
        hits = DEFAULT_FORMAT_REGISTRY.classify(
            b":00000001FE\n", path="bad.hex"
        )
        self.assertFalse(any(row.status == "CONFIRMED" for row in hits))

    def test_empty_registry_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FormatRegistry(())


class ParseResultTests(unittest.TestCase):
    def test_intel_result_uses_common_schema(self) -> None:
        result = parse_artifact(FIXTURE.read_bytes(), path=FIXTURE.name)
        value = result.to_dict()
        self.assertEqual(value["schema"], "phoenix-mmi.parse-result/v1")
        self.assertTrue(value["fully_validated"])
        self.assertEqual(value["region_count"], 1)

    def test_region_bytes_are_private_by_default(self) -> None:
        value = parse_artifact(
            FIXTURE.read_bytes(), path=FIXTURE.name
        ).to_dict()
        self.assertNotIn("data_hex", value["regions"][0])
        self.assertFalse(value["region_data_included"])

    def test_lod_remains_opaque(self) -> None:
        result = parse_lod_bounded(b"\xff" * 64 + b"\x00" * 64)
        self.assertFalse(result.fully_validated)
        self.assertEqual(result.classification, "OPAQUE_STRUCTURAL_ONLY")
        self.assertFalse(result.metrics["record_model_established"])

    def test_lod_limit_is_enforced(self) -> None:
        with self.assertRaises(ValueError):
            parse_lod_bounded(b"\x00" * 17, limit=16)

    def test_unknown_format_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_artifact(b"\x01\x02\x03", path="unknown.bin")


class ChecksumExperimentTests(unittest.TestCase):
    def test_match_and_observation(self) -> None:
        data = b"checksum"
        rows = (
            ChecksumExperiment(
                "a",
                "CRC32/IEEE",
                ChecksumRegion("whole", 0, len(data)),
                zlib.crc32(data) & 0xFFFFFFFF,
            ),
            ChecksumExperiment(
                "b", "ADLER32", ChecksumRegion("whole", 0, len(data))
            ),
        )
        results = run_checksum_experiments(data, rows)
        self.assertEqual([row.outcome for row in results], ["MATCH", "OBSERVED"])

    def test_non_match_is_preserved(self) -> None:
        row = ChecksumExperiment(
            "x", "SUM16", ChecksumRegion("whole", 0, 2), 0
        )
        self.assertEqual(
            run_checksum_experiments(b"\x01\x02", (row,))[0].outcome,
            "NO_MATCH",
        )

    def test_out_of_bounds_region_is_rejected(self) -> None:
        row = ChecksumExperiment(
            "x", "SUM16", ChecksumRegion("bad", 1, 2)
        )
        with self.assertRaises(ValueError):
            run_checksum_experiments(b"\x00", (row,))

    def test_duplicate_ids_are_rejected(self) -> None:
        row = ChecksumExperiment("x", "SUM16", ChecksumRegion("a", 0, 0))
        with self.assertRaises(ValueError):
            run_checksum_experiments(b"", (row, row))


class StructuralDiffTests(unittest.TestCase):
    def test_equal_values(self) -> None:
        self.assertTrue(structural_diff({"a": [1]}, {"a": [1]})["equal"])

    def test_change_paths_are_deterministic(self) -> None:
        value = structural_diff({"b": 1, "a": 2}, {"b": 3, "c": 4})
        self.assertEqual(
            [row["path"] for row in value["differences"]],
            ["/a", "/b", "/c"],
        )

    def test_values_are_redacted(self) -> None:
        value = structural_diff({"secret": "left"}, {"secret": "right"})
        row = value["differences"][0]
        self.assertNotIn("left_value", row)
        self.assertNotIn("right_value", row)
        self.assertEqual(len(row["left_digest"]), 16)

    def test_type_change_is_detected(self) -> None:
        value = structural_diff({"x": 1}, {"x": "1"})
        self.assertEqual(value["differences"][0]["kind"], "TYPE_CHANGED")


class SchemaRegistryTests(unittest.TestCase):
    def test_parse_result_validates(self) -> None:
        value = parse_artifact(
            FIXTURE.read_bytes(), path=FIXTURE.name
        ).to_dict()
        self.assertTrue(DEFAULT_SCHEMA_REGISTRY.validate(value).valid)

    def test_unknown_schema_is_rejected(self) -> None:
        result = DEFAULT_SCHEMA_REGISTRY.validate({"schema": "unknown/v1"})
        self.assertFalse(result.valid)

    def test_missing_schema_is_rejected(self) -> None:
        self.assertFalse(DEFAULT_SCHEMA_REGISTRY.validate({}).valid)

    def test_registry_is_sorted(self) -> None:
        self.assertEqual(
            DEFAULT_SCHEMA_REGISTRY.schema_ids,
            tuple(sorted(DEFAULT_SCHEMA_REGISTRY.schema_ids)),
        )


class IntegrationAndCliTests(unittest.TestCase):
    def test_integration_passes_and_repeats(self) -> None:
        first = run_sanitized_integration(FIXTURE)
        second = run_sanitized_integration(FIXTURE)
        self.assertTrue(first["passed"])
        self.assertEqual(first, second)

    def test_cli_classify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "classify.json"
            self.assertEqual(main(["classify", str(FIXTURE), "-o", str(output)]), 0)
            value = json.loads(output.read_text("utf-8"))
            self.assertEqual(value["evidence"][0]["status"], "CONFIRMED")

    def test_cli_parse_and_validate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parsed = Path(temporary) / "parse.json"
            validation = Path(temporary) / "validation.json"
            self.assertEqual(main(["parse", str(FIXTURE), "-o", str(parsed)]), 0)
            self.assertEqual(main(["validate", str(parsed), "-o", str(validation)]), 0)
            value = json.loads(validation.read_text("utf-8"))
            self.assertTrue(value["result"]["valid"])

    def test_cli_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left.json"
            right = root / "right.json"
            output = root / "diff.json"
            left.write_text('{"a":1}', encoding="utf-8")
            right.write_text('{"a":2}', encoding="utf-8")
            self.assertEqual(
                main(["diff", str(left), str(right), "-o", str(output)]), 0
            )
            self.assertEqual(
                json.loads(output.read_text("utf-8"))["difference_count"], 1
            )

    def test_cli_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "manifest.json"
            self.assertEqual(
                main(["manifest", str(FIXTURE), "-o", str(output)]), 0
            )
            value = json.loads(output.read_text("utf-8"))
            self.assertEqual(value["artifact_count"], 1)


if __name__ == "__main__":
    unittest.main()

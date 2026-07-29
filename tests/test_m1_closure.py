import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.iso9660 import ISO9660Image
from phoenix_mmi.m1_closure import (
    _iso9660_level1_name,
    audit_m1_evidence,
    audit_m1_media,
    audit_update_model,
    build_m1_closure,
    classify_m1_members,
    parse_metainfo_text,
)

from test_iso9660 import make_iso


def _register(images):
    return {
        image.path.name: {
            "artifact": image.path.name,
            "size_bytes": str(image.path.stat().st_size),
            "sha256": image.sha256(),
        }
        for image in images.values()
    }


def _baseline(images):
    rows = {}
    for disc, image in images.items():
        entries = image.entries()
        files = [entry for entry in entries if not entry.is_directory]
        directories = [entry for entry in entries if entry.is_directory]
        rows[disc] = {
            "artifact": image.path.name,
            "volume_identifier": image.volume_identifier,
            "iso_size": image.path.stat().st_size,
            "file_count": len(files),
            "directory_count": len(directories),
            "payload_bytes": sum(entry.size for entry in files),
        }
    return rows


class FakeImage:
    def __init__(self, path, entries, payloads):
        self.path = path
        self.volume_identifier = "TEST"
        self._entries = entries
        self._payloads = payloads

    def entries(self):
        return list(self._entries)

    def read_entry(self, entry, offset, length):
        return self._payloads[entry.path][offset : offset + length]


def _metainfo(
    *,
    filename="A.BIN",
    target_version=None,
    target_crc=None,
    source_version=None,
    source_crc=None,
):
    fields = [
        '[common]',
        'MetafileChecksum = "fixture"',
        'PerformEepromUpdate = "true"',
        '[Device]',
        'Name = "fixture"',
        r'[Device\App\01\default\Application]',
        f'FileName = "{filename}"',
        'FileSize = "3"',
        'CheckSum = "fixture"',
    ]
    if target_version:
        fields.extend(
            [
                f'EEPROMPatchTargetVersion = "{target_version}"',
                f'EEPROMPatchTargetCrc = "{target_crc}"',
            ]
        )
    if source_version:
        fields.extend(
            [
                f'EEPROMPatchSourceVersion = "{source_version}"',
                f'EEPROMPatchSourceCrc = "{source_crc}"',
            ]
        )
    return ("\n".join(fields) + "\n").encode("latin1")


class M1ClosureTests(unittest.TestCase):
    def test_primary_iso_level1_alias_is_deterministic(self):
        self.assertEqual(
            _iso9660_level1_name("H2_HI_EU_R1006_SH3_AudiHi_5570.bin"),
            "H2_HI_EU.BIN",
        )
        self.assertEqual(
            _iso9660_level1_name("FLASH_FormatB_FLall.lod"),
            "FLASH_FO.LOD",
        )

    def test_registered_media_inventory_reproduction(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            images = {}
            for disc in ("cd1", "cd2", "cd3"):
                path = root / f"{disc}.iso"
                make_iso(path)
                images[disc] = ISO9660Image(path)
            report = audit_m1_media(
                images,
                _register(images),
                baseline=_baseline(images),
            )
            self.assertEqual(
                report["classification"]["media_readiness_for_m1"],
                "PASS",
            )
            self.assertEqual(report["totals"]["file_count"], 3)

    def test_every_fixture_member_is_classified_and_routed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            images = {}
            for disc in ("cd1", "cd2", "cd3"):
                path = root / f"{disc}.iso"
                make_iso(path)
                images[disc] = ISO9660Image(path)
            report = classify_m1_members(images)
            self.assertEqual(report["artifact_count"], 3)
            self.assertEqual(
                report["classification"]["m1_artifact_understanding"],
                "PASS",
            )

    def test_metainfo_parser_separates_record_roles(self):
        text = "\n".join(
            [
                "[common]",
                'Release = "fixture"',
                "[Device]",
                'Name = "fixture"',
                r"[Device\App\01\default\Application]",
                'FileName = "A.BIN"',
                r"[Device\App\01\alias\Application]",
                r'Link = "Device\App\01\default\Application"',
                r"[Device\App\01\default\Options]",
                'Mode = "fixture"',
            ]
        )
        parsed = parse_metainfo_text(text)
        self.assertEqual(parsed["section_count"], 5)
        self.assertEqual(len(parsed["devices"]), 1)
        self.assertEqual(len(parsed["payloads"]), 1)
        self.assertEqual(len(parsed["links"]), 1)
        self.assertEqual(len(parsed["options"]), 1)

    def test_update_model_reproduces_staged_eeprom_chain(self):
        from phoenix_mmi.iso9660 import ISOEntry

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            images = {}
            baseline = {}
            for disc in ("cd1", "cd2", "cd3"):
                path = root / f"{disc}.iso"
                path.write_bytes(b"fixture")
                kwargs = {}
                if disc == "cd1":
                    kwargs = {
                        "target_version": "next",
                        "target_crc": "abcd",
                    }
                elif disc == "cd3":
                    kwargs = {
                        "source_version": "next",
                        "source_crc": "ABCD",
                    }
                descriptor = _metainfo(**kwargs)
                entries = [
                    ISOEntry("METAINFO.TXT", 0, len(descriptor), False),
                    ISOEntry("A.BIN", 1, 3, False),
                ]
                images[disc] = FakeImage(
                    path,
                    entries,
                    {
                        "METAINFO.TXT": descriptor,
                        "A.BIN": b"abc",
                    },
                )
                parsed = parse_metainfo_text(descriptor.decode("latin1"))
                baseline[disc] = {
                    "section_count": parsed["section_count"],
                    "device_family_count": len(parsed["devices"]),
                    "payload_record_count": len(parsed["payloads"]),
                    "link_count": len(parsed["links"]),
                    "option_count": len(parsed["options"]),
                }
            report = audit_update_model(images, baseline=baseline)
            self.assertTrue(
                report[
                    "cd1_target_to_cd3_source_eeprom_chain_reproduced"
                ]
            )
            self.assertEqual(
                report["classification"]["m1_update_model_understanding"],
                "PASS",
            )

    def test_update_model_resolves_declared_payload_on_later_disc(self):
        from phoenix_mmi.iso9660 import ISOEntry

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            images = {}
            baseline = {}
            for disc in ("cd1", "cd2", "cd3"):
                path = root / f"{disc}.iso"
                path.write_bytes(b"fixture")
                if disc == "cd2":
                    filename = "A.BIN"
                    member_name = "A.BIN"
                else:
                    filename = "MISSING_LONG_FILENAME.BIN"
                    member_name = "MISSING_.BIN"
                kwargs = {"filename": filename}
                if disc == "cd1":
                    kwargs.update(
                        target_version="next",
                        target_crc="abcd",
                    )
                elif disc == "cd3":
                    kwargs.update(
                        source_version="next",
                        source_crc="ABCD",
                    )
                descriptor = _metainfo(**kwargs)
                entries = [
                    ISOEntry("METAINFO.TXT", 0, len(descriptor), False)
                ]
                payloads = {"METAINFO.TXT": descriptor}
                if disc != "cd1":
                    entries.append(
                        ISOEntry(member_name, 1, 3, False)
                    )
                    payloads[member_name] = b"abc"
                images[disc] = FakeImage(path, entries, payloads)
                parsed = parse_metainfo_text(descriptor.decode("latin1"))
                baseline[disc] = {
                    "section_count": parsed["section_count"],
                    "device_family_count": len(parsed["devices"]),
                    "payload_record_count": len(parsed["payloads"]),
                    "link_count": len(parsed["links"]),
                    "option_count": len(parsed["options"]),
                }
            report = audit_update_model(images, baseline=baseline)
            cd1 = report["descriptors"][0]
            self.assertEqual(
                cd1["payload_other_registered_media_resolution_count"],
                1,
            )
            self.assertTrue(
                cd1["all_payloads_resolve_in_registered_set"]
            )

    def test_evidence_audit_has_stable_self_exclusion(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            required = [
                "README.md",
                "sdk/README.md",
                "docs/000-project-charter.md",
                "docs/research-questions/README.md",
                "docs/safety/lab-safety.md",
                "docs/milestones/M1-firmware-archaeology.md",
            ]
            for value in required:
                path = root / value
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
            (root / "docs/001-roadmap.md").write_text(
                "Session 043: not executed\n",
                encoding="utf-8",
            )
            (root / "docs/sessions").mkdir(parents=True)
            (root / "docs/sessions/SESSION-000-fixture.md").write_text(
                "fixture\n", encoding="utf-8"
            )
            (root / "docs/specs").mkdir(parents=True)
            (root / "docs/specs/SPEC-001-fixture.md").write_text(
                "fixture\n", encoding="utf-8"
            )
            (root / "docs/research-questions/README.md").write_text(
                "| RQ-001 | fixture | CLOSED | evidence |\n",
                encoding="utf-8",
            )
            report_path = root / "research/prior/report.json"
            report_path.parent.mkdir(parents=True)
            report_path.write_text("{}\n", encoding="utf-8")
            self_path = (
                root
                / "research/milestones/m1/session064/self.json"
            )
            self_path.parent.mkdir(parents=True)
            self_path.write_text("{broken", encoding="utf-8")
            report = audit_m1_evidence(
                root,
                expected_session_ids={0},
                expected_spec_ids={1},
                expected_rq_ids={1},
            )
            self.assertEqual(report["public_json_report_count"], 1)
            self.assertEqual(report["invalid_public_json_count"], 0)
            self.assertEqual(
                report["classification"]["evidence_traceability"],
                "PASS",
            )

    def test_closure_preserves_open_work_and_mutation_block(self):
        graph = {
            "schema": "phoenix-mmi.operational-graph/v52",
            "nodes": [{"id": "firmware-evidence-map-v2", "status": "OPEN"}],
            "edges": [],
        }
        session060 = {
            "schema": "phoenix-mmi.firmware-evidence-map/v2",
            "classification": {"safe_mutation_ready": False},
            "operational_graph": graph,
        }
        reports = [
            {
                "session": "061",
                "classification": {"media_readiness_for_m1": "PASS"},
            },
            {
                "session": "062",
                "classification": {
                    "m1_artifact_understanding": "PASS"
                },
            },
            {
                "session": "063",
                "classification": {
                    "m1_update_model_understanding": "PASS"
                },
            },
            {
                "session": "064",
                "classification": {
                    "m1_reproducibility_documentation": "PASS"
                },
            },
        ]
        report = build_m1_closure(session060, reports)
        self.assertEqual(
            report["classification"]["milestone_m1"], "COMPLETE"
        )
        self.assertFalse(
            report["scope_correction"][
                "deep_semantic_questions_resolved_by_closure"
            ]
        )
        self.assertFalse(report["classification"]["safe_mutation_ready"])
        self.assertEqual(report["operational_graph_version"], "v57")


if __name__ == "__main__":
    unittest.main()

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.resource_bundle import (
    PointerRun,
    analyze_resource_bundle,
    build_public_resource_bundle,
    compare_pointer_runs,
    find_embedded_html,
    find_pointer_runs,
    test_relative_offset_tables as scan_relative_offset_tables,
)


class ResourceBundleTests(unittest.TestCase):
    def test_html_summary_excludes_raw_content_and_uris(self):
        data = (
            b'<html><body><img src="http://TCULocal_a.gif">'
            b'<img src="http://TCULocal_b.jpeg">'
            b'<a href="http://192.168.1.11/start">x</a></body></html>\r\n\x00'
        )
        documents = find_embedded_html(data)
        self.assertEqual(len(documents), 1)
        document = documents[0]
        self.assertEqual(document.image_reference_count, 2)
        self.assertEqual(document.image_extension_counts, {"gif": 1, "jpg": 1})
        self.assertEqual(document.private_ipv4_reference_count, 1)
        self.assertEqual(document.end, len(data) - 1)
        self.assertNotIn("TCULocal", str(document.to_dict()))

    def test_pointer_runs_and_delta_comparison(self):
        left_values = (0x0C001000, 0x0C001004, 0x0C001008)
        right_values = tuple(value + 0x200 for value in left_values)
        left_bytes = b"".join(value.to_bytes(4, "big") for value in left_values) + b"\x00" * 8
        runs = find_pointer_runs(left_bytes)
        self.assertEqual([(run.offset, run.count) for run in runs], [(0, 3)])
        comparison = compare_pointer_runs(
            runs,
            [PointerRun(offset=4, end=16, count=3, values=right_values)],
        )
        pair = comparison["pairs"][0]
        self.assertEqual(pair["offset_delta"], 4)
        self.assertEqual(pair["value_delta_mode"], 0x200)
        self.assertTrue(pair["all_values_same_delta"])

    def test_strided_relative_table_and_bundle_analysis(self):
        table = b"\x00\x10aa\x00\x20bb\x00\x30cc"
        result = scan_relative_offset_tables(
            {"metadata": table}, {"resource-starts": [0x10, 0x20, 0x30]}
        )
        self.assertEqual(result["full_candidate_count"], 1)
        self.assertEqual(result["full_candidates"][0]["stride"], 4)

        with TemporaryDirectory() as temporary:
            main = b'<html><body><img src="http://TCULocal_a.gif"></body></html>\r\n'
            prefix = main + b"\x00"
            cluster = b"GIF89a" + b"A" * 10 + b"GIF89a" + b"B" * 6
            pointers = b"".join(
                value.to_bytes(4, "big")
                for value in (0x0C001000, 0x0C001004, 0x0C001008)
            )
            suffix = pointers + b'<HTML><BODY>fallback</BODY></HTML>\r\n'
            payload = prefix + cluster + suffix
            path = Path(temporary) / "bundle.bin"
            path.write_bytes(payload)
            report = analyze_resource_bundle(
                BinaryReader(path),
                island={"offset": 0, "end": len(payload)},
                cluster={"offset": len(prefix), "end": len(prefix) + len(cluster)},
                resources=[
                    {"offset": len(prefix), "length": 16, "format": "GIF89a"},
                    {"offset": len(prefix) + 16, "length": 12, "format": "GIF89a"},
                ],
            )
            self.assertEqual(report["html"]["document_count"], 2)
            self.assertEqual(report["html"]["main_document_trailing_separator_length"], 1)
            self.assertEqual(report["post_cluster"]["pointer_runs"][0]["count"], 3)
            public = build_public_resource_bundle(report)
            self.assertNotIn("_internal_pointer_runs", public)
            self.assertFalse(public["publication_safety"]["raw_html_included"])
            serialized = json.dumps(public).casefold()
            self.assertNotIn("tculocal", serialized)
            self.assertNotIn("http://", serialized)


if __name__ == "__main__":
    unittest.main()

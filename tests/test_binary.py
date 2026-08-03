from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader


class BinaryReaderTests(unittest.TestCase):
    def test_bounded_reads_hash_and_cross_chunk_search(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.bin"
            path.write_bytes(b"01234567MAGIC89MAGIC")
            reader = BinaryReader(path)

            self.assertEqual(reader.size, 20)
            self.assertEqual(reader.read(2, 4), b"2345")
            self.assertEqual(reader.read(18, 99), b"IC")
            self.assertEqual(reader.find_all(b"MAGIC", chunk_size=10), [8, 15])
            self.assertEqual(
                reader.sha256(),
                "6f42240423d42a5cb35d765d5567f0e05795996f69d8e701cc5ed2187cb28ce7",
            )

    def test_invalid_bounds_are_rejected(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.bin"
            path.write_bytes(b"abc")
            reader = BinaryReader(path)
            with self.assertRaises(ValueError):
                reader.read(-1, 1)
            with self.assertRaises(ValueError):
                reader.read(4, 1)


if __name__ == "__main__":
    unittest.main()

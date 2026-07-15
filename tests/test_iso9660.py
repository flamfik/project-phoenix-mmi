from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.iso9660 import ISO9660Image, SECTOR_SIZE


def both_u16(value: int) -> bytes:
    return value.to_bytes(2, "little") + value.to_bytes(2, "big")


def both_u32(value: int) -> bytes:
    return value.to_bytes(4, "little") + value.to_bytes(4, "big")


def directory_record(name: bytes, extent: int, size: int, directory: bool) -> bytes:
    length = 33 + len(name) + (0 if len(name) % 2 else 1)
    record = bytearray(length)
    record[0] = length
    record[2:10] = both_u32(extent)
    record[10:18] = both_u32(size)
    record[25] = 2 if directory else 0
    record[28:32] = both_u16(1)
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def make_iso(path: Path) -> bytes:
    image = bytearray(24 * SECTOR_SIZE)
    pvd = memoryview(image)[16 * SECTOR_SIZE : 17 * SECTOR_SIZE]
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[40:72] = b"TEST_DISC".ljust(32, b" ")
    pvd[80:88] = both_u32(24)
    pvd[120:124] = both_u16(1)
    pvd[124:128] = both_u16(1)
    pvd[128:132] = both_u16(SECTOR_SIZE)
    pvd[156 : 156 + 34] = directory_record(b"\x00", 20, SECTOR_SIZE, True)

    root = memoryview(image)[20 * SECTOR_SIZE : 21 * SECTOR_SIZE]
    records = (
        directory_record(b"\x00", 20, SECTOR_SIZE, True)
        + directory_record(b"\x01", 20, SECTOR_SIZE, True)
        + directory_record(b"MMI.BIN;1", 21, 12, False)
    )
    root[: len(records)] = records
    payload = b"hello world!"
    image[21 * SECTOR_SIZE : 21 * SECTOR_SIZE + len(payload)] = payload
    path.write_bytes(image)
    return payload


class ISO9660Tests(unittest.TestCase):
    def test_targeted_member_lookup_and_extraction(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            iso_path = root / "disc.iso"
            payload = make_iso(iso_path)
            image = ISO9660Image(iso_path)

            self.assertEqual(image.volume_identifier, "TEST_DISC")
            entry = image.find_filename("mmi.bin")
            self.assertEqual(entry.path, "MMI.BIN")
            self.assertEqual(image.find_path("./MMI.BIN"), entry)
            destination = image.extract(entry, root / "out" / "MMI.BIN")
            self.assertEqual(destination.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phoenix_mmi.binary import BinaryReader
from phoenix_mmi.superh import (
    decode_instruction,
    find_pc_relative_referrers,
    trace_control_flow,
)


class SuperHTests(unittest.TestCase):
    def test_big_endian_startup_branch_and_pc_relative_literals(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "startup.bin"
            data = bytearray(0x60)
            data[0:2] = bytes.fromhex("a002")  # bra 0x8
            data[2:4] = bytes.fromhex("0009")  # delay-slot nop
            data[8:10] = bytes.fromhex("d010")  # literal at 0x4c
            data[10:12] = bytes.fromhex("400e")
            data[12:14] = bytes.fromhex("c778")
            data[14:16] = bytes.fromhex("4017")
            data[16:18] = bytes.fromhex("9002")
            data[18:20] = bytes.fromhex("000b")
            data[20:22] = bytes.fromhex("0009")
            data[0x18:0x1A] = (0xFF80).to_bytes(2, "big")
            data[0x4C:0x50] = (0x400000F0).to_bytes(4, "big")
            path.write_bytes(data)
            reader = BinaryReader(path)

            branch = decode_instruction(reader, 0)
            self.assertEqual((branch.mnemonic, branch.target), ("bra", 8))
            literal = decode_instruction(reader, 8)
            self.assertEqual(literal.literal_address, 0x4C)
            self.assertEqual(literal.literal_value, 0x400000F0)
            self.assertEqual(decode_instruction(reader, 12).target, 0x1F0)
            self.assertEqual(decode_instruction(reader, 16).literal_value, -128)

            trace = trace_control_flow(reader, end=0x60)
            offsets = {item.offset for item in trace}
            self.assertIn(0x0, offsets)
            self.assertIn(0x2, offsets)
            self.assertIn(0x8, offsets)
            self.assertNotIn(0x4, offsets)

    def test_literal_referrer_requires_exact_pc_computation(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "literal.bin"
            data = bytearray(0x80)
            data[0x20:0x22] = bytes.fromhex("d107")  # (0x20 & ~3) + 4 + 7*4 = 0x40
            data[0x40:0x44] = (0x00123456).to_bytes(4, "big")
            path.write_bytes(data)
            reader = BinaryReader(path)
            hits = find_pc_relative_referrers(reader, 0x40)
            self.assertEqual([hit.offset for hit in hits], [0x20])


if __name__ == "__main__":
    unittest.main()

"""Magic-byte and embedded-format fingerprinting."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import bz2
import hashlib
import zlib

from .binary import BinaryReader


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    magic: bytes
    confidence: str = "candidate"


@dataclass(frozen=True)
class FingerprintHit:
    name: str
    category: str
    offset: int
    magic_hex: str
    confidence: str
    details: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


SIGNATURES: tuple[Signature, ...] = (
    Signature("ELF", "executable", b"\x7fELF", "strong"),
    Signature("U-Boot legacy uImage", "container", b"\x27\x05\x19\x56", "strong"),
    Signature("ISO 9660 descriptor", "filesystem", b"CD001", "contextual"),
    Signature("ROMFS", "filesystem", b"-rom1fs-", "strong"),
    Signature("SquashFS little-endian", "filesystem", b"hsqs", "strong"),
    Signature("SquashFS big-endian", "filesystem", b"sqsh", "strong"),
    Signature("CRAMFS little-endian", "filesystem", b"\x45\x3d\xcd\x28", "strong"),
    Signature("CRAMFS big-endian", "filesystem", b"\x28\xcd\x3d\x45", "strong"),
    Signature("UBIFS", "filesystem", b"\x31\x18\x10\x06", "strong"),
    Signature("JFFS2 little-endian node", "filesystem-candidate", b"\x85\x19", "weak"),
    Signature("JFFS2 big-endian node", "filesystem-candidate", b"\x19\x85", "weak"),
    Signature("gzip", "compression", b"\x1f\x8b\x08", "strong"),
    Signature("xz", "compression", b"\xfd7zXZ\x00", "strong"),
    Signature("bzip2", "compression", b"BZh", "strong"),
    Signature("zlib/deflate 78 01", "compression-candidate", b"\x78\x01", "weak"),
    Signature("zlib/deflate 78 5e", "compression-candidate", b"\x78\x5e", "weak"),
    Signature("zlib/deflate 78 9c", "compression-candidate", b"\x78\x9c", "weak"),
    Signature("zlib/deflate 78 da", "compression-candidate", b"\x78\xda", "weak"),
    Signature("ZIP local header", "archive", b"PK\x03\x04", "strong"),
    Signature("CPIO new ASCII", "archive", b"070701", "strong"),
    Signature("CPIO CRC ASCII", "archive", b"070702", "strong"),
    Signature("CPIO old ASCII", "archive", b"070707", "strong"),
    Signature("PNG", "resource", b"\x89PNG\r\n\x1a\n", "strong"),
    Signature("GIF87a", "resource", b"GIF87a", "strong"),
    Signature("GIF89a", "resource", b"GIF89a", "strong"),
    Signature("JPEG", "resource", b"\xff\xd8\xff", "contextual"),
    Signature("BMP", "resource-candidate", b"BM", "weak"),
    Signature("TrueType font", "font", b"\x00\x01\x00\x00", "contextual"),
    Signature("OpenType font", "font", b"OTTO", "strong"),
)


ELF_MACHINES = {
    3: "Intel 80386",
    20: "PowerPC",
    40: "ARM",
    42: "Renesas SuperH",
    62: "AMD x86-64",
}


def _elf_details(reader: BinaryReader, offset: int) -> dict[str, object]:
    header = reader.read(offset, 20)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return {}
    elf_class = {1: "ELF32", 2: "ELF64"}.get(header[4], f"unknown:{header[4]}")
    byte_order = {1: "little", 2: "big"}.get(header[5])
    details: dict[str, object] = {
        "class": elf_class,
        "byte_order": byte_order or "unknown",
        "validated": header[4] in (1, 2) and byte_order is not None,
    }
    if byte_order:
        machine = int.from_bytes(header[18:20], byte_order)
        details["machine"] = machine
        details["machine_name"] = ELF_MACHINES.get(machine, "unknown")
    return details


def _font_details(reader: BinaryReader, offset: int) -> dict[str, object]:
    header = reader.read(offset, 12)
    if len(header) < 12:
        return {"validated": False, "reason": "truncated font header"}
    table_count = int.from_bytes(header[4:6], "big")
    if not 1 <= table_count <= 256:
        return {"validated": False, "table_count": table_count}
    directory = reader.read(offset + 12, table_count * 16)
    if len(directory) != table_count * 16:
        return {"validated": False, "reason": "truncated table directory"}
    for index in range(table_count):
        record = directory[index * 16 : (index + 1) * 16]
        tag = record[:4]
        table_offset = int.from_bytes(record[8:12], "big")
        table_length = int.from_bytes(record[12:16], "big")
        if not all(0x20 <= byte <= 0x7E for byte in tag):
            return {"validated": False, "reason": "non-printable table tag"}
        if table_offset + table_length > reader.size - offset:
            return {"validated": False, "reason": "table outside artifact"}
    return {"validated": True, "table_count": table_count}


def _jpeg_details(reader: BinaryReader, offset: int) -> dict[str, object]:
    data = reader.read(offset, min(1024 * 1024, reader.size - offset))
    cursor = 2
    dimensions: tuple[int, int, int] | None = None
    while cursor + 4 <= len(data):
        if data[cursor] != 0xFF:
            return {"validated": False, "reason": "invalid JPEG marker prefix"}
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            break
        marker = data[cursor]
        cursor += 1
        if marker == 0xD9:
            break
        if marker in {0x01, *range(0xD0, 0xD9)}:
            continue
        if cursor + 2 > len(data):
            break
        length = int.from_bytes(data[cursor : cursor + 2], "big")
        if length < 2 or cursor + length > len(data):
            return {"validated": False, "reason": "invalid JPEG segment length"}
        if marker in range(0xC0, 0xC4) and length >= 7:
            height = int.from_bytes(data[cursor + 3 : cursor + 5], "big")
            width = int.from_bytes(data[cursor + 5 : cursor + 7], "big")
            dimensions = (width, height, marker)
        if marker == 0xDA and dimensions is not None:
            end_of_image = data.find(b"\xff\xd9", cursor + length)
            width, height, sof_marker = dimensions
            return {
                "validated": bool(width and height and end_of_image >= 0),
                "width": width,
                "height": height,
                "sof_marker": f"0x{sof_marker:02x}",
                "eoi_offset": offset + end_of_image if end_of_image >= 0 else None,
                "length": end_of_image + 2 if end_of_image >= 0 else None,
                "sha256": (
                    hashlib.sha256(data[: end_of_image + 2]).hexdigest()
                    if end_of_image >= 0
                    else None
                ),
            }
        cursor += length
    return {"validated": False, "reason": "no bounded SOF marker"}


def _format_details(reader: BinaryReader, hit_name: str, offset: int) -> dict[str, object] | None:
    if hit_name == "ELF":
        return _elf_details(reader, offset)
    if hit_name == "PNG":
        header = reader.read(offset, 24)
        valid = len(header) == 24 and header[8:16] == b"\x00\x00\x00\rIHDR"
        return {
            "validated": valid,
            "width": int.from_bytes(header[16:20], "big") if valid else None,
            "height": int.from_bytes(header[20:24], "big") if valid else None,
        }
    if hit_name in {"GIF87a", "GIF89a"}:
        data = reader.read(offset, min(1024 * 1024, reader.size - offset))
        header = data[:10]
        width = int.from_bytes(header[6:8], "little") if len(header) == 10 else 0
        height = int.from_bytes(header[8:10], "little") if len(header) == 10 else 0
        cursor = 13
        if len(data) >= 13 and data[10] & 0x80:
            cursor += 3 * (2 ** ((data[10] & 0x07) + 1))
        valid = bool(width and height)
        trailer = -1
        while valid and cursor < len(data):
            introducer = data[cursor]
            if introducer == 0x3B:
                trailer = cursor
                break
            if introducer == 0x2C:
                if cursor + 10 > len(data):
                    valid = False
                    break
                packed = data[cursor + 9]
                cursor += 10
                if packed & 0x80:
                    cursor += 3 * (2 ** ((packed & 0x07) + 1))
                if cursor >= len(data):
                    valid = False
                    break
                cursor += 1
            elif introducer == 0x21:
                if cursor + 2 > len(data):
                    valid = False
                    break
                cursor += 2
            else:
                valid = False
                break
            while cursor < len(data):
                block_length = data[cursor]
                cursor += 1
                if block_length == 0:
                    break
                cursor += block_length
                if cursor > len(data):
                    valid = False
                    break
        return {
            "validated": valid and trailer >= 0,
            "width": width,
            "height": height,
            "trailer_offset": offset + trailer if trailer >= 0 else None,
            "length": trailer + 1 if trailer >= 0 else None,
            "sha256": (
                hashlib.sha256(data[: trailer + 1]).hexdigest() if trailer >= 0 else None
            ),
        }
    if hit_name == "JPEG":
        return _jpeg_details(reader, offset)
    if hit_name == "BMP":
        header = reader.read(offset, 54)
        if len(header) < 26:
            return {"validated": False, "reason": "truncated BMP header"}
        file_size = int.from_bytes(header[2:6], "little")
        pixel_offset = int.from_bytes(header[10:14], "little")
        dib_size = int.from_bytes(header[14:18], "little")
        valid = (
            dib_size in {12, 16, 40, 52, 56, 64, 108, 124}
            and 14 + dib_size <= pixel_offset <= file_size
            and file_size <= reader.size - offset
        )
        return {
            "validated": valid,
            "file_size": file_size,
            "pixel_offset": pixel_offset,
            "dib_size": dib_size,
        }
    if hit_name in {"TrueType font", "OpenType font"}:
        return _font_details(reader, offset)
    if hit_name == "ISO 9660 descriptor":
        descriptor = reader.read(offset - 1, 2048) if offset else b""
        valid = len(descriptor) == 2048 and descriptor[0] in {0, 1, 2, 3, 255} and descriptor[6] == 1
        if valid and descriptor[0] == 1:
            little = int.from_bytes(descriptor[128:130], "little")
            big = int.from_bytes(descriptor[130:132], "big")
            valid = little == big == 2048
        return {"validated": valid, "descriptor_type": descriptor[0] if descriptor else None}
    if hit_name == "bzip2":
        header = reader.read(offset, 4)
        valid_header = len(header) == 4 and header[3:4] in b"123456789"
        if not valid_header:
            return {"validated": False, "reason": "invalid block-size marker"}
        try:
            decompressor = bz2.BZ2Decompressor()
            output = decompressor.decompress(
                reader.read(offset, min(256 * 1024, reader.size - offset)),
                max_length=1024 * 1024,
            )
            return {
                "validated": bool(output) and decompressor.eof,
                "block_size_marker": header[3:4].decode(),
            }
        except OSError:
            return {"validated": False, "reason": "decompressor rejected stream"}
    if hit_name.startswith("zlib/deflate"):
        try:
            decompressor = zlib.decompressobj()
            output = decompressor.decompress(
                reader.read(offset, min(256 * 1024, reader.size - offset)),
                1024 * 1024,
            )
            return {"validated": bool(output) and decompressor.eof}
        except zlib.error:
            return {"validated": False, "reason": "decompressor rejected stream"}
    return None


def scan_fingerprints(
    reader: BinaryReader,
    *,
    max_hits_per_signature: int = 256,
) -> list[FingerprintHit]:
    """Return signature hits; a hit is evidence of bytes, not proof of a format."""

    hits: list[FingerprintHit] = []
    for signature in SIGNATURES:
        for offset in reader.find_all(signature.magic, max_hits=max_hits_per_signature):
            details = _format_details(reader, signature.name, offset)
            hits.append(
                FingerprintHit(
                    name=signature.name,
                    category=signature.category,
                    offset=offset,
                    magic_hex=signature.magic.hex(),
                    confidence=signature.confidence,
                    details=details or None,
                )
            )
    return sorted(hits, key=lambda hit: (hit.offset, hit.name))

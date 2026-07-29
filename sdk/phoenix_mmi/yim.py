"""Validated read-only XIM2/YIM parsing and RLE decoding.

The decoder exposes structure and aggregate metrics only. Decoded raster
bytes remain private to callers and are never added to public reports.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass
import zlib


_ASCII_PREAMBLE_SIZE = 24
_XIM2_MAGIC_OFFSET = 24
_XIM2_HEADER_SIZE = 28
_RLE_PAYLOAD_OFFSET = 60
_BYTES_PER_UNIT = 2
_MAX_RASTER_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class YimEnvelope:
    integrity32: int
    integrity16: int
    declared_file_size: int
    version: int
    outer_span: int
    width: int
    height: int
    image_header_size: int
    payload_block_span: int
    codec_word: int
    encoded_payload: bytes


@dataclass(frozen=True)
class YimDecodeResult:
    envelope: YimEnvelope
    raster: bytes
    literal_command_count: int
    repeat_command_count: int
    encoded_unit_count: int
    decoded_unit_count: int


def _ascii_hex(field: bytes, name: str) -> int:
    if not field:
        raise ValueError(f"{name} is empty")
    try:
        text = field.decode("ascii")
        value = int(text, 16)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"{name} is not ASCII hexadecimal") from error
    if len(text) != len(field):
        raise ValueError(f"{name} width differs")
    return value


def parse_yim_envelope(data: bytes) -> YimEnvelope:
    """Validate the observed 60-byte YIM/XIM2 envelope."""

    if len(data) < _RLE_PAYLOAD_OFFSET:
        raise ValueError("YIM envelope is truncated")
    integrity32 = _ascii_hex(data[0:8], "YIM integrity32 field")
    integrity16 = _ascii_hex(data[8:12], "YIM integrity16 field")
    declared_file_size = _ascii_hex(
        data[12:20], "YIM declared-size field"
    )
    version = _ascii_hex(data[20:24], "YIM version field")
    if declared_file_size != len(data):
        raise ValueError("YIM ASCII file size differs")
    if data[_XIM2_MAGIC_OFFSET : _XIM2_MAGIC_OFFSET + 4] != b"XIM2":
        raise ValueError("YIM XIM2 magic differs")

    outer_span = int.from_bytes(data[28:32], "big")
    width = int.from_bytes(data[32:34], "big")
    height = int.from_bytes(data[34:36], "big")
    image_header_size = int.from_bytes(data[36:40], "big")
    reserved = data[40:52]
    payload_block_span = int.from_bytes(data[52:56], "big")
    codec_word = int.from_bytes(data[56:60], "big")
    if outer_span != len(data) - _ASCII_PREAMBLE_SIZE:
        raise ValueError("YIM outer span differs")
    if width <= 0 or height <= 0:
        raise ValueError("YIM raster geometry is empty")
    if image_header_size != _XIM2_HEADER_SIZE:
        raise ValueError("YIM image-header size differs")
    if any(reserved):
        raise ValueError("YIM reserved header area is nonzero")
    if payload_block_span != len(data) - 52:
        raise ValueError("YIM payload-block span differs")
    expected_raster_bytes = width * height * _BYTES_PER_UNIT
    if expected_raster_bytes > _MAX_RASTER_BYTES:
        raise ValueError("YIM declared raster exceeds safety bound")
    return YimEnvelope(
        integrity32=integrity32,
        integrity16=integrity16,
        declared_file_size=declared_file_size,
        version=version,
        outer_span=outer_span,
        width=width,
        height=height,
        image_header_size=image_header_size,
        payload_block_span=payload_block_span,
        codec_word=codec_word,
        encoded_payload=data[_RLE_PAYLOAD_OFFSET:],
    )


def decode_yim_rle(data: bytes) -> YimDecodeResult:
    """Decode the bounded two-byte-unit XIM2 RLE stream."""

    envelope = parse_yim_envelope(data)
    expected = envelope.width * envelope.height * _BYTES_PER_UNIT
    payload = envelope.encoded_payload
    cursor = 0
    output = bytearray()
    literal_commands = 0
    repeat_commands = 0
    encoded_units = 0
    while cursor < len(payload):
        if cursor + 2 > len(payload):
            raise ValueError("YIM RLE command is truncated")
        command = int.from_bytes(payload[cursor : cursor + 2], "big")
        cursor += 2
        literal = bool(command & 0x8000)
        count = command & 0x7FFF
        if count == 0:
            raise ValueError("YIM RLE zero-length command")
        expanded = count * _BYTES_PER_UNIT
        if len(output) + expanded > expected:
            raise ValueError("YIM RLE output exceeds declared raster")
        if literal:
            if cursor + expanded > len(payload):
                raise ValueError("YIM RLE literal is truncated")
            output.extend(payload[cursor : cursor + expanded])
            cursor += expanded
            literal_commands += 1
        else:
            if cursor + _BYTES_PER_UNIT > len(payload):
                raise ValueError("YIM RLE repeat unit is truncated")
            unit = payload[cursor : cursor + _BYTES_PER_UNIT]
            cursor += _BYTES_PER_UNIT
            output.extend(unit * count)
            repeat_commands += 1
        encoded_units += count
    if cursor != len(payload):
        raise ValueError("YIM RLE trailing encoded bytes remain")
    if len(output) != expected:
        raise ValueError("YIM RLE raster size differs")
    return YimDecodeResult(
        envelope=envelope,
        raster=bytes(output),
        literal_command_count=literal_commands,
        repeat_command_count=repeat_commands,
        encoded_unit_count=encoded_units,
        decoded_unit_count=len(output) // _BYTES_PER_UNIT,
    )


def _crc16_ibm(data: bytes, initial: int = 0) -> int:
    crc = initial
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc & 0xFFFF


def yim_integrity_candidates(
    data: bytes,
    decoded: YimDecodeResult | None = None,
) -> dict[str, object]:
    """Test common integrity algorithms without assigning unknown fields."""

    result = decoded or decode_yim_rle(data)
    envelope = result.envelope
    ranges = {
        "AFTER_ASCII_PREAMBLE": data[24:],
        "AFTER_XIM2_MAGIC": data[28:],
        "ENCODED_RLE": envelope.encoded_payload,
        "DECODED_RASTER": result.raster,
    }
    matches32: list[dict[str, str]] = []
    matches16: list[dict[str, str]] = []
    for range_name, material in ranges.items():
        candidates32 = {
            "CRC32_IEEE": zlib.crc32(material) & 0xFFFFFFFF,
            "ADLER32": zlib.adler32(material) & 0xFFFFFFFF,
            "SUM_BYTES_32": sum(material) & 0xFFFFFFFF,
        }
        candidates16 = {
            "CRC16_CCITT_INIT_0000": binascii.crc_hqx(material, 0),
            "CRC16_CCITT_INIT_FFFF": binascii.crc_hqx(
                material, 0xFFFF
            ),
            "CRC16_IBM_INIT_0000": _crc16_ibm(material),
            "SUM_BYTES_16": sum(material) & 0xFFFF,
        }
        matches32.extend(
            {"range": range_name, "algorithm": algorithm}
            for algorithm, value in candidates32.items()
            if value == envelope.integrity32
        )
        matches16.extend(
            {"range": range_name, "algorithm": algorithm}
            for algorithm, value in candidates16.items()
            if value == envelope.integrity16
        )
    return {
        "candidate_32bit_algorithms_tested": 3,
        "candidate_16bit_algorithms_tested": 4,
        "candidate_ranges_tested": len(ranges),
        "integrity32_match_count": len(matches32),
        "integrity16_match_count": len(matches16),
        "integrity32_matches": matches32,
        "integrity16_matches": matches16,
        "integrity_fields_interpreted": False,
    }


def public_yim_envelope(
    result: YimDecodeResult,
) -> dict[str, object]:
    envelope = result.envelope
    return {
        "format": "YIM_XIM2",
        "declared_file_size": envelope.declared_file_size,
        "ascii_preamble_size": _ASCII_PREAMBLE_SIZE,
        "magic_offset": _XIM2_MAGIC_OFFSET,
        "magic": "XIM2",
        "version": envelope.version,
        "outer_span": envelope.outer_span,
        "width": envelope.width,
        "height": envelope.height,
        "bytes_per_decoded_unit": _BYTES_PER_UNIT,
        "image_header_size": envelope.image_header_size,
        "rle_payload_offset": _RLE_PAYLOAD_OFFSET,
        "payload_block_span": envelope.payload_block_span,
        "encoded_payload_size": len(envelope.encoded_payload),
        "length_contract_validated": True,
        "reserved_header_zero_validated": True,
        "integrity_values_included": False,
        "codec_word_included": False,
    }


def public_yim_rle(result: YimDecodeResult) -> dict[str, object]:
    encoded = len(result.envelope.encoded_payload)
    decoded = len(result.raster)
    return {
        "format": "YIM_XIM2_RLE",
        "encoded_payload_size": encoded,
        "decoded_raster_size": decoded,
        "decoded_unit_count": result.decoded_unit_count,
        "literal_command_count": result.literal_command_count,
        "repeat_command_count": result.repeat_command_count,
        "command_count": (
            result.literal_command_count + result.repeat_command_count
        ),
        "compression_ratio_encoded_to_decoded": round(
            encoded / decoded, 8
        ),
        "stream_fully_consumed": True,
        "declared_raster_size_validated": True,
        "decoded_raster_included": False,
        "decoded_raster_hash_included": False,
    }

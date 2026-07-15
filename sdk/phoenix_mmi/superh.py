"""Small, dependency-free SuperH static decoder used by Phoenix research.

The module intentionally decodes only instruction families needed to establish
control flow and PC-relative references. Unknown halfwords remain explicit;
they are never guessed into a more specific instruction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from collections import deque

from .binary import BinaryReader


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


@dataclass(frozen=True)
class SHInstruction:
    offset: int
    mnemonic: str
    operands: str = ""
    target: int | None = None
    literal_address: int | None = None
    literal_value: int | None = None
    flow: str = "linear"
    delayed: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return decoded semantics without redistributing instruction bytes."""

        return {key: value for key, value in asdict(self).items() if value is not None}


def decode_instruction(reader: BinaryReader, offset: int) -> SHInstruction:
    """Decode one big-endian SH-3 instruction at a file-relative address."""

    raw = reader.read(offset, 2)
    if len(raw) != 2:
        raise ValueError(f"truncated SuperH instruction at {offset:#x}")
    word = int.from_bytes(raw, "big")
    n = (word >> 8) & 0xF
    m = (word >> 4) & 0xF

    if word == 0x0009:
        return SHInstruction(offset, "nop")
    if word == 0x000B:
        return SHInstruction(offset, "rts", flow="return", delayed=True)
    if word == 0x002B:
        return SHInstruction(offset, "rte", flow="return", delayed=True)
    if word & 0xF000 == 0xA000:
        displacement = _sign_extend(word & 0x0FFF, 12) * 2
        target = offset + 4 + displacement
        return SHInstruction(offset, "bra", f"{target:#x}", target, flow="branch", delayed=True)
    if word & 0xF000 == 0xB000:
        displacement = _sign_extend(word & 0x0FFF, 12) * 2
        target = offset + 4 + displacement
        return SHInstruction(offset, "bsr", f"{target:#x}", target, flow="call", delayed=True)
    if word & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00):
        names = {0x8900: "bt", 0x8B00: "bf", 0x8D00: "bt/s", 0x8F00: "bf/s"}
        family = word & 0xFF00
        target = offset + 4 + _sign_extend(word & 0xFF, 8) * 2
        delayed = family in (0x8D00, 0x8F00)
        return SHInstruction(
            offset,
            names[family],
            f"{target:#x}",
            target,
            flow="conditional",
            delayed=delayed,
        )
    if word & 0xF0FF == 0x402B:
        return SHInstruction(offset, "jmp", f"@r{n}", flow="indirect-branch", delayed=True)
    if word & 0xF0FF == 0x400B:
        return SHInstruction(offset, "jsr", f"@r{n}", flow="indirect-call", delayed=True)
    if word & 0xF000 == 0xD000:
        literal_address = (offset & ~3) + 4 + (word & 0xFF) * 4
        value = None
        if literal_address + 4 <= reader.size:
            value = int.from_bytes(reader.read(literal_address, 4), "big")
        return SHInstruction(
            offset,
            "mov.l",
            f"@({literal_address:#x},pc),r{n}",
            literal_address=literal_address,
            literal_value=value,
        )
    if word & 0xF000 == 0x9000:
        literal_address = offset + 4 + (word & 0xFF) * 2
        value = None
        if literal_address + 2 <= reader.size:
            value = int.from_bytes(reader.read(literal_address, 2), "big", signed=True)
        return SHInstruction(
            offset,
            "mov.w",
            f"@({literal_address:#x},pc),r{n}",
            literal_address=literal_address,
            literal_value=value,
        )
    if word & 0xFF00 == 0xC700:
        target = (offset & ~3) + 4 + (word & 0xFF) * 4
        return SHInstruction(offset, "mova", f"@({target:#x},pc),r0", target=target)
    if word & 0xFF00 in (0xC000, 0xC100, 0xC200):
        names = {0xC000: "mov.b", 0xC100: "mov.w", 0xC200: "mov.l"}
        scale = {0xC000: 1, 0xC100: 2, 0xC200: 4}
        family = word & 0xFF00
        displacement = (word & 0xFF) * scale[family]
        return SHInstruction(offset, names[family], f"r0,@({displacement},gbr)")
    if word & 0xFF00 in (0xC400, 0xC500, 0xC600):
        names = {0xC400: "mov.b", 0xC500: "mov.w", 0xC600: "mov.l"}
        scale = {0xC400: 1, 0xC500: 2, 0xC600: 4}
        family = word & 0xFF00
        displacement = (word & 0xFF) * scale[family]
        return SHInstruction(offset, names[family], f"@({displacement},gbr),r0")
    if word & 0xF0FF == 0x400E:
        return SHInstruction(offset, "ldc", f"r{n},sr")
    if word & 0xF0FF == 0x401E:
        return SHInstruction(offset, "ldc", f"r{n},gbr")
    if word & 0xF0FF == 0x4017:
        return SHInstruction(offset, "ldc.l", f"@r{n}+,gbr")
    if word & 0xF000 == 0xE000:
        immediate = _sign_extend(word & 0xFF, 8)
        return SHInstruction(offset, "mov", f"#{immediate},r{n}")
    if word & 0xF000 == 0x7000:
        immediate = _sign_extend(word & 0xFF, 8)
        return SHInstruction(offset, "add", f"#{immediate},r{n}")
    if word & 0xF00F == 0x6003:
        return SHInstruction(offset, "mov", f"r{m},r{n}")
    if word & 0xF00F == 0x6002:
        return SHInstruction(offset, "mov.l", f"@r{m},r{n}")
    if word & 0xF00F == 0x2002:
        return SHInstruction(offset, "mov.l", f"r{m},@r{n}")
    return SHInstruction(offset, "unknown")


def trace_control_flow(
    reader: BinaryReader,
    *,
    entry_points: tuple[int, ...] = (0,),
    end: int = 0x10000,
    max_instructions: int = 100_000,
) -> list[SHInstruction]:
    """Trace directly reachable instructions inside a bounded startup region."""

    end = min(end, reader.size)
    queue = deque(entry_points)
    decoded: dict[int, SHInstruction] = {}

    def include_delay_slot(offset: int) -> None:
        if 0 <= offset < end and offset not in decoded:
            decoded[offset] = decode_instruction(reader, offset)

    while queue and len(decoded) < max_instructions:
        offset = queue.popleft()
        while 0 <= offset < end and offset not in decoded and len(decoded) < max_instructions:
            instruction = decode_instruction(reader, offset)
            decoded[offset] = instruction
            if instruction.flow == "branch":
                include_delay_slot(offset + 2)
                if instruction.target is not None:
                    queue.append(instruction.target)
                break
            if instruction.flow == "call":
                include_delay_slot(offset + 2)
                if instruction.target is not None:
                    queue.append(instruction.target)
                offset += 4
                continue
            if instruction.flow == "conditional":
                if instruction.target is not None:
                    queue.append(instruction.target)
                if instruction.delayed:
                    include_delay_slot(offset + 2)
                    offset += 4
                else:
                    offset += 2
                continue
            if instruction.flow in ("return", "indirect-branch"):
                include_delay_slot(offset + 2)
                break
            if instruction.flow == "indirect-call":
                include_delay_slot(offset + 2)
                offset += 4
                continue
            offset += 2
    return [decoded[offset] for offset in sorted(decoded)]


def find_pc_relative_referrers(
    reader: BinaryReader,
    literal_address: int,
    *,
    search_distance: int = 0x404,
) -> list[SHInstruction]:
    """Find MOV.L instructions whose computed literal address is exact."""

    start = max(0, literal_address - search_distance)
    start += start & 1
    hits: list[SHInstruction] = []
    for offset in range(start, min(literal_address, reader.size - 1), 2):
        instruction = decode_instruction(reader, offset)
        if instruction.mnemonic == "mov.l" and instruction.literal_address == literal_address:
            hits.append(instruction)
    return hits

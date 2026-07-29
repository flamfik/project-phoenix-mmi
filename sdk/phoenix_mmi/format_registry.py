"""Declarative format registry backed by bounded structural validators."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
import re
from typing import Callable

from .record_normalization import (
    decode_intel_hex,
    decode_srecord_envelope,
)
from .yim import parse_yim_envelope


FORMAT_REGISTRY_SCHEMA = "phoenix-mmi.format-registry/v1"
_CONFIDENCE = {"strong", "contextual", "routing-only"}
_STATUS_RANK = {
    "CONFIRMED": 3,
    "OPAQUE_ROUTED": 2,
    "CANDIDATE": 1,
}


@dataclass(frozen=True)
class FormatRule:
    rule_id: str
    family: str
    category: str
    priority: int
    confidence: str
    validator: str
    extensions: tuple[str, ...] = ()
    magic_hex: str | None = None
    magic_offset: int = 0
    minimum_size: int = 0

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", self.rule_id):
            raise ValueError(f"invalid format rule ID: {self.rule_id!r}")
        if self.confidence not in _CONFIDENCE:
            raise ValueError(f"invalid confidence: {self.confidence!r}")
        if self.priority < 0 or self.magic_offset < 0 or self.minimum_size < 0:
            raise ValueError("format rule numeric bounds must be non-negative")
        if tuple(sorted(set(self.extensions))) != self.extensions:
            raise ValueError("extensions must be unique and sorted")
        if any(not value.startswith(".") for value in self.extensions):
            raise ValueError("extensions must start with a dot")
        if self.magic_hex is not None:
            if len(self.magic_hex) % 2:
                raise ValueError("magic_hex must contain complete bytes")
            bytes.fromhex(self.magic_hex)

    @property
    def magic(self) -> bytes | None:
        return (
            None if self.magic_hex is None else bytes.fromhex(self.magic_hex)
        )

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["extensions"] = list(self.extensions)
        return value


@dataclass(frozen=True)
class FormatEvidence:
    rule_id: str
    family: str
    category: str
    status: str
    confidence: str
    validator: str
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["diagnostics"] = list(self.diagnostics)
        return value


Validator = Callable[[bytes, int], tuple[str | None, tuple[str, ...]]]


def _valid_magic(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    return "CONFIRMED", ()


def _valid_elf(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    valid = (
        len(data) >= 20
        and data[:4] == b"\x7fELF"
        and data[4] in (1, 2)
        and data[5] in (1, 2)
        and data[6] == 1
    )
    return (
        ("CONFIRMED", ())
        if valid
        else ("CANDIDATE", ("ELF_HEADER_INVALID",))
    )


def _valid_uboot(data: bytes, size: int) -> tuple[str | None, tuple[str, ...]]:
    if len(data) < 64:
        return "CANDIDATE", ("UBOOT_HEADER_TRUNCATED",)
    payload_size = int.from_bytes(data[12:16], "big")
    valid = data[:4] == b"\x27\x05\x19\x56" and payload_size <= size - 64
    return (
        ("CONFIRMED", ())
        if valid
        else ("CANDIDATE", ("UBOOT_SIZE_CONTRACT_INVALID",))
    )


def _valid_iso(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    start = 16 * 2048
    descriptor = data[start : start + 2048]
    valid = (
        len(descriptor) == 2048
        and descriptor[0] == 1
        and descriptor[1:6] == b"CD001"
        and descriptor[6] == 1
        and int.from_bytes(descriptor[128:130], "little") == 2048
        and int.from_bytes(descriptor[130:132], "big") == 2048
    )
    return (
        ("CONFIRMED", ())
        if valid
        else ("CANDIDATE", ("ISO_PVD_INVALID_OR_TRUNCATED",))
    )


def _valid_intel(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    try:
        decode_intel_hex(data)
    except ValueError:
        return None, ()
    return "CONFIRMED", ()


def _valid_srecord(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    try:
        result = decode_srecord_envelope(data)
    except ValueError:
        return None, ()
    return (
        ("CONFIRMED", ())
        if result.fully_validated
        else ("CANDIDATE", ("S_RECORD_PARTIAL_ENVELOPE",))
    )


def _valid_yim(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    try:
        parse_yim_envelope(data)
    except ValueError:
        return None, ()
    return "CONFIRMED", ()


def _valid_metainfo(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    text = data.decode("latin1")
    sections = re.findall(r"(?m)^\s*\[([^\]]+)]\s*$", text)
    fields = re.findall(r"(?m)^\s*([A-Za-z][A-Za-z0-9]+)\s*=", text)
    if sections and fields and (
        any(value.casefold() == "common" for value in sections)
        or "FileName" in fields
    ):
        return "CONFIRMED", ()
    return None, ()


def _valid_fldb(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    if len(data) < 32:
        return "CANDIDATE", ("FLDB_HEADER_TRUNCATED",)
    directory_offset = int.from_bytes(data[0:4], "little")
    entry_count = int.from_bytes(data[12:16], "little")
    record_size = int.from_bytes(data[16:20], "little")
    table_end = directory_offset + entry_count * record_size
    if (
        data[20:24] != b"FLDB"
        or directory_offset < 32
        or record_size < 36
        or entry_count > 1_000_000
        or table_end > len(data)
    ):
        return "CANDIDATE", ("FLDB_STRUCTURE_INVALID",)
    return "CONFIRMED", ()


def _valid_png(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    valid = (
        len(data) >= 24
        and data[:8] == b"\x89PNG\r\n\x1a\n"
        and data[12:16] == b"IHDR"
        and int.from_bytes(data[16:20], "big") > 0
        and int.from_bytes(data[20:24], "big") > 0
    )
    return (
        ("CONFIRMED", ())
        if valid
        else ("CANDIDATE", ("PNG_IHDR_INVALID",))
    )


def _valid_gif(data: bytes, _: int) -> tuple[str | None, tuple[str, ...]]:
    valid = (
        len(data) >= 14
        and data[:6] in {b"GIF87a", b"GIF89a"}
        and int.from_bytes(data[6:8], "little") > 0
        and int.from_bytes(data[8:10], "little") > 0
        and data.endswith(b"\x3b")
    )
    return (
        ("CONFIRMED", ())
        if valid
        else ("CANDIDATE", ("GIF_STRUCTURE_INVALID",))
    )


def _valid_lod(_: bytes, __: int) -> tuple[str | None, tuple[str, ...]]:
    return "OPAQUE_ROUTED", ("LOD_SEMANTICS_UNRESOLVED",)


_VALIDATORS: dict[str, Validator] = {
    "magic-only": _valid_magic,
    "elf-header": _valid_elf,
    "uboot-header": _valid_uboot,
    "iso9660-pvd": _valid_iso,
    "intel-hex": _valid_intel,
    "motorola-s-record": _valid_srecord,
    "yim-envelope": _valid_yim,
    "metainfo-structure": _valid_metainfo,
    "fldb-container": _valid_fldb,
    "png-ihdr": _valid_png,
    "gif-stream": _valid_gif,
    "lod-opaque-route": _valid_lod,
}


class FormatRegistry:
    """Immutable ordered registry of format declarations."""

    def __init__(
        self, rules: tuple[FormatRule, ...], *, registry_id: str = "default"
    ) -> None:
        if not rules:
            raise ValueError("format registry cannot be empty")
        ids = [rule.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate format rule ID")
        missing = sorted(
            {rule.validator for rule in rules} - _VALIDATORS.keys()
        )
        if missing:
            raise ValueError(f"unknown validators: {missing}")
        self.registry_id = registry_id
        self.rules = tuple(
            sorted(rules, key=lambda item: (-item.priority, item.rule_id))
        )

    def classify(
        self, data: bytes, *, path: str = "artifact.bin", size: int | None = None
    ) -> tuple[FormatEvidence, ...]:
        declared_size = len(data) if size is None else size
        if declared_size < len(data):
            raise ValueError("declared size is smaller than supplied bytes")
        extension = PurePosixPath(path).suffix.upper()
        hits = []
        for rule in self.rules:
            if rule.extensions and extension not in rule.extensions:
                continue
            if declared_size < rule.minimum_size:
                continue
            magic = rule.magic
            if magic is not None:
                end = rule.magic_offset + len(magic)
                if len(data) < end or data[rule.magic_offset:end] != magic:
                    continue
            status, diagnostics = _VALIDATORS[rule.validator](
                data, declared_size
            )
            if status is None:
                continue
            hits.append(
                FormatEvidence(
                    rule.rule_id,
                    rule.family,
                    rule.category,
                    status,
                    rule.confidence,
                    rule.validator,
                    diagnostics,
                )
            )
        return tuple(
            sorted(
                hits,
                key=lambda item: (
                    -_STATUS_RANK[item.status],
                    -next(
                        rule.priority
                        for rule in self.rules
                        if rule.rule_id == item.rule_id
                    ),
                    item.rule_id,
                ),
            )
        )

    def primary(
        self, data: bytes, *, path: str = "artifact.bin", size: int | None = None
    ) -> FormatEvidence | None:
        hits = self.classify(data, path=path, size=size)
        return hits[0] if hits else None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": FORMAT_REGISTRY_SCHEMA,
            "registry_id": self.registry_id,
            "rule_count": len(self.rules),
            "rules": [rule.to_dict() for rule in self.rules],
        }


DEFAULT_FORMAT_REGISTRY = FormatRegistry(
    (
        FormatRule(
            "elf",
            "ELF_EXECUTABLE",
            "executable",
            100,
            "strong",
            "elf-header",
            magic_hex="7f454c46",
            minimum_size=20,
        ),
        FormatRule(
            "uboot-legacy",
            "UBOOT_LEGACY_IMAGE",
            "container",
            95,
            "strong",
            "uboot-header",
            magic_hex="27051956",
            minimum_size=64,
        ),
        FormatRule(
            "iso9660",
            "ISO9660_MEDIA",
            "filesystem",
            95,
            "strong",
            "iso9660-pvd",
            magic_hex="4344303031",
            magic_offset=16 * 2048 + 1,
            minimum_size=17 * 2048,
        ),
        FormatRule(
            "intel-hex",
            "INTEL_HEX_TEXT",
            "record-container",
            90,
            "strong",
            "intel-hex",
            (".HEX", ".LOD", ".SW"),
            magic_hex="3a",
            minimum_size=12,
        ),
        FormatRule(
            "motorola-s-record",
            "S_RECORD_STREAM",
            "record-container",
            90,
            "strong",
            "motorola-s-record",
            (".HEX", ".LOD", ".SW"),
            magic_hex="53",
            minimum_size=12,
        ),
        FormatRule(
            "yim-xim2",
            "YIM_XIM2_RESOURCE",
            "resource",
            90,
            "strong",
            "yim-envelope",
            (".YIM",),
            minimum_size=60,
        ),
        FormatRule(
            "metainfo",
            "UPDATE_DESCRIPTOR_METAINFO",
            "metadata",
            85,
            "contextual",
            "metainfo-structure",
            (".TXT",),
            minimum_size=8,
        ),
        FormatRule(
            "fldb",
            "FLDB_CONTAINER",
            "container",
            85,
            "strong",
            "fldb-container",
            magic_hex="464c4442",
            magic_offset=20,
            minimum_size=32,
        ),
        FormatRule(
            "png",
            "PNG_RESOURCE",
            "resource",
            80,
            "strong",
            "png-ihdr",
            magic_hex="89504e470d0a1a0a",
            minimum_size=24,
        ),
        FormatRule(
            "gif87a",
            "GIF_RESOURCE",
            "resource",
            80,
            "strong",
            "gif-stream",
            magic_hex="474946383761",
            minimum_size=14,
        ),
        FormatRule(
            "gif89a",
            "GIF_RESOURCE",
            "resource",
            80,
            "strong",
            "gif-stream",
            magic_hex="474946383961",
            minimum_size=14,
        ),
        FormatRule(
            "gzip",
            "GZIP_STREAM",
            "compression",
            70,
            "contextual",
            "magic-only",
            magic_hex="1f8b08",
            minimum_size=10,
        ),
        FormatRule(
            "zip",
            "ZIP_ARCHIVE",
            "archive",
            70,
            "contextual",
            "magic-only",
            magic_hex="504b0304",
            minimum_size=30,
        ),
        FormatRule(
            "lod-opaque",
            "LOD_LANGUAGE_PAYLOAD",
            "opaque-resource",
            10,
            "routing-only",
            "lod-opaque-route",
            (".LOD",),
        ),
    )
)


def build_public_registry_summary(
    registry: FormatRegistry = DEFAULT_FORMAT_REGISTRY,
) -> dict[str, object]:
    categories: dict[str, int] = {}
    for rule in registry.rules:
        categories[rule.category] = categories.get(rule.category, 0) + 1
    return {
        "schema": "phoenix-mmi.format-registry-summary/v1",
        "registry_schema": FORMAT_REGISTRY_SCHEMA,
        "registry_id": registry.registry_id,
        "rule_count": len(registry.rules),
        "category_counts": dict(sorted(categories.items())),
        "unique_rule_ids": True,
        "all_validators_resolved": True,
        "classification_levels": [
            "CONFIRMED",
            "OPAQUE_ROUTED",
            "CANDIDATE",
        ],
        "raw_artifact_bytes_included": False,
    }

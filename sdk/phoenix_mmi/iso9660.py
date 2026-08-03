"""Minimal read-only ISO 9660 member access for targeted firmware analysis."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


SECTOR_SIZE = 2048


def _both_endian_u32(data: bytes) -> int:
    if len(data) < 8:
        raise ValueError("truncated ISO both-endian u32")
    little = int.from_bytes(data[:4], "little")
    big = int.from_bytes(data[4:8], "big")
    if little != big:
        raise ValueError("inconsistent ISO both-endian u32")
    return little


@dataclass(frozen=True)
class ISOEntry:
    path: str
    extent: int
    size: int
    is_directory: bool


@dataclass(frozen=True)
class ISODescriptor:
    """One validated ECMA-119 volume-descriptor sequence record."""

    sector: int
    descriptor_type: int
    identifier: str
    version: int
    joliet_escape: str | None = None


class ISO9660Image:
    """Walk and extract an explicitly selected ISO 9660 member."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        with self.path.open("rb") as handle:
            handle.seek(16 * SECTOR_SIZE)
            self._pvd = handle.read(SECTOR_SIZE)
        if len(self._pvd) != SECTOR_SIZE or self._pvd[0] != 1 or self._pvd[1:6] != b"CD001":
            raise ValueError(f"{self.path} does not contain an ISO 9660 primary descriptor")
        self.volume_identifier = self._pvd[40:72].decode("ascii", "ignore").strip(" \x00")

    def sha256(self) -> str:
        digest = hashlib.sha256()
        with self.path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def descriptors(self, *, maximum_sector: int = 255) -> list[ISODescriptor]:
        """Read the ECMA-119 descriptor sequence without interpreting payloads."""

        if maximum_sector < 16:
            raise ValueError("maximum_sector must include sector 16")
        descriptors: list[ISODescriptor] = []
        with self.path.open("rb") as handle:
            for sector in range(16, maximum_sector + 1):
                handle.seek(sector * SECTOR_SIZE)
                data = handle.read(SECTOR_SIZE)
                if len(data) != SECTOR_SIZE:
                    break
                if data[1:6] != b"CD001":
                    if descriptors:
                        break
                    continue
                descriptor_type = data[0]
                joliet_escape = None
                if descriptor_type == 2 and data[88:91] in (b"%/@", b"%/C", b"%/E"):
                    joliet_escape = data[88:91].decode("ascii")
                descriptors.append(
                    ISODescriptor(
                        sector=sector,
                        descriptor_type=descriptor_type,
                        identifier="CD001",
                        version=data[6],
                        joliet_escape=joliet_escape,
                    )
                )
                if descriptor_type == 255:
                    break
        return descriptors

    def volume_metadata(self) -> dict[str, object]:
        """Return validated structural metadata from the primary descriptor."""

        volume_space_size = _both_endian_u32(self._pvd[80:88])
        logical_block_size = int.from_bytes(self._pvd[128:130], "little")
        logical_block_size_be = int.from_bytes(self._pvd[130:132], "big")
        if logical_block_size != logical_block_size_be:
            raise ValueError("inconsistent ISO both-endian logical block size")
        path_table_size = _both_endian_u32(self._pvd[132:140])
        return {
            "system_identifier": self._pvd[8:40]
            .decode("ascii", "ignore")
            .strip(" \x00"),
            "volume_identifier": self.volume_identifier,
            "volume_space_size": volume_space_size,
            "logical_block_size": logical_block_size,
            "path_table_size": path_table_size,
            "application_identifier": self._pvd[574:702]
            .decode("ascii", "ignore")
            .strip(" \x00"),
            "creation_time_raw": self._pvd[813:830],
            "modification_time_raw": self._pvd[830:847],
            "file_structure_version": self._pvd[881],
        }

    @staticmethod
    def _record(data: bytes, offset: int) -> tuple[ISOEntry | None, int]:
        length = data[offset]
        if length == 0:
            return None, offset + 1
        record = data[offset : offset + length]
        if len(record) != length or length < 34:
            raise ValueError("truncated ISO directory record")
        extent = _both_endian_u32(record[2:10])
        size = _both_endian_u32(record[10:18])
        name_length = record[32]
        raw_name = record[33 : 33 + name_length]
        if raw_name == b"\x00":
            name = "."
        elif raw_name == b"\x01":
            name = ".."
        else:
            name = raw_name.decode("ascii", "replace").split(";")[0]
        return ISOEntry(name, extent, size, bool(record[25] & 2)), offset + length

    def entries(self) -> list[ISOEntry]:
        root, _ = self._record(self._pvd, 156)
        if root is None:
            raise ValueError("missing ISO root directory")
        entries: list[ISOEntry] = []
        visited: set[tuple[int, int]] = set()
        with self.path.open("rb") as handle:

            def walk(directory: ISOEntry, parent: PurePosixPath) -> None:
                key = (directory.extent, directory.size)
                if key in visited:
                    return
                visited.add(key)
                handle.seek(directory.extent * SECTOR_SIZE)
                directory_data = handle.read(directory.size)
                offset = 0
                while offset < len(directory_data):
                    if directory_data[offset] == 0:
                        offset = ((offset // SECTOR_SIZE) + 1) * SECTOR_SIZE
                        continue
                    child, offset = self._record(directory_data, offset)
                    if child is None or child.path in (".", ".."):
                        continue
                    path = (parent / child.path).as_posix()
                    normalized = ISOEntry(path, child.extent, child.size, child.is_directory)
                    entries.append(normalized)
                    if child.is_directory:
                        walk(child, parent / child.path)

            walk(root, PurePosixPath("."))
        return entries

    def read_entry(self, entry: ISOEntry, offset: int, length: int) -> bytes:
        """Read a bounded range from one member without extracting it."""

        if entry.is_directory:
            raise ValueError("cannot read a directory as a file")
        if offset < 0 or length < 0 or offset > entry.size:
            raise ValueError("entry offset and length must be in bounds")
        with self.path.open("rb") as handle:
            handle.seek(entry.extent * SECTOR_SIZE + offset)
            return handle.read(min(length, entry.size - offset))

    def iter_entry_chunks(
        self, entry: ISOEntry, *, chunk_size: int = 1024 * 1024
    ):
        """Yield member-relative offsets and bytes without writing a local copy."""

        if entry.is_directory:
            raise ValueError("cannot iterate a directory as a file")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        remaining = entry.size
        offset = 0
        with self.path.open("rb") as handle:
            handle.seek(entry.extent * SECTOR_SIZE)
            while remaining:
                chunk = handle.read(min(chunk_size, remaining))
                if not chunk:
                    raise EOFError(f"truncated ISO member at extent {entry.extent}")
                yield offset, chunk
                offset += len(chunk)
                remaining -= len(chunk)

    def find_filename(self, filename: str) -> ISOEntry:
        wanted = filename.casefold()
        matches = [
            entry
            for entry in self.entries()
            if not entry.is_directory and PurePosixPath(entry.path).name.casefold() == wanted
        ]
        if len(matches) != 1:
            raise KeyError(f"expected one ISO member named {filename!r}, found {len(matches)}")
        return matches[0]

    def find_path(self, path: str) -> ISOEntry:
        """Resolve one canonical ISO path, ignoring ISO filename case."""

        wanted = PurePosixPath(path).as_posix().lstrip("./").casefold()
        matches = [
            entry
            for entry in self.entries()
            if not entry.is_directory and entry.path.lstrip("./").casefold() == wanted
        ]
        if len(matches) != 1:
            raise KeyError(f"expected one ISO member at {path!r}, found {len(matches)}")
        return matches[0]

    def extract(self, entry: ISOEntry, destination: str | Path) -> Path:
        if entry.is_directory:
            raise ValueError("cannot extract a directory as a file")
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("rb") as source, destination.open("wb") as output:
            source.seek(entry.extent * SECTOR_SIZE)
            remaining = entry.size
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise EOFError(f"truncated ISO member {entry.path}")
                output.write(chunk)
                remaining -= len(chunk)
        return destination

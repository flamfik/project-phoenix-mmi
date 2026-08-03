"""Bounded, read-only access to binary research artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator


class BinaryReader:
    """Small read-only binary reader with explicit bounds checking.

    The class never memory-maps or executes an artifact. Reads use fresh file
    handles so callers can safely retain a reader for a long analysis run.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        self.size = self.path.stat().st_size

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset > self.size:
            raise ValueError(f"offset {offset} is beyond artifact size {self.size}")
        with self.path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(min(length, self.size - offset))

    def head(self, length: int = 64) -> bytes:
        return self.read(0, length)

    def iter_chunks(self, chunk_size: int = 1024 * 1024) -> Iterator[tuple[int, bytes]]:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        offset = 0
        with self.path.open("rb") as handle:
            while chunk := handle.read(chunk_size):
                yield offset, chunk
                offset += len(chunk)

    def sha256(self, chunk_size: int = 1024 * 1024) -> str:
        digest = hashlib.sha256()
        for _, chunk in self.iter_chunks(chunk_size):
            digest.update(chunk)
        return digest.hexdigest()

    def find_all(
        self,
        needle: bytes,
        *,
        chunk_size: int = 1024 * 1024,
        max_hits: int | None = None,
    ) -> list[int]:
        """Find byte signatures without loading the complete artifact."""

        if not needle:
            raise ValueError("needle must not be empty")
        if max_hits is not None and max_hits <= 0:
            return []

        hits: list[int] = []
        tail = b""
        for chunk_offset, chunk in self.iter_chunks(chunk_size):
            combined = tail + chunk
            base_offset = chunk_offset - len(tail)
            search_from = 0
            while True:
                index = combined.find(needle, search_from)
                if index < 0:
                    break
                absolute = base_offset + index
                if absolute >= 0 and (not hits or hits[-1] != absolute):
                    hits.append(absolute)
                    if max_hits is not None and len(hits) >= max_hits:
                        return hits
                search_from = index + 1
            tail = combined[-(len(needle) - 1) :] if len(needle) > 1 else b""
        return hits

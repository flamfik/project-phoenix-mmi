#!/usr/bin/env python3
"""Read-only ISO 9660 inventory tool used by Session 001.

The tool walks ISO directory records directly, extracts files into a disposable
workspace, calculates SHA-256 hashes, and classifies file types with `file`.
It intentionally does not understand or execute firmware payloads.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

SECTOR_SIZE = 2048


def both_endian_u32(data: bytes) -> int:
    return int.from_bytes(data[:4], "little")


def both_endian_u16(data: bytes) -> int:
    return int.from_bytes(data[:2], "little")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_directory_record(data: bytes, offset: int):
    length = data[offset]
    if length == 0:
        return None, offset + 1
    record = data[offset : offset + length]
    extent = both_endian_u32(record[2:10])
    size = both_endian_u32(record[10:18])
    flags = record[25]
    name_length = record[32]
    raw_name = record[33 : 33 + name_length]
    if raw_name == b"\x00":
        name = "."
    elif raw_name == b"\x01":
        name = ".."
    else:
        name = raw_name.decode("ascii", "replace").split(";")[0]
    return {
        "length": length,
        "extent": extent,
        "size": size,
        "flags": flags,
        "name": name,
        "is_dir": bool(flags & 2),
    }, offset + length


def inventory_iso(iso_path: Path, disc: int, output: Path):
    extraction_root = output / f"cd{disc}-extracted"
    extraction_root.mkdir(parents=True, exist_ok=True)

    with iso_path.open("rb") as image:
        image.seek(16 * SECTOR_SIZE)
        pvd = image.read(SECTOR_SIZE)
        if pvd[0] != 1 or pvd[1:6] != b"CD001":
            raise ValueError(f"{iso_path} does not contain a valid ISO 9660 PVD")

        metadata = {
            "disc": disc,
            "iso": iso_path.name,
            "iso_size": iso_path.stat().st_size,
            "iso_sha256": sha256_file(iso_path),
            "system_identifier": pvd[8:40].decode("ascii", "ignore").strip(" \x00"),
            "volume_identifier": pvd[40:72].decode("ascii", "ignore").strip(" \x00"),
            "volume_space_size": both_endian_u32(pvd[80:88]),
            "logical_block_size": both_endian_u16(pvd[128:132]),
            "path_table_size": both_endian_u32(pvd[132:140]),
        }
        root, _ = parse_directory_record(pvd, 156)
        if root is None:
            raise ValueError("Missing ISO root directory record")

        rows = []
        visited = set()

        def walk(record, relative: Path):
            key = (record["extent"], record["size"])
            if key in visited:
                return
            visited.add(key)
            image.seek(record["extent"] * SECTOR_SIZE)
            directory_data = image.read(record["size"])
            offset = 0
            while offset < len(directory_data):
                if directory_data[offset] == 0:
                    offset = ((offset // SECTOR_SIZE) + 1) * SECTOR_SIZE
                    continue
                child, next_offset = parse_directory_record(directory_data, offset)
                offset = next_offset
                if child is None or child["name"] in (".", ".."):
                    continue

                relative_path = relative / child["name"]
                local_path = extraction_root / relative_path
                manifest_path = relative_path.as_posix()

                if child["is_dir"]:
                    local_path.mkdir(parents=True, exist_ok=True)
                    rows.append({
                        "disc": disc,
                        "path": manifest_path + "/",
                        "kind": "directory",
                        "size_bytes": 0,
                        "sha256": "",
                        "file_type": "",
                    })
                    walk(child, relative_path)
                    continue

                local_path.parent.mkdir(parents=True, exist_ok=True)
                image.seek(child["extent"] * SECTOR_SIZE)
                content = image.read(child["size"])
                local_path.write_bytes(content)
                file_type = subprocess.run(
                    ["file", "-b", str(local_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip()
                rows.append({
                    "disc": disc,
                    "path": manifest_path,
                    "kind": "file",
                    "size_bytes": child["size"],
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "file_type": file_type,
                })

        walk(root, Path("."))
        return metadata, rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("images", nargs="+", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    metadata = []
    rows = []
    for disc, image in enumerate(args.images, start=1):
        disc_metadata, disc_rows = inventory_iso(image, disc, args.output)
        metadata.append(disc_metadata)
        rows.extend(disc_rows)

    (args.output / "iso-metadata.json").write_text(json.dumps(metadata, indent=2))
    with (args.output / "file-manifest.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["disc", "path", "kind", "size_bytes", "sha256", "file_type"],
        )
        writer.writeheader()
        writer.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

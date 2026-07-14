#!/usr/bin/env python3
"""Generate a deterministic SHA-256 inventory for local research artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, help="Directory containing local artifacts")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    if not args.directory.is_dir():
        print(f"error: not a directory: {args.directory}", file=sys.stderr)
        return 2

    records = []
    for path in sorted(p for p in args.directory.iterdir() if p.is_file()):
        records.append({
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })

    if args.json:
        print(json.dumps(records, indent=2))
    else:
        for record in records:
            print(f"{record['sha256']}  {record['name']}  {record['size_bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

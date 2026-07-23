# Session 014 public evidence

This directory contains publication-safe, deterministic reports from the
global role-sensitive FLDB parser search.

Files:

- `cd1-global-fldb-parser-search.public.json`;
- `cd3-global-fldb-parser-search.public.json`;
- `cd1-cd3.global-fldb-parser-search.comparison.json`;
- `global-fldb-parser-correlation.json`.

The reports contain no firmware bytes, instruction bytes, runtime addresses,
raw strings, local paths, map payloads or extracted resources. They record only
hashes, file-relative offsets, counts, bounded instruction roles and confidence
classifications.

Result: seven cross-version 36-byte loop pairs were found, one is a write-only
fixed-record initializer, and no candidate meets the parser promotion gate.
The actual FLDB parser and optical sector-read ABI remain open.

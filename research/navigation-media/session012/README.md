# Session 012 publication-safe evidence

This directory contains deterministic reports produced by the read-only
payload-family and firmware constant analyzers:

- `navigation-payload-families.public.json` - family signatures, validated
  directories, speech split, anonymous partition graph and opaque-field probes;
- `cd1-parser-constants.public.json` and `cd3-parser-constants.public.json` -
  bounded SH constant-load evidence;
- `cd1-cd3.parser-constants.comparison.json` - relocation-normalized pairs;
- `firmware-payload-parser.comparison.json` - conservative correlation and
  operational graph v5.

No map or firmware bytes, filenames, internal names, raw headers, raw metadata,
timestamps, opaque values, local paths or extracted resources are included.
The source ISO remains a local, ignored and provenance-unverified artifact.

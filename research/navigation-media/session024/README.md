# Session 024 publication-safe evidence

This directory contains generated, publication-safe evidence for the bounded
owner-entry indirect-caller compatibility analysis:

- `cd1-owner-caller-compatibility.public.json`;
- `cd3-owner-caller-compatibility.public.json`;
- `cd1-cd3.owner-caller-compatibility.comparison.json`;
- `owner-caller-compatibility-correlation.json`.

The reports contain hashes, file-relative offsets, generated canonical
expressions, normalized context counts and evidence status. They do not
contain firmware bytes, instruction bytes, absolute runtime addresses, raw
strings, local paths, map payloads or extracted resources.

Full local analysis output belongs under `work/`, which is ignored by Git.

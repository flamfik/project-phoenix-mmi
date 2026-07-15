# Session 006 publication-safe evidence

This directory contains generated, publication-safe evidence for runtime-address mapping of the four post-cluster value runs.

- `cd1-runtime-address-map.public.json` - MMI 5150 model evaluation and mapped-region summary;
- `cd3-runtime-address-map.public.json` - MMI 5570 model evaluation and mapped-region summary;
- `cd1-cd3.runtime-address-map.comparison.json` - competing-model scores, exact target-window counts and relocated-record evidence.

The reports contain addresses, offsets, hashes, counts and decoded instruction semantics only. They do not contain firmware bytes, target-window bytes, resource bytes, raw strings, raw HTML/URIs or the complete pointer-run value lists. Full local reports remain under the ignored `research/firmware-5570/work/session006/` directory.

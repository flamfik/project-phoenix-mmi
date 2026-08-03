# Session 010 publication-safe evidence

This directory contains generated evidence for the navigation-dataflow and
optical-service contract pass.

- `cd1-navigation-dataflow.public.json` - MMI 5150 fixed anchors,
  relocation-normalized neighborhoods and bounded SH-3 call-site summaries;
- `cd3-navigation-dataflow.public.json` - MMI 5570 equivalent evidence;
- `cd1-cd3.navigation-dataflow.comparison.json` - cross-release contract
  comparison and operational graph v3.

The reports contain only predeclared anchor identifiers, offsets, counts,
hashes, decoded instruction-family summaries and confidence-graded findings.
They contain no firmware or instruction bytes, arbitrary strings, raw runtime
addresses, map/route payload or extracted resources. Full local reports remain
under the ignored `research/firmware-5570/work/session010/` directory.

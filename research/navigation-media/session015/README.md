# Session 015 public evidence

This directory contains deterministic, publication-safe reports from the
bounded optical/navigation interprocedural SH analysis.

Files:

- `cd1-optical-callgraph.public.json`;
- `cd3-optical-callgraph.public.json`;
- `cd1-cd3.optical-callgraph.comparison.json`;
- `optical-sector-correlation.json`.

The reports contain no firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

Result: 102 paired optical pointer slots reduce to 69 unique target pairs and
25 two-release code-gated seeds. The depth-two graph contains 35 node pairs and
20 deduplicated static-call edges. It has no shared navigation/optical node, no
direct cross-domain edge and no `2048` argument edge. The sector-read ABI,
buffer provenance and buffer owner remain open.

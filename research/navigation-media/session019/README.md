# Session 019 public evidence

This directory contains deterministic, publication-safe reports from the CD1
zero-tail slot, translated static accessor-cluster and bounded writer/relocation
analysis.

Files:

- `cd1-runtime-slot-lineage.public.json`;
- `cd3-shadow-accessor-cluster.public.json`;
- `cd1-cd3.runtime-slot-lineage.comparison.json`;
- `runtime-slot-lineage-correlation.json`.

The reports contain no firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

Result: three of 15 zero-tail words are literal-backed CD1 call targets. Their
contexts select three compact CD3 direct entries, and byte-identical bodies
remain at translated CD1 offsets with zero direct calls. One mapping passes the
fixed Session 018 promotion gate, one is probable but below that gate and one
is a structural candidate. A 235,864-seed bounded address/dataflow census found
no direct store to the run, and the exact 32-byte source/destination record
model found no candidate. Runtime patch, overlay or linkage behavior therefore
remains a strengthened hypothesis, not a confirmed mechanism.

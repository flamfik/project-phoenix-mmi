# Session 017 public evidence

This directory contains deterministic, publication-safe reports from the
descriptor producer, accessor-family and mixed-width initializer analysis.

Files:

- `cd1-descriptor-lineage.public.json`;
- `cd3-descriptor-lineage.public.json`;
- `cd1-cd3.descriptor-lineage.comparison.json`;
- `descriptor-lineage-correlation.json`.

The reports contain no firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

Result: both dynamic dispatch instances have paired nearest-producer calls and
stable argument roles. CD3 alone closes a local forwarding chain to a field-12
accessor. A paired six-member accessor cluster exists across CD1/CD3, but the
CD1 producer edge is absent under the direct-reference model. Eighteen paired
mixed-width initializer signatures were analyzable; zero passed the executable
context gate. Parser, sector ABI, buffer ownership/provenance and partition
consumer remain open.

# Session 020 public evidence

This directory contains deterministic, publication-safe reports for the
bilateral pointer-zero runtime-linkage family and bounded loader probes.

Files:

- `cd1-runtime-linkage-family.public.json`;
- `cd3-runtime-linkage-family.public.json`;
- `cd1-cd3.runtime-linkage-family.comparison.json`;
- `runtime-linkage-family-correlation.json`.

The reports contain no firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

Result: the Session 019 five-record run has one unique normalized CD3 pair.
The run start and all five pointer targets translate by `+324,860` bytes. CD1
uses three tail slots in 909 adjacent literal/JSR forms; CD3 retains one slot
with four forms. Similar zero-filled syntactic targets occur broadly in both
images. Bounded GBR, exact-address helper, coherent referenced copy-table and
five-marker cache-maintenance probes find no writer chain, so runtime linkage
remains a strengthened hypothesis rather than a confirmed mechanism.

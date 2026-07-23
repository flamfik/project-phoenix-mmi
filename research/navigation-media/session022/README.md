# Session 022 public evidence

This directory contains deterministic, publication-safe reports for bounded
owner ingress and state-base provenance.

Files:

- `cd1-owner-ingress-state.public.json`;
- `cd3-owner-ingress-state.public.json`;
- `cd1-cd3.owner-ingress-state.comparison.json`;
- `owner-ingress-state-correlation.json`.

The reports contain no firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

Result: no adjacent literal/JSR or direct BSR calls enter the selected owner
windows. One internal address-taken use exists per release, but no bilateral
selected-owner use is established. Both owner pairs preserve
entry-argument-rooted state bases, including four argument-dereference bases
per owner and zero static-image-pointer-rooted bases. This establishes bounded
state provenance, not creator, class, semantic owner or writer/loader identity.

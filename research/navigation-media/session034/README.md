# Session 034 publication-safe evidence

Generated reports:

- `cd1-exact-block-map.public.json`;
- `cd3-exact-block-map.public.json`;
- `cd1-cd3.exact-block-map.comparison.json`;
- `exact-block-map-correlation.json`.

They contain artifact hashes, generated zone/block IDs, file-relative offsets,
lengths, relocation deltas, fixed seed/window parameters, counts, transition
bounds and evidence statuses only. Firmware bytes, raw seed digests,
instruction bytes, raw strings, raw pointer values, absolute runtime
addresses, local paths, map payloads and extracted resources are excluded.
Detailed expected-delta blocks appear once in the comparison report; per-disc
reports retain compact summaries. Full local output belongs under ignored
`work/`.

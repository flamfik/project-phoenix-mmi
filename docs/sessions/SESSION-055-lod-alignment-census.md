# Session 055 - LOD alignment census

- Date: 2026-07-29
- Objective: test fixed candidate widths for cross-language phase structure.
- Mode: read-only, aligned-byte comparison.
- Status: COMPLETE, CANDIDATE ONLY.

## Method and result

Widths 2, 3, 4, 8 and 16 were tested over the common 2,195,064-byte span.
Only width 3 exceeded the predeclared 0.05 phase-spread threshold:

```text
width 3 phase ratios = 0.07769022, 0.04849881, 0.01645237
phase spread         = 0.06123785
maximum phase        = 0
```

The other candidate widths had spreads below 0.0048.

This supports a three-byte alignment hypothesis but does not establish a
three-byte record, word encoding or address model.

## Deliverables

- SPEC-063;
- RQ-201-RQ-203;
- `lod-alignment.public.json`;
- fixed-width phase analyzer.

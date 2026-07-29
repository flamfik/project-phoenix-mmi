# Session 051 - YIM expanded integrity catalogue

- Date: 2026-07-29
- Objective: test a frozen catalogue of common CRC variants against the two
  unknown ASCII-preamble integrity fields.
- Mode: static, read-only, non-adaptive.
- Status: COMPLETE, BOUNDED NEGATIVE.

## Method

The catalogue was fixed before the corpus run:

- 7 named 32-bit CRC variants;
- 9 named 16-bit CRC variants;
- 7 material ranges, including encoded and decoded representations;
- native and byte-swapped result representations.

No polynomial, range or initial value was tuned from an observed field.

## Result

All five unique YIM sources produced:

```text
32-bit matches = 0
16-bit matches = 0
```

This excludes only the documented catalogue. It does not prove that the fields
are not checksums.

## Safety decision

Read-only parsing remains allowed. Repacking and firmware mutation remain
blocked because neither integrity field is explained.

## Deliverables

- SPEC-059;
- RQ-188-RQ-190;
- `yim-integrity-catalog.public.json`;
- reusable CRC catalogue in Phoenix SDK.

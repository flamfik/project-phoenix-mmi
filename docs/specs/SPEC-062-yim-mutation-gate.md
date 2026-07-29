# SPEC-062 - YIM mutation gate

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 047, 051-054
- Related questions: RQ-198-RQ-200

## Allowed

- strict envelope validation;
- bounded RLE decoding;
- aggregate metadata reporting;
- exact private content correlation.

## Blocked

- field synthesis;
- YIM encoding or repacking;
- resource replacement;
- firmware or update-media mutation.

The gate may open only after both integrity fields and the encoder contract are
independently reproduced and negative controls pass.

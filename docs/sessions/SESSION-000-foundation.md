# Session 000 — Foundation

- Date: 2026-07-14
- Objective: Establish repository structure, safety boundaries, evidence rules, and the initial artifact register.

## Confirmed observations

| ID | Status | Claim | Evidence |
|---|---|---|---|
| S000-01 | CONFIRMED | Three ISO 9660 images were supplied as the MMI 5570 update set. | Host `file` identification and SHA-256 calculation. |
| S000-02 | CONFIRMED | Disc 1 volume label is `H2_HI_EU_K942`. | ISO filesystem metadata reported by `file`. |
| S000-03 | CONFIRMED | Disc 2 volume label is `DISC`. | ISO filesystem metadata reported by `file`. |
| S000-04 | CONFIRMED | Disc 3 volume label is `DISK`. | ISO filesystem metadata reported by `file`. |

## Decisions

- Firmware images remain local and are excluded from Git.
- Initial work is static, read-only, and reproducible.
- Component Protection is outside the modification scope.

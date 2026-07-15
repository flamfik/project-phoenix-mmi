# Research Questions

| ID | Question | Status after Session 003 | Evidence / target |
|---|---|---|---|
| RQ-001 | Does the principal BIN have a vendor container header? | PARTIAL | No standard magic at offset zero; identical Wind River startup region. SPEC-001. |
| RQ-002 | One ELF, several executables or a flat image? | PARTIAL | No validated embedded ELF; flat SuperH/VxWorks image is PROBABLE. SPEC-001. |
| RQ-003 | Which offsets are genuine segments? | PARTIAL | 512 KiB integrity chunks are CONFIRMED; semantic regions remain open. SPEC-002. |
| RQ-004 | How do `CheckSum` and `CheckSum1`–`24` map to the image? | CLOSED | CRC32/IEEE of 25 consecutive 512 KiB chunks, final chunk truncated. SPEC-002. |
| RQ-005 | Are regions compressed with standard algorithms? | PARTIAL | All apparent gzip/xz/bzip2/zlib candidates failed complete-stream validation. |
| RQ-006 | Are standard graphics embedded? | CLOSED | Three JPEG and nine GIF89a resources, identical in CD1/CD3. SPEC-003. |
| RQ-007 | Are standard fonts embedded? | OPEN | Apparent TTF/OTF magics failed table-directory validation. |
| RQ-008 | How are strings encoded and grouped? | PARTIAL | ASCII/UTF-16 inventory and domain markers are reproducible; tables remain unknown. |
| RQ-009 | Is navigation a distinct internal region? | OPEN | NAV/GPS markers exist; no bounded module yet. |
| RQ-010 | Known filesystem or proprietary table? | PARTIAL | No validated ROMFS/CRAMFS/SquashFS/UBIFS/JFFS2/ISO9660; proprietary layout remains possible. |

A bare magic-byte occurrence never closes a question. Positive formats require structural validation; negative results are limited to the formats and validators documented in Phoenix SDK.

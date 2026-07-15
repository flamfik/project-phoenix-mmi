# Research Questions

| ID | Question | Status after Session 004 | Evidence / target |
|---|---|---|---|
| RQ-001 | Does the principal BIN have a vendor container header? | CLOSED | Offset zero is executable SH-3 control flow, not a separate container header. SPEC-001, SPEC-005. |
| RQ-002 | One ELF, several executables or a flat image? | PARTIAL | A flat SH-3/VxWorks executable start is CONFIRMED; later internal module boundaries remain open. SPEC-001, SPEC-005. |
| RQ-003 | Which offsets are genuine segments? | PARTIAL | Startup is executable and a filler-bounded resource island is PROBABLE; no vendor segment directory is known. SPEC-002, SPEC-006. |
| RQ-004 | How do `CheckSum` and `CheckSum1`-`24` map to the image? | CLOSED | CRC32/IEEE of 25 consecutive 512 KiB chunks, final chunk truncated. SPEC-002. |
| RQ-005 | Are regions compressed with standard algorithms? | PARTIAL | All apparent gzip/xz/bzip2/zlib candidates failed complete-stream validation. |
| RQ-006 | Are standard graphics embedded? | CLOSED | Three JPEG and nine GIF89a resources, identical in CD1/CD3. SPEC-003. |
| RQ-007 | Are standard fonts embedded? | OPEN | Apparent TTF/OTF magics failed table-directory validation. |
| RQ-008 | How are strings encoded and grouped? | PARTIAL | ASCII/UTF-16 inventory and domain markers are reproducible; tables remain unknown. |
| RQ-009 | Is navigation a distinct internal region? | OPEN | NAV/GPS markers exist; no bounded module yet. |
| RQ-010 | Known filesystem or proprietary table? | PARTIAL | No validated ROMFS/CRAMFS/SquashFS/UBIFS/JFFS2/ISO9660; proprietary layout remains possible. |
| RQ-011 | Is the entry point valid big-endian SH-3 code? | CLOSED | Documented branch, delayed-slot, PC-relative load and control-register semantics form a coherent startup path. SPEC-005. |
| RQ-012 | Is a VxWorks symbol or module table present? | PARTIAL | Runtime markers and `taskSpawn` exist, but canonical names/record layout and references did not confirm a table. SPEC-006. |
| RQ-013 | How does code address the standard resource cluster? | PARTIAL | No exact big-endian file-offset or `FlashStartAddress + offset` reference was found; relative/indexed tables remain open. SPEC-006. |

A bare magic-byte occurrence never closes a question. Positive formats require structural validation; negative results are limited to the formats, address models and validators documented in Phoenix SDK.

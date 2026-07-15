# Research Questions

| ID | Question | Status after Session 008 | Evidence / target |
|---|---|---|---|
| RQ-001 | Does the principal BIN have a vendor container header? | CLOSED | Offset zero is executable SH-3 control flow, not a separate container header. SPEC-001, SPEC-005. |
| RQ-002 | One ELF, several executables or a flat image? | PARTIAL | A flat SH-3/VxWorks executable start is CONFIRMED; later internal module boundaries remain open. SPEC-001, SPEC-005. |
| RQ-003 | Which offsets are genuine segments? | PARTIAL | Startup is executable and the filler-bounded island contains a CONFIRMED browser-resource core plus post-cluster data; no vendor segment directory is known. SPEC-002, SPEC-006, SPEC-007. |
| RQ-004 | How do `CheckSum` and `CheckSum1`-`24` map to the image? | CLOSED | CRC32/IEEE of 25 consecutive 512 KiB chunks, final chunk truncated. SPEC-002. |
| RQ-005 | Are regions compressed with standard algorithms? | PARTIAL | All apparent gzip/xz/bzip2/zlib candidates failed complete-stream validation. |
| RQ-006 | Are standard graphics embedded? | CLOSED | Three JPEG and nine GIF89a resources, identical in CD1/CD3. SPEC-003. |
| RQ-007 | Are standard fonts embedded? | PARTIAL | Apparent TTF/OTF magics failed validation, but Session 008 confirms a sparse-row bitmap region with probable 1 bpp glyph-atlas semantics. SPEC-011. |
| RQ-008 | How are strings encoded and grouped? | PARTIAL | ASCII/UTF-16 inventory and domain markers are reproducible; tables remain unknown. |
| RQ-009 | Is navigation a distinct internal region? | OPEN | NAV/GPS markers exist; no bounded module yet. |
| RQ-010 | Known filesystem or proprietary table? | PARTIAL | No validated ROMFS/CRAMFS/SquashFS/UBIFS/JFFS2/ISO9660; proprietary layout remains possible. |
| RQ-011 | Is the entry point valid big-endian SH-3 code? | CLOSED | Documented branch, delayed-slot, PC-relative load and control-register semantics form a coherent startup path. SPEC-005. |
| RQ-012 | Is a VxWorks symbol or module table present? | PARTIAL | Runtime markers and `taskSpawn` exist, but canonical names/record layout and references did not confirm a table. SPEC-006. |
| RQ-013 | How does code address the standard resource cluster? | PARTIAL | Direct address models from Session 004 failed, and Session 005 found no complete fixed-width/stride island-relative or cluster-relative resource-start table under the tested models. Other indexed/runtime models remain open. SPEC-006, SPEC-007. |
| RQ-014 | Is the stable 1,588-byte pre-resource area a proprietary header? | CLOSED | It is a 1,587-byte HTML document followed by one separator byte. The HTML plus the 12-image cluster is byte-identical across CD1/CD3. SPEC-007. |
| RQ-015 | What are the `0x0C000000`-range runs after the image cluster? | PARTIAL | All 69 entries map in bounds. Run 0 and the descriptor select a confirmed relocated bitmap-like region; runs 1/3 lack exact target matches and remain unresolved. SPEC-008, SPEC-009, SPEC-011. |
| RQ-016 | What runtime base maps linked addresses to principal-image offsets? | CLOSED | `file_offset = runtime_address - 0x0C000000` is supported by two bounded MOV.L/JSR sequences in both releases, maps the base value to the confirmed entry, maps all 69 entries in bounds and is the only tested model with cross-version target matches. SPEC-009. |
| RQ-017 | Which subsystem owns the post-cluster address runs? | PARTIAL | Run 0 and the descriptor select a confirmed bitmap-like region; browser/glyph ownership is probable, but no direct renderer consumer identifies an owner. SPEC-010, SPEC-011. |
| RQ-018 | Does a normalized relocated descriptor graph surround the confirmed record block? | CLOSED | A nine-field normalized graph remains at block `-0x1FF4` and relocates by the same `0x4F0DC` in both releases. SPEC-010. |
| RQ-019 | Which code consumes the source table or descriptor graph? | OPEN | Exact absolute-word and PC-relative `MOV.L` probes found no consumer; bounded register/dataflow analysis is required. SPEC-010. |
| RQ-020 | Is the Session 006 target code, generic data or graphics? | PARTIAL | A 71,245-byte relocated sparse-row bitmap region is structurally confirmed; 1 bpp glyph-atlas semantics remain probable. SPEC-011. |
| RQ-021 | What end-to-end firmware operation can be stated from current evidence? | PARTIAL | SPEC-012 connects update selection, integrity, SH-3/VxWorks startup, runtime addressing and the browser/bitmap path while preserving navigation, storage and consumer gaps as OPEN/HYPOTHESIS. |

A bare magic-byte occurrence never closes a question. Positive formats require structural validation; negative results are limited to the formats, address models and validators documented in Phoenix SDK.

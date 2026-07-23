# SPEC-031 - Owner ingress and state-base provenance

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 021-022
- Related questions: RQ-059, RQ-060, RQ-062, RQ-063, RQ-064, RQ-065

## Purpose

Define a bounded method for testing static ingress to selected owner windows
and tracing memory-base expressions without asserting function boundaries,
object identity or runtime execution.

## Static ingress models

Phoenix scans two call forms:

- adjacent PC-relative `MOV.L` followed by same-register `JSR`;
- direct in-image `BSR`.

Both are tested against the exact owner start and every offset inside the
bounded owner window. Results remain syntactic because a complete executable
map is unavailable.

Absence applies only to these two forms. Computed jumps, non-adjacent indirect
calls, runtime callbacks, tables and external loaders remain outside the
negative result.

## Address-taken model

A candidate is a four-byte-aligned big-endian value in the runtime image range
whose normalized target lies inside a selected owner window.

Promotion requires at least one exact PC-relative long-load referrer. The
loaded register is followed for at most 16 instructions and classified as:

- `INDIRECT_CONTROL_TARGET`;
- `ARGUMENT_TO_OTHER_INDIRECT_CALL`;
- `MEMORY_BASE`;
- `OVERWRITTEN_BEFORE_MODELED_USE`;
- `NO_MODELED_USE_WITHIN_LOOKAHEAD`.

The fixed 16-word context around the load is compared against all
opposite-release PC-relative long loads. A bilateral selected-owner use is
established only when an exact opposite context also loads a target inside one
of the registered opposite owner windows.

## Memory-base expressions

For every bounded `mov.b`, `mov.w` or `mov.l` memory operand, Phoenix traces the
base register backward to:

- an entry argument;
- a constant;
- a call return;
- an in-image pointer;
- a memory load from another expression;
- an addition;
- an unsupported write, clobber or unresolved definition.

Expressions are canonicalized without concrete image addresses. Example:

```text
ADD(LOAD32[8](ENTRY:r4),CONST:64)
```

An entry argument is a runtime value. It is not a statically resolved base and
does not identify an object's creator or type.

## Cross-version comparison

Owner instructions use the complete normalized sequence alignment from
SPEC-030. A memory-base row is compared only when:

- its right instruction lies in a matching sequence block;
- the corresponding left instruction has the same base occurrence and base
  register.

Phoenix reports both exact canonical-expression equality and root-class
equality. Unaligned rows remain unknown.

## Session 022 status

- zero adjacent literal/JSR or BSR calls target an exact selected owner start;
- zero such calls enter any selected owner window from outside;
- one aligned PC-relative address-taken use occurs in each release;
- the two uses target different owner pairs and are not a bilateral selected
  owner use;
- Owner A aligns 17 memory-base rows with 17 equal root classes and 13 equal
  expressions; four expressions retain their roots while field constants
  increase by eight;
- Owner B aligns 19 rows with 19 equal expressions and root classes;
- all four owner profiles contain entry-argument-rooted state;
- each owner contains four load-rooted bases descending from entry argument
  `r4`;
- no selected-owner memory base is rooted in a static image pointer.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, relative owner
offsets, normalized shape hashes, canonical generated expressions, aggregate
counts and evidence statuses. They must not contain firmware or instruction
bytes, absolute runtime addresses, raw strings, local paths, map payloads or
extracted resources.

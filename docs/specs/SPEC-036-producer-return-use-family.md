# SPEC-036 - Producer return-use family

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 026-027
- Related questions: RQ-077-RQ-087

## Purpose

Define a bounded census and classification for every exact static use of the
single producer target pair registered by Session 026.

## Pointer-use gate

Phoenix accepts only aligned exact runtime-pointer words for the registered
target. Every PC-relative referrer is classified with a fixed 16-instruction
lookahead as:

- indirect control target;
- argument to another indirect call;
- memory base;
- overwrite or no modeled use.

Direct `BSR` targets and data-only aligned words are counted independently.
The result is a syntactic topology, not an executable map or runtime trace.

## Bilateral flow gate

Each sorted call pair must preserve:

1. the producer target relocation delta for literal, referrer, call and owner;
2. an equal normalized owner shape;
3. bilateral owner code gates;
4. equal producer `r4`-`r7` arguments;
5. an equal following-call signature and returned-object geometry.

Owner windows remain analysis anchors. Linear following-call selection does
not prove path dominance.

## Return-use classes

Session 027 defines:

- `RETURN_OBJECT_DYNAMIC_DISPATCH`;
- `RETURN_FORWARDED_TO_STATIC_HELPER`;
- `RETURN_NULL_TEST_WITHOUT_LINEAR_CALL`;
- `OTHER_LINEAR_RESULT_USE`.

Dynamic dispatch requires a shared `CALL_RETURN` vtable/receiver grammar with
the target field four bytes after the 16-bit receiver-adjustment field.

Static handoff requires a resolved next-call target and at least one argument
rooted in `CALL_RETURN`. Passing the value as an argument does not prove the
callee reads or stores it.

## Session 027 result

- 17 aligned target words and 18 PC-relative references per release;
- all 18 uses are indirect control targets;
- zero data-only target words and zero direct `BSR` targets;
- 18 bilateral flows in 17 unique exact code-gated owner pairs;
- 15 dynamic dispatches, two static handoffs and one null test;
- dynamic target fields `28` through `92` on an eight-byte grid;
- five complete `r4`/`r6` dispatches, including one new field-`60` context;
- two code-gated static helper pairs, zero equal target shapes and zero
  confirmed modeled entry-`r5` reads.

No producer implementation, object writer, static registration path or
selected-owner target edge is established.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, generated
expressions, normalized shape hashes, field geometry and aggregate counts.
They must not contain firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

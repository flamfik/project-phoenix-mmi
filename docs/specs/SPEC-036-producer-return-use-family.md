# SPEC-036 - Producer return-use family

- Version: 0.4
- Maturity: DRAFT
- Evidence: Sessions 026-030
- Related questions: RQ-077-RQ-099

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

## Session 028 exact-entry correction

The Session 027 static-handoff code gate establishes only a nearby prologue.
Session 028's stricter exact-entry gate rejects all four mapped handoff
targets because documented unknown/control-transfer/call evidence occurs
before a sufficiently early save-PR. The handoffs remain structural pointer
candidates; they are not validated code entries or registration helpers.
See SPEC-037.

## Session 029 local-prefix correction

Both handoff pairs begin with bounded runs of runtime-range words. Advancing
by the complete run produces strict, fully decoded entries with equal
cross-version normalized shapes. This corrects the exact local mapping, but
does not restore the Session 027 semantic label.

Direct CFG analysis proves that all four corrected callees ignore entry `r5`
on every modeled path. The two flow classifications are therefore refined
from `RETURN_FORWARDED_TO_STATIC_HELPER` to
`CALL_RETURN_PRESENT_IN_UNUSED_ENTRY_R5`. Registration or object consumption
through these two exact callee families is disproved; other dynamic paths
remain open. See SPEC-038.

## Session 030 correction

The two registered targets are members of complete PC-relative literal pools.
The code analyzed by Session 029 begins at each pool end, but no exact runtime
word or direct `BSR` targets those successors. They are not validated callees.

`CALL_RETURN_PRESENT_IN_UNUSED_ENTRY_R5` and the registration disproof are
therefore retained only as properties of the adjacent successor bodies, not
as classifications of the actual handoff flows. The flow targets and return
consumption return to `OPEN`. See SPEC-039.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, generated
expressions, normalized shape hashes, field geometry and aggregate counts.
They must not contain firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

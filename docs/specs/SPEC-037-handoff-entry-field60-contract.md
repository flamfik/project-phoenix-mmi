# SPEC-037 - Exact handoff entry and field-60 contract

- Version: 0.3
- Maturity: DRAFT
- Evidence: Sessions 006, 021, 027-030
- Related questions: RQ-085, RQ-086, RQ-088-RQ-099

## Purpose

Define the bounded rules for reassessing a runtime-pointer target as an exact
code entry and for promoting observable field-60 caller effects without
assigning an object type or method name.

## Documented decoder boundary

Phoenix may add an SH instruction family only when:

1. the family occurs in a registered bounded research window;
2. its encoding and semantics are present in the official Renesas SH-3
   software manual;
3. synthetic tests cover operand order and control-flow class;
4. unsupported encodings remain `unknown`.

Decoding an instruction does not classify its containing bytes as code.

## Strict exact-entry gate

A target passes the Session 028 strict gate only when:

- save-PR occurs within the first five decoded instructions;
- no unknown instruction precedes save-PR;
- no call precedes save-PR;
- no branch, conditional transfer, indirect transfer, return or trap precedes
  save-PR.

This is a conservative evidence gate, not a vendor ABI specification.
Failure means `NOT_VALIDATED_UNDER_STRICT_ENTRY_GATE`; it does not prove that
the runtime target is invalid.

A previous bounded-code gate that merely finds a nearby prologue must not be
reinterpreted as exact-entry validation.

## Entry-register use rule

Entry `r5` is a confirmed direct consumer only when a documented instruction
reads it before:

- explicit overwrite;
- caller-saved call clobber;
- unconditional or conditional control split;
- indirect branch, return or trap.

Delay-slot reads and writes are applied before the transfer. Unknown
instructions preserve a limit on any negative result.

## Field-60 structural contract

The bilateral contract is promoted when both releases independently show:

1. equal code-gated owner shapes;
2. zero unknown instructions in the bounded owner windows;
3. preservation of entry `r5` and `r6`;
4. a long-word zero store through each preserved entry pointer before the
   producer call;
5. reuse of those pointers as field-60 dispatch arguments;
6. `EXTU.B` normalization of dispatch `r0`;
7. return of that normalized value in `r0`.

These gates establish pointer-addressed stores and an unsigned-byte return.
They do not establish parameter names, object type, method identity, path
dominance or runtime equivalence.

## Selected-owner pointer probe

The bounded probe tests only exact aligned words:

```text
0x0C000000 + selected_owner_file_offset
```

inside each registered handoff window. The Session 006 address model is
explicitly bounded and is not assumed universal. Zero matches do not exclude
section-relative, encoded, computed, copied or runtime-created pointers.

## Session 028 result

- one fully decoded bilateral field-60 owner contract;
- two confirmed long-word zero stores through entry `r5/r6` per release;
- one confirmed unsigned-byte return normalization per release;
- zero strict handoff entry pairs;
- zero bilateral modeled handoff entry-`r5` consumers;
- zero exact selected-owner pointer pairs;
- no registration path or selected-owner target link.

## Session 029 correction

The Session 028 raw targets are not code entries because they begin with
short runtime-pointer-range prefixes. SPEC-038 defines a non-searching local
correction: advance by the complete maximal prefix, then reapply the strict
entry gate.

All four corrected entries pass that gate and form two bilateral normalized
code families. This is a mapping correction, not semantic promotion. Direct
CFG analysis finds no read of entry `r5` on any modeled path, so these two
callees disprove the proposed registration/consumer route through `r5`.
Loader/section semantics and universal mapping remain open.

## Session 030 correction

The Session 029 correction ends at the boundary of a complete literal pool;
it does not recover the runtime target. The strict code entries remain valid
as pool-end successors, but their entry-`r5` behavior cannot be assigned to
the unresolved handoff callees.

The field-60 contract itself is unchanged. Only the separate static-handoff
interpretation is corrected. See SPEC-039.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, mnemonic names,
aggregate counts, generated expressions and evidence statuses. They must not
contain firmware bytes, instruction bytes, absolute runtime addresses, raw
strings, local paths, map payloads or extracted resources.

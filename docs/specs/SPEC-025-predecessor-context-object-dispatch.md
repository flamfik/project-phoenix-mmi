# SPEC-025 - Bounded predecessor context and dynamic descriptor paths

- Version: 0.1
- Maturity: DRAFT
- Evidence: Session 016
- Related questions: RQ-037, RQ-040, RQ-042, RQ-043, RQ-044, RQ-045, RQ-046

## Purpose

Define how an unresolved Session 015 `JSR @Rn` may be revisited using bounded
predecessor context without inventing function boundaries, branch dominance,
vtable semantics or runtime targets.

## Input gate

A call enters this model only when:

- it belongs to a registered Session 015 node pair;
- both releases contain an unresolved indirect call at the same ordinal;
- the pair can be deduplicated by its two file-relative call-site offsets.

One-sided, reordered and unpaired calls remain outside the result.

## Context boundary

At most `0x100` predecessor bytes are decoded. The start is selected in this
order:

1. latest supported save-PR prologue after the latest return;
2. first position after the latest return and its delay slot;
3. hard backward limit.

Every report carries `function_boundary_asserted = false` and
`path_dominance_asserted = false`.

## Symbolic expression classes

Supported expressions are:

- entry arguments `r4`-`r7`;
- small constants;
- in-image pointers from exact PC-relative literals;
- register moves;
- immediate and register addition;
- 8/16/32-bit memory loads with explicit displacement;
- the return value in `r0` from a preceding call;
- explicit caller-saved clobber, unsupported-write, cycle and depth-limit
  states.

Unknown instructions never receive guessed semantics.

## Static target rule

A target is a contextual literal call target only if the complete expression
resolves in bounds in both registered images. This confirms the destination of
the observed `JSR`; it does not confirm a function boundary.

Child graph expansion is a separate gate. Both target windows must satisfy the
Session 015 bounded-code rule. Session 016 recovers two target pairs and
promotes zero new graph nodes because neither pair passes that second gate.

## Dynamic descriptor rule

A structural descriptor contract requires:

- equal normalized target paths across both releases;
- at least one explicit memory load;
- unresolved dynamic target status;
- equal receiver (`r4`) paths;
- equal delay-slot-aware selector constant when one is present.

The resulting status is
`CONFIRMED_CROSS_VERSION_DYNAMIC_DESCRIPTOR_STRUCTURE`. It must carry:

- `vtable_semantics_asserted = false`;
- `method_semantics_asserted = false`;
- the target and receiver memory paths;
- the terminal origin class, such as `CALL_RETURN`;
- any receiver path constants and selector value.

## Session 016 descriptor instance

Two call sites share one shape:

- terminal object origin: prior `CALL_RETURN`;
- target path: three 32-bit loads with outer field displacement `12`;
- receiver path: a 16-bit load through an address containing constant `8`;
- selector: `r5 = 3` from the call delay slot.

These are structural properties only. Field names, class identity, method role
and optical/media semantics remain open.

## Cross-domain promotion rule

No navigation-to-optical edge may be promoted unless a resolved target pair:

1. is in bounds in both releases;
2. passes the code gate in both releases;
3. matches an independently accepted optical node or target family;
4. retains compatible argument and result provenance.

Session 016 finds zero such edges.

## Publication contract

Reports may contain hashes, file-relative offsets, expression paths, widths,
field displacements, small constants, aggregate counts and bounded code-gate
metrics. They must not contain firmware or instruction bytes, absolute runtime
addresses, raw strings, local paths, map payloads or extracted resources.

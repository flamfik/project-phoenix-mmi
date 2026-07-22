# SPEC-024 - Bounded optical/navigation interprocedural call graph

- Version: 0.1
- Maturity: DRAFT
- Evidence: Session 015
- Related questions: RQ-025, RQ-026, RQ-036, RQ-037, RQ-040, RQ-041, RQ-042, RQ-043

## Purpose

Define how record pointers and navigation call targets may seed a conservative
cross-version SH graph without assigning unsupported function, class, sector or
buffer semantics.

## Seed classes

### Navigation seed

A navigation pair must already have `target_window_shape_equal = true` in the
Session 010 comparison. Duplicate target pairs are collapsed while occurrence
counts remain visible.

### Optical record seed

An optical pair starts from equal relative slots in paired registered record
neighborhoods. Both targets must be in bounds and independently pass the
bounded-code gate:

- known-instruction ratio at least `0.70`; and
- prologue plus return, return plus resolved call, or prologue plus resolved
  call.

Passing this rule yields
`CONFIRMED_RECORD_POINTER_PAIRED_BOUNDED_CODE`, not a function name or boundary.

## Bounded window

Decoding starts at the explicit seed and ends at the first explicit return plus
its delay slot, or after `0x180` bytes. The result always carries
`function_boundary_asserted = false`.

## Static target resolution

Accepted targets are limited to:

- in-image direct `BSR` destinations;
- `JSR @Rn` where backward register tracing reaches an in-image PC-relative
  literal without an unsupported write.

Field-loaded, computed and object/vtable targets remain
`UNRESOLVED_INDIRECT_CALL`.

## Argument and result contract

Candidate call arguments are `r4`-`r7`. Their origin classes include:

- `ENTRY_ARGUMENT`;
- `CONSTANT`;
- `IN_IMAGE_POINTER`;
- `MEMORY_FIELD` or `MEMORY_DEREFERENCE`;
- `CALL_RETURN`;
- `DERIVED_POINTER_OR_VALUE`;
- explicit clobber, unsupported-write and unresolved states.

The call delay slot participates in argument tracing. Result summaries record
local `r0` testing, capture, dereference, store and forwarding before the next
call. None of these fields alone proves buffer semantics.

## Cross-version edge rule

Calls pair only at the same ordinal when these properties agree:

- target-resolution status;
- `r4`-`r7` origin classes;
- local result-test, result-dereference and result-forwarding booleans.

Both targets must resolve in bounds. Duplicate edges from overlapping roots are
removed.

## Expansion limits

- maximum depth: `2`;
- maximum paired nodes: `128`;
- child expansion requires both targets to pass the bounded-code gate;
- object dispatch is never guessed.

## Sector-ABI promotion rule

A sector ABI cannot be promoted from a constant alone. At minimum, a paired
edge must show:

1. stable target and argument roles;
2. a plausible sector/count value;
3. independently traced destination-buffer provenance;
4. a result contract consistent across releases;
5. a validated link to optical service or the FLDB consumer.

Session 015 finds no paired `2048` argument and no cross-domain edge, so the ABI
and buffer owner remain `OPEN`.

## Publication contract

Reports may contain file-relative offsets, hashes, aggregate counts, fixed
anchor IDs, argument-role classes and small immediate values. They must not
contain firmware or instruction bytes, absolute runtime addresses, raw strings,
local paths, map payloads or extracted resources.

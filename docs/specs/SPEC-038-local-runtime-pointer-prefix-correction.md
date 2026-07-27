# SPEC-038 - Local runtime-pointer-prefix correction

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 006, 026-029
- Related questions: RQ-086, RQ-090-RQ-095

## Purpose

Define a conservative rule for testing whether one registered file-relative
target begins with a bounded runtime-pointer prefix followed by a code entry.
The rule is local to explicitly registered targets and must not be used as a
general executable scanner.

## Prefix grammar

For an aligned registered target:

1. read at most eight consecutive big-endian 32-bit words;
2. count the maximal leading run in the bounded runtime range beginning at
   the Session 006 base and extending for 16 MiB;
3. publish only the count and byte length, never the pointer values;
4. define the corrected entry as `target + prefix_bytes`.

The prefix is eligible only when it is non-empty and terminates before the
eight-word bound. An unaligned target, zero-length run or bound-exhausting run
is not corrected.

## Bilateral promotion gate

A CD1/CD3 pair is promoted only when both sides independently satisfy:

- a non-empty maximal prefix;
- the Session 028 strict exact-entry gate at the corrected entry;
- a fully decoded bounded body with a passing code gate;
- equal normalized shape and call/return counts across releases.

For a multi-pair family, all corrected pairs must also share one relocation
delta. No arbitrary forward search or nearest-prologue selection is allowed.

Passing this gate confirms only a local structural correction. It does not
identify a vendor loader record, section boundary, relocation format,
function descriptor, runtime equivalence or universal address map.

## Direct entry-`r5` liveness

The bounded direct CFG:

- begins with entry `r5` live;
- applies documented register reads and writes;
- executes a delay slot before the associated transfer;
- explores both direct conditional successors;
- does not follow calls and treats `r5` as caller-saved after their delay
  slots;
- rejects a complete negative conclusion when an unknown instruction,
  indirect transfer, external direct target or missing window successor is
  reachable.

Entry `r5` is ignored only when the CFG is complete and no modeled path reads
it while live. A read used to preserve or copy `r5` also prevents that
negative result.

## Negative-control rule

The registered Session 026 producer target pair is tested with the identical
prefix grammar. A zero-prefix result must remain `NOT_APPLICABLE`; the
analyzer may not scan forward for an unrelated code-looking entry.

## Session 029 result

- two of two registered handoff pairs pass the bilateral correction gate;
- prefix lengths are 3/4 and 2/3 words for CD1/CD3;
- both corrected pairs share a 322,532-byte relocation delta;
- all four corrected bodies are fully decoded;
- entry `r5` is ignored on every modeled path in both families;
- the two proposed registration/consumer paths are disproved under this
  bounded callee model;
- the producer negative control has zero prefix words on both sides.

The prefix's physical format and universal applicability remain open.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, prefix counts and
lengths, normalized shape hashes, mnemonic-derived aggregate counts and
evidence statuses. They must not contain firmware bytes, instruction bytes,
raw pointer values, absolute runtime addresses, raw strings, local paths, map
payloads or extracted resources.

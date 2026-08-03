# SPEC-030 - Bounded linkage-owner lineage

- Version: 0.1
- Maturity: DRAFT
- Evidence: Sessions 018-021
- Related questions: RQ-051, RQ-056, RQ-057, RQ-059, RQ-060, RQ-061

## Purpose

Define a reproducible method for grouping residual calls to an active
pointer-zero target, correlating the containing bounded windows across firmware
releases and reporting global prevalence without promoting those windows to
functions or assigning runtime semantics.

## Owner window

For a call seed, Phoenix examines at most 256 predecessor bytes. The start is:

1. the latest save-PR prologue after the latest return;
2. otherwise the instruction after the latest return delay slot;
3. otherwise the backward limit.

Forward decoding ends at the first return after the seed or after 384 bytes.
An accepted prologue owner must both start at the latest save-PR prologue and
pass the existing bounded-code gate.

`owner` means “bounded window containing the selected call.” It does not mean
function, method, class, task or subsystem.

## Exact-context target consensus

Each right-side residual call uses the fixed 16-word call-site signature
defined by SPEC-027. Exact left-side matches contribute a target vote only when
all matches for that signature select one left target. Promotion requires at
least two votes for the dominant target.

## Normalized owner sequence

Each decoded instruction becomes:

```text
(mnemonic, address-normalized operands, flow class, delayed flag)
```

Concrete hexadecimal addresses in operands become `<address>`. Sequence
similarity uses `SequenceMatcher` with automatic junk suppression disabled.

Every residual call must fall inside a matching block and its aligned
left-side instruction must be a registered call to the dominant left target.

## Pair promotion gates

### Confirmed pair

All of the following are required:

- every selected right call aligns to a dominant-target left call;
- the left owner is not already assigned;
- every selected right call has an exact context match in that left owner;
- sequence similarity is at least `0.95`.

### Probable pair

All of the following are required:

- every selected right call aligns to a dominant-target left call;
- the left owner is not already assigned;
- left and right windows have equal total call and return counts;
- sequence similarity is at least `0.75`;
- similarity exceeds the next candidate by at least `0.25`.

Other matches remain candidates. Sequence matching never establishes semantic
equivalence.

## Short target-shape gate

A selected left target may be described as a literal-backed short return shape
only when:

- at least four adjacent literal/JSR forms select it;
- its decoded window is at most 32 bytes;
- known-instruction ratio is at least `0.8`;
- it contains exactly one return;
- it contains no call.

This gate exists because a compact leaf-like target may correctly fail the
general prologue/call-oriented code gate. It does not assign function
semantics.

## Global census

The census includes calls whose target is a zero tail word of any
pointer-plus-zero run. It reports owner counts, code-gate counts, context-start
reasons, per-owner call/target histograms and exact normalized shape counts
among prologue-backed code-gated owners.

Cross-release exact-shape counts describe repeated syntax only. Semantic owner
classes and runtime execution remain unasserted.

## Session 021 status

- four residual CD3 calls group into two prologue-backed code-gated owners;
- two exact-context calls select one CD1 target;
- full-window alignment maps all four residual calls to four CD1 calls to that
  target;
- one owner pair is confirmed and one is probable;
- the CD1 target passes the short return-shape gate;
- 29 exact prologue-owner shapes occur in both releases;
- runtime writer, loader, initializer and owner semantics remain open.

## Publication contract

Reports may contain artifact hashes, file-relative offsets, aggregate counts,
normalized-shape hashes, thresholds, similarities and evidence statuses. They
must not contain firmware or instruction bytes, absolute runtime addresses,
raw strings, local paths, map payloads or extracted resources.

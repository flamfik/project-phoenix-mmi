# SPEC-023 - Global role-sensitive FLDB parser search

- Version: 0.1
- Maturity: DRAFT
- Evidence: Session 014
- Related questions: RQ-029, RQ-031, RQ-036, RQ-037, RQ-039, RQ-040

## Purpose

Define a reproducible promotion gate for firmware parser candidates without
treating numeric coincidence as format ownership.

## Input contract

- one registered flat big-endian SH principal image;
- the Session 010 navigation/optical context report;
- the media-side FLDB grammar from SPEC-018;
- no executable or vehicle access.

## Exact numeric roles

The value 36 is classified separately when it is:

- moved as an immediate;
- added to a register;
- used in a call delay slot or bounded call-argument preparation;
- used as the delay-slot step of a backward branch;
- merely present as a structure displacement.

Only the backward-loop-step role creates a record-width loop candidate.

## Candidate fields

Each candidate records:

- file-relative seed and loop boundaries;
- loop length and known-instruction ratio;
- stepped register and its load/store counts;
- best same-base header read/write offset sets;
- explicit endian-instruction count;
- bounded `0x220` and 2,048 literal counts;
- nearest registered context as proximity only;
- normalized and raw loop hashes;
- structural classification and publication-safety flags.

Instruction bytes, runtime addresses, raw strings and local paths are forbidden.

## Promotion rule

A candidate requires all of:

1. cross-version structural pairing;
2. a read-side 36-byte record loop;
3. at least three compatible header-field reads from one base;
4. explicit endian work or validated helper semantics;
5. verified optical-buffer provenance.

No weighted score may override a missing required signal.

## Negative classifications

- `PROBABLE_FIXED_RECORD_ARRAY_INITIALIZER`: the stepped base is written at
  least three times and never read inside the loop;
- `REJECTED_CALL_FIELD_OFFSET_NOT_RECORD_STRIDE`: 36 prepares call arguments,
  while the observed backward-loop step is different;
- `GENERIC_36_BYTE_LOOP_NOT_PROMOTED`: record-width loop exists without enough
  independent parser evidence;
- `NO_CANDIDATE_MET_PARSER_PROMOTION_GATE`: no cross-version pair satisfies the
  complete rule.

These are bounded results. They do not prove absence outside the documented
instruction idioms and windows.

## Cross-version pairing

Exact loops pair by normalized instruction shape. Raw loop SHA-256 equality is
reported independently. Navigation-band clusters use the confirmed Session 010
relocation delta and require a matching semantic signature; relocation alone is
not sufficient.

## Operational graph effect

Graph v7 adds a `CONFIRMED_BOUNDED_NEGATIVE` search node and a
`BOUNDED_NEGATIVE` edge to the `OPEN` parser node. It does not change the
optical-reader, parser, sector-ABI or dynamic-compatibility gaps to confirmed.

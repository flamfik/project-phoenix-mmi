# Session 028 - Handoff preludes and field-60 contract

- Date: 2026-07-27
- Objective: resolve the remaining documented instructions in the Session 027
  field-60 owner and reassess the two static handoff target mappings.
- Mode: read-only static analysis; firmware was never executed or modified.
- Status: COMPLETE for the three registered bounded windows.

## Safety boundary

The runner verifies the registered CD1/CD3 ISO hashes and the Session 003
principal-image hashes. It extracts only the two principal members into an
operating-system temporary directory and deletes them after analysis.

The scan is restricted to:

- the one Session 027 field-60 owner pair;
- the two Session 027 static handoff target pairs;
- two previously selected Session 021 owner offsets per release.

No unconstrained executable scan, firmware execution, resource extraction,
repacking or vehicle operation was performed.

## Decoder source and correction rule

The new instruction families are implemented from the official
[Renesas SH-3/SH-3E/SH3-DSP Software Manual](https://www.renesas.com/en/document/mas/sh-3sh-3esh3-dsp-software-manual?language=en).
Phoenix now decodes the documented indexed `MOV`, `MUL.L`, `MAC.L`,
`SHAD`/`SHLD`, `EXTU`/`EXTS` and `TRAPA` families needed by the three
bounded windows.

Unknown halfwords remain unknown. A documented decoding match is not evidence
that the underlying bytes are executable code.

Session 028 adds a stricter target-entry gate. A nearby save-PR prologue is no
longer sufficient: before that prologue, the mapped target may not contain an
unknown instruction, call or control transfer, and the save must occur within
the first five decoded instructions. This is a conservative analysis policy,
not a claim about the vendor ABI.

## Confirmed findings

### S028-01 - The field-60 owner pair is fully decoded

Both bounded owner windows now contain zero unknown instructions. Their
normalized owner shape and dynamic contract remain equal across releases.

The dynamic target remains:

```text
LOAD32[60](LOAD32[0](CALL_RETURN))
```

with the 16-bit receiver adjustment at field `56`. The target is still
memory-loaded and no concrete selected-owner address is established.

### S028-02 - The field-60 wrapper has a bilateral pointer contract

Before calling the Session 026 producer, both releases:

1. preserve entry `r5` and `r6` in callee-saved registers;
2. write a 32-bit zero through the pointer originally supplied in entry `r5`;
3. write a 32-bit zero through the pointer originally supplied in entry `r6`.

After the producer returns, those preserved pointers are reused as `r5` and
`r6` for the field-60 dynamic dispatch. This confirms two pointer-addressed
output/state initializations, but not their types, sizes beyond the observed
long-word stores or ownership.

### S028-03 - The dynamic result is an unsigned byte

In both releases the field-60 dispatch return in `r0` is passed through
`EXTU.B` and the zero-extended value is returned in `r0`.

Status:

```text
field60_unsigned_byte_return_pair = true
```

This establishes the observed return-width normalization, not the semantic
meaning of the value.

## Corrected and bounded-negative findings

### S028-04 - Neither handoff pointer validates as an exact code entry

The two Session 027 pointer pairs still have nearby prologues, but all four
exact mapped targets fail the stricter entry gate:

| Flow | CD1 save-PR delta | CD1 prelude | CD3 save-PR delta | CD3 prelude |
|---:|---:|---|---:|---|
| 12 | 16 bytes | 1 unknown | 20 bytes | 3 unknown, 2 calls |
| 13 | 10 bytes | 1 unknown, 1 transfer | 14 bytes | 2 unknown, 1 call, 2 transfers |

The current `file_offset = runtime_address - 0x0C000000` model was confirmed
only for bounded Session 006 structures and was never a universal mapping
claim. Session 028 therefore changes the handoff conclusion from
“code-gated static helper” to:

```text
static_handoff_exact_target_mapping =
  NOT_VALIDATED_UNDER_STRICT_ENTRY_GATE
```

The nearby code remains useful structural evidence, but it cannot validate
the exact pointer target.

### S028-05 - No registration or selected-owner edge is established

Before the first unresolved transfer, neither handoff pair contains a modeled
bilateral read of entry `r5`. Within each fixed `0x180`-byte handoff window,
the exact runtime-word model finds zero pointers to either selected Session
021 owner in both releases.

This is a bounded negative result. Computed, encoded, copied, loader-created
or runtime-created pointers were not tested.

## Operational graph v21

Graph v21 contains 45 nodes and 54 edges:

- 37 confirmed nodes;
- four probable nodes;
- two open nodes;
- nine bounded-negative edges.

It adds the confirmed bilateral field-60 structural contract and a
bounded-negative target-link edge. It does not add a selected-owner,
registration, parser, sector-read or buffer-owner edge.

## Phoenix SDK 0.26 deliverable

Session 028 adds:

- documented SH indexed transfer, multiply, dynamic-shift, extension and trap
  decoding;
- control-transfer-aware entry-register profiling;
- a strict exact-target entry gate;
- bilateral field-60 pointer-store and return-width analysis;
- a bounded selected-owner pointer probe;
- operational graph v21;
- a hash-gated runner and seven new unit tests.

The complete suite contains 121 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S028-01 | CONFIRMED, BOUNDED | Both field-60 owner windows are fully decoded and structurally equal. |
| S028-02 | CONFIRMED, STRUCTURAL | Both write zero through entry `r5/r6` pointers and reuse them for field-60 dispatch. |
| S028-03 | CONFIRMED, STRUCTURAL | Both normalize the dispatch result with `EXTU.B` and return it in `r0`. |
| S028-04 | OPEN, BOUNDED NEGATIVE | All four exact handoff mappings fail the strict entry gate. |
| S028-05 | OPEN, BOUNDED NEGATIVE | No bilateral entry-`r5` consumer, registration store or exact selected-owner pointer is established. |

## Next step

Session 029 should stop treating the Session 006 runtime-base relation as a
universal executable mapping. It should test a section-aware or loader-aware
runtime-to-file mapping around the two handoff pointers, then revisit the
field-60 target only if a concrete writer or selected-owner address can be
derived. No semantic promotion should occur from prologue proximity alone.

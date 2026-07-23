# Session 006 - Runtime address map and target correlation

- Date: 2026-07-15
- Objective: test explicit address models for the four post-cluster runs, map targets into both principal images and distinguish confirmed relocation evidence from unresolved semantics.
- Mode: read-only static analysis; firmware was never executed.
- Status: COMPLETE for the bounded runtime-base and cross-version target-correlation pass.

## Safety gates

Before analysis, the working tree was clean and the CD1/CD3 ISO SHA-256 values matched the artifact register. The runner independently re-verifies ISO and principal-image hashes, extracts only the selected members into an operating-system temporary directory and removes them after analysis.

The selected address model was not found by an unconstrained best-score search. Five models were declared in advance from raw file, METAINFO flash and observed runtime-range hypotheses. Code evidence was evaluated separately from cross-version target equality.

## Confirmed findings

### S006-01 - Runtime link base `0x0C000000`

Both releases contain two bounded, coherent PC-relative `MOV.L`/indirect `JSR` sequences that load `0x0C000000` and a call target from the same runtime range. The sequences have the same structural file offsets in CD1/CD3; the first maps runtime target `0x0C002410` to file offset `0x2410` in both.

Together with the confirmed executable entry at file offset zero, this supports:

```text
file_offset = runtime_address - 0x0C000000
```

Status: `CONFIRMED_BOUNDED_STATIC_MODEL`. This is not a universal claim for every word in the image.

### S006-02 - All 69 run entries map in bounds

Under the selected model, all 69 entries (65 unique) are four-byte aligned and map inside both principal images. One maps exactly to the image entry; the remaining 68 map before the browser-resource island.

The raw-file and METAINFO-flash models map zero entries in bounds. The two runtime-base variants shifted by `0x60000` produce no exact cross-version 4/16/64-byte target matches. Only `0x0C000000` produces 21 exact target pairs.

### S006-03 - Run 0 contains a relocated record block

Twenty of the 21 run-0 entries use the dominant address delta `0x4F0DC`. After duplicate removal, the targets form 16 consecutive 16-byte records. The 256-byte block at CD1 offset `0xAC3DC` is byte-identical to the block at CD3 offset `0xFB4B8`.

This is sufficient to mark the run-0 subset `CONFIRMED_RELOCATED_RECORD_BLOCK`. The record schema and owner remain unknown.

### S006-04 - Run 2 contains an image-entry anchor

One run-2 value is exactly the runtime base and maps to file offset zero in both versions. Its 64-byte target windows match because the entry prefix is already confirmed identical. The other two run-2 targets are unresolved.

## Deliberately unresolved findings

### S006-05 - Runs 1 and 3 are not promoted

Runs 1 and 3 map fully in bounds and retain regular alignment, but none of their paired targets match at 4, 16 or 64 bytes. They remain `MAPPED_WITHOUT_EXACT_CROSS_VERSION_TARGET`; mapping alone is insufficient to prove a record type.

### S006-06 - Browser ownership is not confirmed

No mapped target falls inside the HTML/image core or the post-cluster part of the browser-resource island. The tables are stored there, but their targets point earlier in the principal image. This does not identify which code or subsystem owns them.

## Phoenix SDK 0.4 deliverable

Session 006 adds `phoenix_mmi.runtime_map` with:

- five explicit, reproducible address models;
- bounded `MOV.L`/`JSR` link-base evidence;
- in-bounds, alignment and semantic-region summaries;
- cross-version 4/16/64-byte target-window comparisons;
- relocated fixed-stride record-block confirmation;
- a registered-ISO Session 006 runner;
- three synthetic tests, bringing the suite to 18 tests.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S006-01 | CONFIRMED, BOUNDED | `0x0C000000` is the runtime link base for the tested structures. |
| S006-02 | CONFIRMED | All 69 entries map in bounds and four-byte aligned under that model. |
| S006-03 | CONFIRMED | Run 0 addresses one byte-identical relocated 16-record block. |
| S006-04 | CONFIRMED, PARTIAL | Run 2 contains the image-entry anchor; its other targets remain unresolved. |
| S006-05 | NOT CONFIRMED | Runs 1 and 3 have no exact paired target windows. |
| S006-06 | NOT CONFIRMED | The owning subsystem is not identified. |

## Reproduction

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
python tools/session006/analyze_runtime_address_map.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session006 \
  --public-output research/firmware-5570/session006
```

## Limits

- Code probes are bounded to the first `0x2000` bytes and use a deliberately partial SH-3 decoder.
- A valid address mapping does not distinguish executable code, constants, tables or mutable data.
- Exact relocated records do not reveal their schema or owning module.
- Lack of exact target equality in runs 1/3 does not disprove pointer semantics; version-specific data may legitimately differ.
- No firmware was executed, modified, repacked or installed.

## Recommended Session 007

Trace referrers to the confirmed 256-byte record block and to the four post-cluster source runs. Use exact PC-relative literal computation, bounded SH-3 control-flow context and cross-version structural agreement. Owner labels must require at least two independent signals; otherwise they remain unresolved.

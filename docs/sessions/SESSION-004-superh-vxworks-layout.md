# Session 004 - SuperH/VxWorks executable layout

- Date: 2026-07-15
- Objective: confirm the principal-image startup, map bounded PC-relative/absolute references, probe VxWorks tables and correlate the standard resource cluster with structural boundaries.
- Mode: read-only static analysis; firmware was never executed.
- Status: COMPLETE for the bounded entry-flow and resource-island pass.

## Artifact verification

The runner verified the registered CD1/CD3 ISO SHA-256 values and the principal-image SHA-256 values recorded by Session 003. Selected members existed only in an operating-system temporary directory and were removed after analysis.

## Confirmed findings

### S004-01 - Executable code starts at offset zero

The first instruction is a coherent big-endian SH-3 delayed branch to offset `0x8`. Its delay slot is `nop`. The reached code performs documented PC-relative loads, writes the status register, initializes GBR and branches over the Wind River banner at offset `0x20`.

This closes RQ-001: the principal image does not begin with a separate vendor container header. It begins with executable code.

### S004-02 - The entry prefix is identical; later startup data differs

The control-flow pass reaches 790 instruction offsets through `0xFEE` in both images and produces equal first 48 decoded records plus equal aggregate flow counts. The byte-identical entry prefix is 782 bytes. Across the 4,080-byte reached range, 177 bytes differ, beginning at `0x30E` and ending at `0xEBF`.

| Metric | CD1 / 5150 | CD3 / 5570 |
|---|---:|---:|
| Reached instruction offsets | 790 | 790 |
| Unconditional branches | 31 | 31 |
| Conditional branches | 48 | 48 |
| Indirect calls | 68 | 68 |
| Returns | 1 | 1 |
| PC-relative literal loads | 198 | 198 |
| Unknown decoded families | 157 | 157 |

The equal metrics do not prove that every later instruction is semantically equal. Session 004 records both region hashes and the bounded byte-difference summary.

### S004-03 - Resource island boundary

The 12 validated JPEG/GIF resources occupy the same relative position inside a zero-filler-bounded island in both versions. The cluster starts 1,588 bytes after the preceding filler. The resource bytes and 13,672-byte cluster length are identical; the surrounding island is 20 bytes longer in 5570.

This promotes the area from an entropy/filler hypothesis to a `PROBABLE_RESOURCE_ISLAND`. A vendor segment table is still not known.

### S004-04 - Direct resource addresses were not found

Exact big-endian 32-bit values were tested for resource starts and cluster boundaries as raw file offsets and as `0x60000 + offset`. No candidate occurred in either image. The result is bounded: relative/indexed offsets and runtime-created pointers remain possible.

### S004-05 - No VxWorks symbol/module table is confirmed

Fixed VxWorks/Wind River evidence remains present. Of the canonical name probes, only `taskSpawn` occurs, with no validated reference chain. The evidence is insufficient to label any region a VxWorks symbol or module table.

## Phoenix SDK 0.2 deliverable

Session 004 adds:

- `phoenix_mmi.superh`: dependency-free big-endian SH-3 branch, delayed-slot, PC-relative literal and selected data-movement decoding;
- `phoenix_mmi.layout`: bounded startup tracing, address-model classification, VxWorks probes, exact resource-reference search and filler-bounded island correlation;
- a direct registered-ISO Session 004 runner;
- four new synthetic tests, bringing the suite to 12 tests.

No synthetic fixture contains Audi firmware. Public JSON contains only hashes, offsets, decoded semantics, fixed-name probes and aggregate results; it contains no instruction bytes, firmware payload, resource bytes or arbitrary raw strings.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S004-01 | CONFIRMED | Executable big-endian SH-3 control flow starts at file offset zero. |
| S004-02 | CONFIRMED | The 782-byte entry prefix and early decoded trace are identical; the later reached range differs in 177 bytes. |
| S004-03 | PROBABLE | The filler-bounded non-zero area is a semantic resource island. |
| S004-04 | CONFIRMED | No exact resource address exists under the two tested big-endian models. |
| S004-05 | NOT CONFIRMED | A VxWorks symbol/module table was not identified. |

## Reproduction

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
python tools/session004/analyze_executable_layout.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session004 \
  --public-output research/firmware-5570/session004
```

## Limits

- The decoder is intentionally partial; 157 reached halfwords remain `unknown`.
- Indirect calls are recorded but their targets are not inferred.
- The trace begins only from the confirmed entry point and does not map all firmware code.
- Absence of canonical VxWorks symbol names does not prove that symbols were omitted.
- No firmware was executed, modified, repacked or installed.

## Recommended Session 005

Analyze the resource island wrapper with cross-version differential methods. The immediate targets are the stable 1,588-byte prefix before the first validated image, the 20-byte island growth in 5570, relative-offset tables and record-size/endianness hypotheses. This can identify a proprietary resource directory without exporting any resource bytes.

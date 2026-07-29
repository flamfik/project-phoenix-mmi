# Session 060 - integrated firmware evidence map v2

- Date: 2026-07-29
- Objective: integrate Sessions 051-059 with operational graph v42.
- Mode: evidence synthesis only.
- Status: COMPLETE as a partial model; M1 remains open.

## Updated operating model

```text
ISO update media
  -> METAINFO component and version selection
  -> principal SuperH image
       -> startup/runtime code
       -> embedded XIM2 display-resource set
            -> 84 strict resources shared by 5150 and 5570
            -> external YIM relationship confirmed for one unique asset
            -> renderer and write-integrity owner still open
  -> peripheral and language payloads
       -> validated addressed record families
       -> LOD speech-language family
            -> repeatable fill topology
            -> cross-language exact reuse
            -> record/length/address decoder still open
  -> transfer, flash/EEPROM migration, restart and verification
```

## Graph v52

The new graph contains 86 nodes and 101 edges. Sessions 051-059 add bounded
integrity, resource-containment, alignment and shared-region evidence without
inventing a renderer, LOD decoder or write path.

## Milestone and safety

```text
display resource read model = CONFIRMED_PARTIAL
speech payload read model   = STRUCTURAL_ONLY
M1 Firmware Archaeology     = PARTIAL_NOT_COMPLETE
safe_mutation_ready         = false
```

## Deliverables

- SPEC-068;
- RQ-216-RQ-220;
- `firmware-evidence-map-v2.json`;
- operational graph v52;
- Phoenix SDK 0.57.0.

## Recommended next step

Session 061 should locate bounded static references to validated embedded XIM2
records and the two `.yim` suffix markers, using target/control evidence. In
parallel, LOD work should prioritize consumer discovery over wider statistical
searches; more blind format guessing is not justified.

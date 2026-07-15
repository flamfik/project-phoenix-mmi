# SPEC-006 - Resource island and VxWorks table probes

- Version: 0.1
- Maturity: ALPHA
- Evidence: Sessions 003-004, registered CD1/CD3 principal images
- Related questions: RQ-003, RQ-012, RQ-013

## Filler-bounded resource island

The 12 validated standard resources sit in a compact non-zero island between two long zero-filled regions.

| Release | Island start | Island end | Island length | Cluster offset in island |
|---|---:|---:|---:|---:|
| MMI 5150 | `0x82B9B8` | `0x830994` | 20,444 | 1,588 |
| MMI 5570 | `0x7DBEAC` | `0x7E0E9C` | 20,464 | 1,588 |

The encoded 12-resource cluster is 13,672 bytes in both releases and moves by `-0x4FB0C`. The complete island grows by 20 bytes in 5570, while the resource cluster begins at the same relative position.

`PROBABLE`: this is a semantic resource island containing a stable resource cluster plus version-dependent wrapper/table data. It is not yet a confirmed vendor segment.

## Reference search

Phoenix tested exact big-endian 32-bit references for every resource start plus the cluster start/end under two models:

- raw file offset;
- `FlashStartAddress + file_offset`.

Neither image contains an exact candidate under those models. This does not exclude relative offsets, indexes, runtime-built addresses or a proprietary resource table.

## VxWorks probes

Both releases contain one Wind River copyright banner, five `VxWorks` markers, seven `Wind River` markers and one `taskSpawn` probe. Probes for `sysSymTbl`, `symTbl`, `usrInit`, `usrRoot`, `sysInit`, `kernelInit`, `moduleLib` and `loadModule` did not confirm a canonical table. No validated record layout or reference chain was found.

Status: `NOT_CONFIRMED`, not absent. Stripped names or proprietary table layouts remain possible.

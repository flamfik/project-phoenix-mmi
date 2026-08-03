# SPEC-003 — Embedded standard resources and negative signatures

- Version: 0.2
- Maturity: ALPHA
- Evidence: Session 003, both registered principal images
- Related questions: RQ-005–RQ-010

## Validated resource cluster

Both images contain the same 12 byte-identical standard resources in one compact cluster:

- 3 JPEG images;
- 9 GIF89a images;
- 12/12 SHA-256 values shared between 5150 and 5570;
- identical dimensions and encoded lengths.

| Artifact | Cluster start | Cluster end | Span |
|---|---:|---:|---:|
| CD1 / 5150 | `0x82BFEC` | `0x82F554` | 13,672 bytes |
| CD3 / 5570 | `0x7DC4E0` | `0x7DFA48` | 13,672 bytes |

The byte content is unchanged but relocated by `-0x4FB0C` in 5570. Individual dimensions, lengths and hashes are stored in the public summaries; resource bytes are not exported.

## Structurally rejected candidates

Magic-byte scanning also produced apparent PNG, BMP, TrueType, OpenType, ISO9660, JFFS2, bzip2 and zlib hits. Surrounding-header or complete-stream validation rejected all of them. No validated embedded ELF, standard filesystem, font or compression stream was found.

This is a bounded negative result. It does not exclude proprietary compression, custom font/resource tables or filesystems without a standard on-disk magic.

## Candidate region evidence

Nine long `0x00` filler runs occur in each image, concentrated around the resource cluster. The corresponding pattern is similar but relocated. Entropy transitions plus filler boundaries are useful analytical candidates, but they remain `HYPOTHESIS` until code or a table references them.

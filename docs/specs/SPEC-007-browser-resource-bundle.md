# SPEC-007 - Embedded browser-resource bundle

- Version: 0.1
- Maturity: ALPHA
- Evidence: Session 005, registered CD1/CD3 principal images
- Related questions: RQ-003, RQ-006, RQ-013, RQ-014

## Layout

The filler-bounded island contains a byte-identical 15,260-byte core in MMI 5150 and MMI 5570:

```text
island + 0x0000   HTML document (1,587 bytes)
island + 0x0633   one-byte separator
island + 0x0634   12 validated images (13,672 bytes)
island + 0x3B9C   release-dependent post-cluster data
```

The core SHA-256 is `b8e3e475a1cae4da553e2f016c34ae4cf06838192f19a06fb85c37304add2581` in both releases. The pre-resource area and resource cluster also have equal hashes when considered separately.

## HTML inventory

Three complete HTML documents were structurally parsed in each island. Corresponding documents are byte-identical across CD1/CD3.

| Island-relative offset | Length | DOCTYPE | Image references |
|---:|---:|---|---:|
| `0x0000` | 1,587 | no | 10 |
| `0x3C48` | 564 | yes | 0 |
| `0x3E80` | 187 | yes | 0 |

The main document has ten image references: seven with GIF extensions and three with JPEG extensions. The validated binary cluster contains nine GIF89a and three JPEG resources. The count difference is two; it does not by itself prove that either resource is unused.

The public analyzer records only hashes, offsets, tag counts and reference classes. Raw HTML and URIs are never included.

## Relative-directory tests

Phoenix tested complete resource-start tables using:

- island-relative and cluster-relative values;
- 16-bit and 32-bit widths;
- big- and little-endian encodings;
- fixed strides of 2, 4, 8, 12 and 16 bytes;
- both the pre-resource and post-cluster regions.

No full candidate was found in either release. This is a bounded negative result: variable-width records, transformed values, indexes, hashes and runtime-built associations remain possible.

## Post-cluster data

The post-cluster area is 5,184 bytes in MMI 5150 and 5,204 bytes in MMI 5570. It contains the second and third HTML documents plus the structured value runs described by SPEC-008. Its release-dependent contents mean that the complete island is not one immutable asset archive.

# Session 005 - Browser-resource bundle and post-cluster tables

- Date: 2026-07-15
- Objective: identify the stable pre-resource area, test bounded resource-directory models and explain the 20-byte CD1/CD3 island delta.
- Mode: read-only static analysis; firmware was never executed.
- Status: COMPLETE for HTML/resource structure and the bounded table-model pass.

## Artifact verification

The runner verified the registered CD1/CD3 ISO SHA-256 values, then verified each extracted principal-image SHA-256 against Session 003. Selected members existed only in an operating-system temporary directory and were removed after analysis.

## Confirmed findings

### S005-01 - The 1,588-byte prefix is HTML plus a separator

The first 1,587 bytes of the island form a complete HTML document. One separator byte follows it, placing the first validated image at island offset `0x634` (1,588). This closes RQ-014 and replaces the earlier unknown-wrapper hypothesis.

The public report retains only the document hash, length, structural tag counts and reference-class counts. It does not publish the document or its URIs.

### S005-02 - A stable 15,260-byte browser-resource core

The main HTML document plus the 12-resource image cluster is byte-identical in MMI 5150 and MMI 5570.

| Property | CD1 / 5150 | CD3 / 5570 |
|---|---:|---:|
| Island start | `0x82B9B8` | `0x7DBEAC` |
| Core end | `0x82F554` | `0x7DFA48` |
| Core length | 15,260 | 15,260 |
| Image cluster length | 13,672 | 13,672 |
| Core SHA-256 | `b8e3e475...2581` | `b8e3e475...2581` |

The main HTML document contains ten image references by extension (seven GIF and three JPEG), while the validated binary cluster contains twelve images (nine GIF89a and three JPEG). The difference is a count observation, not proof that two images are unused.

### S005-03 - Three HTML documents are embedded

Two additional, smaller HTML documents occur after the image cluster at island offsets `0x3C48` and `0x3E80`. All three corresponding document hashes are equal across CD1/CD3. This confirms that the area is an embedded browser-resource bundle rather than a graphics-only cluster.

### S005-04 - Simple relative resource directories were not found

Phoenix tested complete island-relative and cluster-relative resource-start tables with 16/32-bit big/little-endian entries and fixed strides `2, 4, 8, 12, 16`. Neither the pre-resource nor post-cluster region contained a complete candidate in either release.

This rejects only the tested fixed-width/fixed-stride models. It does not exclude indexed, transformed, variable-record or runtime-built associations.

### S005-05 - Four post-cluster value runs correlate across releases

The post-cluster regions contain four runs of big-endian values in `0x0C000000`-`0x0D000000`. Their count signature is `[21, 9, 3, 36]` in both releases. Two runs have one relocation-like delta for every member; the other two have a dominant delta with one exception.

The run starts shift by `0, +4, +8, +20` bytes from CD1 to CD3. The distributed growth explains why the final region is 20 bytes longer, but not what the inserted fields mean.

Runtime pointer-table semantics are `PROBABLE`, not confirmed. Target ownership and the runtime load base remain unknown.

## Phoenix SDK 0.3 deliverable

Session 005 adds `phoenix_mmi.resource_bundle` with:

- complete embedded-HTML discovery and publication-safe structural summaries;
- browser-resource core hashing and CD1/CD3 equality checks;
- bounded fixed-width/stride relative-offset table tests;
- big-endian address-range run detection and cross-version delta comparison;
- a direct registered-ISO Session 005 runner;
- three synthetic tests, bringing the suite to 15 tests.

Synthetic fixtures contain no Audi firmware. Public JSON includes no firmware bytes, resource bytes, raw HTML, raw URIs or arbitrary extracted strings.

## Evidence status

| ID | Status | Claim |
|---|---|---|
| S005-01 | CONFIRMED | The pre-resource area is one complete HTML document plus one separator byte. |
| S005-02 | CONFIRMED | The 15,260-byte main HTML/image core is byte-identical in CD1/CD3. |
| S005-03 | CONFIRMED | Each island contains three complete HTML documents with equal cross-version hashes. |
| S005-04 | CONFIRMED, BOUNDED NEGATIVE | No complete resource-start directory exists under the tested width, endianness and stride models. |
| S005-05 | PROBABLE | Four post-cluster runs are relocation-like runtime pointer tables. |

## Reproduction

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
python tools/session005/analyze_resource_bundle.py \
  MMI-5570-4L0.998.961-cd1-3.iso \
  MMI-5570-4L0.998.961-cd3-3.iso \
  --output research/firmware-5570/work/session005 \
  --public-output research/firmware-5570/session005
```

## Limits

- HTML discovery is a tolerant structural parser, not an implementation of the embedded browser.
- Resource references are classified by extension; names and URIs are intentionally not published.
- The two-resource count difference does not establish reachability or usage.
- The pointer detector uses an empirically selected address range and does not prove pointer semantics.
- No runtime load map, target owner, record schema or code reference chain is known yet.
- No firmware was executed, modified, repacked or installed.

## Recommended Session 006

Map the four post-cluster run targets back into the principal image under explicit runtime-base hypotheses. Classify each target as startup code, other executable data, browser HTML/resource data, filler or out-of-image. Cross-version relocation deltas should then be tested against matched target hashes and nearby code references. This is the shortest path to deciding whether the runs are genuine pointer tables and who owns the browser-resource bundle.

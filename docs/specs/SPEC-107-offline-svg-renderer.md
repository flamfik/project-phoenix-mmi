# SPEC-107 - Offline SVG renderer

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 098
- Related questions: RQ-383-RQ-386

The renderer consumes only the typed Phoenix information architecture, bounded
layout and original theme bundle. It emits deterministic static SVG at
480x240. The public preview set contains one file for each of five screens and
records every SHA-256 digest in its manifest.

Scripts, raster embeddings, links, data URIs, external references and imported
assets are prohibited. SVG output is a host research artifact and must not be
described as firmware-renderer-compatible.

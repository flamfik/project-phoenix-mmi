# SPEC-102 - Offline UI constraint contract

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 093
- Related questions: RQ-363-RQ-365

The M5 prototype uses a fixed 480x240 landscape viewport and five abstract
focus actions: activate, back, next, previous and home. These names are a
host-side interaction vocabulary, not a recovered hardware mapping.

Every interaction path must expose focus and remain usable without touch or a
pointer. Only original or synthetic assets are allowed. Pixel layout, display
safe area, hardware input codes, renderer compatibility and numeric target
CPU, memory or frame budgets remain explicitly unestablished.

# Session 096 - Bounded 480x240 UI layout

- Date: 2026-07-29
- Objective: allocate deterministic integer rectangles for every screen.
- Status: COMPLETE; M5-X3 PASS; M5 3/8; operational graph v88.

The layout engine creates five 480x240 screen layouts and 16 entry rectangles.
Header, content and footer regions remain inside the viewport. All coordinates
are integers, the minimum entry height is 34 pixels and the catalog contains
zero overlaps and zero overflows.

This is an independently authored host layout. Resource geometry supports the
viewport size but does not establish display safe area, firmware pixel layout,
font rendering or display-controller behavior.

Authoritative report:
`research/milestones/m5/session096/bounded-layout-catalog.json`.

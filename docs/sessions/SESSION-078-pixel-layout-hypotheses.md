# Session 078 - Pixel-layout hypotheses

- Date: 2026-07-29
- Objective: compare bounded 16-bit pixel interpretations.
- Status: COMPLETE; M3-X3 PASS; operational graph v70.

Eight fixed RGB/BGR 565 and XRGB/XBGR 1555 big/little-endian candidates were
evaluated with structural smoothness and unused-bit metrics. Big-endian 1555
candidates rank first under this heuristic, but the evidence does not select
a color order or pixel layout. The only confirmed contract is a 16-bit pixel
unit for the strictly decoded rasters.

Authoritative report:
`research/milestones/m3/session078/pixel-layout-hypotheses.json`.

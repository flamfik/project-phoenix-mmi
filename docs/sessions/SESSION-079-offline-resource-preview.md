# Session 079 - Format-explicit offline preview

- Date: 2026-07-29
- Objective: render candidate interpretations without executing firmware.
- Status: COMPLETE; M3-X4 PASS; operational graph v71.

Phoenix SDK now renders bounded PPM previews only when the caller names an
explicit pixel layout. Four 480x240 candidate previews were generated in the
private local work area. No preview, raster, content hash or extracted
resource is committed. Previewing a hypothesis does not confirm it.

Authoritative report:
`research/milestones/m3/session079/offline-preview-summary.json`.

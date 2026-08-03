# SPEC-105 - Bounded 480x240 UI layout

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 096
- Related questions: RQ-375-RQ-378

Every `ScreenLayout` uses the fixed 480x240 prototype viewport and partitions
it into bounded header, content and footer rectangles. Entry rectangles use
integer coordinates, retain model order, remain within content and have a
minimum height of 34 pixels.

The complete catalog has five layouts, 16 entry rectangles, zero overlaps and
zero overflows. This contract describes original host geometry only; it does
not reconstruct the firmware layout or establish display safe area.

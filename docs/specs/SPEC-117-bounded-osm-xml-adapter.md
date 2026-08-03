# SPEC-117 - Bounded OSM XML adapter

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 108
- Related questions: RQ-425-RQ-429

The adapter accepts OSM XML 0.6 up to 1,048,576 bytes and 10,000 top-level
elements. DTD and entity declarations are prohibited. Nodes require valid
coordinates; routable highway ways require at least two resolved references
and unique tags. Relations, turn restrictions, lanes, areas and proprietary
target output are not implemented.

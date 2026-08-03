# SPEC-120 - M7 hardware-validation contract

- Version: 1.0
- Maturity: STABLE
- Evidence: Session 111
- Related questions: RQ-440-RQ-443

M7 separates offline SDK preparation from a future human-controlled isolated
bench. The SDK cannot power hardware, execute target firmware, transmit
vehicle or MOST messages, write storage, alter Component Protection or create
installable artifacts. A physical candidate requires all ten prerequisites,
and any one of eight stop conditions terminates the plan.

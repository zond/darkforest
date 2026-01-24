# Design vs Implementation Review Findings

Findings from protocol-security-architect and embedded-rust-engineer reviews comparing docs/design.md against the implementation.

## High Priority

*None remaining.*

## Medium Priority

*None remaining.*

## Low Priority

### DATA message retries not implemented
**Source:** Embedded reviewer (2026-01-24)

Design doc shows request/response retry pattern for DATA messages, but only LOOKUP has retries.

**Impact:** DATA messages can be lost without notification to application.

### Sequence number persistence not implemented
**Source:** Embedded reviewer (2026-01-24)

Design doc lists three options for seq recovery after reboot. Implementation doesn't persist.

**Impact:** 12-hour delay after reboot before PUBLISH works (acceptable per design doc).
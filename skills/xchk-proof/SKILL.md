---
name: xchk-proof
description: Fetch verifiable evidence about this agent's own conduct — the coverage lamp, a review's dual-sealed proof file, or an incident package for a time window. Use when the user asks "prove it", "show the audit trail", "what did the agent do", or wants evidence for an auditor or insurer.
---

# Produce proof, not prose

When asked what you did or whether you are covered, the answer is a verifiable
artifact, never just your own account — a self-report is exactly what the
dashcam exists to make unnecessary.

## The three artifacts
- **Coverage now**: the `xchk` MCP server's `xchk_status` tool → plate, run,
  lamp. Quote the lamp word as reported; never upgrade it in the retelling
  (ACCOUNTED is not COVERED).
- **One review**: GET /api/interchange/receipts-mine/:id/proof (owner auth) →
  self-verifying HTML of that round-trip, both seals, offline recompute.
- **A time window**: the incident package from the dashcam panel (or
  /api/agents/:id/incident-package) → records, seals, ceremonies, host chain,
  reconciliation verdict, registry signature; verifies offline.

## Rules
Hand the user the FILE, state where it verifies (offline, any browser), and
if any lamp is not green, say the actual rung and why — a non-green word in
your own evidence is information, never something to explain away.

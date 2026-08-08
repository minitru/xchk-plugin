---
name: xchk-adopt
description: Adopt this host's agents under xChk accountability — check coverage state, register the agent for a license plate, and install the enforcement gate for this harness. Use when the user asks about xchk, agent licensing, coverage, adoption, the dashcam, or accountability for agent actions.
---

# Adopt this agent under xChk

xChk is the accountability layer for autonomous agents: per-action authorization
against a license grant, a tamper-evident + omission-evident action record (the
"dashcam"), human-approval ceremonies for consequential actions, and coverage
evidence suitable for insurers.

**Grade honesty — read this first.** Presence of this package is NOT coverage.
There are two grades:

- **enforcement-grade** — a gate is intercepting tool execution (Claude Code:
  this plugin's PreToolUse hook; Hermes: the native Python plugin). Actions are
  authorized and recorded. Only this grade can reach COVERED.
- **bootstrap-grade** — this portable package alone (skills + MCP status). It
  can see and explain, but intercepts nothing.

Never describe a bootstrap-grade host as covered, monitored, or protected.

## Steps

1. **Check current state.** Call the `xchk` MCP server's `xchk_status` tool.
   It reports whether a config exists (`~/.xchk/claude.json` or the Hermes
   profile env), the plate, the current run, and the coverage lamp.

2. **If no xChk config exists**, the agent is unregistered. Send the user to
   https://in.xchk.io to register (KYC + license grant) — registration is a
   human act, never something the agent does for them.

3. **Install the enforcement gate for this harness:**
   - **Claude Code:** enabling this plugin IS the gate — the PreToolUse hook in
     `hooks/hooks.json` authorizes and records every gated tool call. Confirm
     `~/.xchk/claude.json` holds the API key; if a legacy curl-install exists in
     `~/.claude/settings.json`, keep exactly ONE wiring active (adopt, don't
     duplicate — two hooks would double-record one action).
   - **Hermes:** this portable package CANNOT intercept (Portable Agent
     Plugins v1 has no middleware class). Install the native gate:
     `curl -fsSL https://in.xchk.io/examples/hermes-attestation-guardrails/hermes-xchk.sh | bash -s -- setup --profile <name>`
     Until that runs, this host is bootstrap-grade.

4. **Verify honestly.** Re-run `xchk_status`. Enforcement-grade shows a run
   reference and a recording chain that advances when a tool call executes.
   If the lamp is not green, report the actual rung (RECONCILING, ACCOUNTED,
   NO ACCOUNTING YET, MANAGER DARK…) — the lamp is a recomputed theorem, and
   a non-green word is information, never something to explain away.

## One machine, one instance

A host binds to a single registry instance. If `xchk_status` shows an existing
install for a different plate or instance, ADOPT it — never create a second
recorder chain beside a live one.

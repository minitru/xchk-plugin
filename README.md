# xchk-plugin — the xChk gate for Claude Code (and a Hermes bootstrap head)

[xChk](https://xchk.io/) puts a verified person behind an AI agent's actions. This plugin is the **gate**: a
fail-closed PreToolUse hook that sends each Claude Code tool call to an xChk registry before it runs. The registry
answers from the plate's grants: allow, refuse, or **hold** for the owner's passkey approval on their phone. Every
decision is a sealed, anchored record that anyone can verify offline. Nothing runs while a hold is unanswered, and
an unreachable registry is a refusal, never a pass.

What it gives you, in the harness you already use:

- **Per-action approval by the right person.** Outside sends, ssh, spend, secrets and system changes are held for
  the plate owner's passkey; routine local work runs. The agent's own stated reason for a command travels with the
  record.
- **Receipts, not logs.** One record per gated action, hash-chained, registry-signed, anchored; a public receipt
  page per approval; a SCITT signed statement for any approved act ([format and checker](https://github.com/minitru/xchk-scitt)).
- **An emergency stop that is measured.** A registry-signed halt at plate, host, org or registry scope, verified
  on the host before any grant is read; 20/20 halted, median 9 ms, p95 221 ms on the November 2026 release.
- **Measured, not claimed.** The bypass and detection benchmark gates every release (0 silent passes across 23
  techniques and 79 per-harness cases); external suites reproduced: AgentDojo 96.2 %, AgentGovBench 47/48, spikee
  94 % with 0 false positives. See [xchk.io/benchmarks](https://xchk.io/benchmarks.html) and the
  [AGSC v1.0.0 self-assessment](https://xchk.io/agsc-assessment.html).

You need a plate (an agent licence) from a registry, issued to a verified owner: start at
[in.xchk.io](https://in.xchk.io/). The plate owner answers for the agent; the plugin never asks the agent.

## Install

Claude Code: install the plugin from the marketplace or from this repository, then open a plate's **Equipment** page
in the console and follow the fit-out; the hook adopts an existing `~/.xchk` install and never creates a second one.
Releases are signed and manifest-hashed; a registry publishes each release and every installed copy reports its
version, so a copy that is behind shows up in the owner's console.

Hermes: `hermes plugins install minitru/xchk-plugin` installs the bootstrap head, whose skill walks the user to the
native gate (`hermes-xchk.sh setup`). Hermes Portable Agent Plugins v1 has no middleware class, so this head cannot
intercept and is never described as coverage.

## One gate, two heads

| | Claude Code head | Hermes portable head |
|---|---|---|
| Manifest | `.claude-plugin/plugin.json` | `plugin.json` (root) |
| MCP config | `.mcp.json` | `mcp.json` |
| Skills | `skills/*/SKILL.md` | same directory, same files |
| Interception | `hooks/hooks.json` → `gate/xchk_hook.py` (PreToolUse/Stop/SessionEnd/SessionStart) | **impossible** — Portable v1 has no middleware class |
| Grade | **enforcement-grade** — enabling the plugin IS the gate | **bootstrap-grade** — skill walks the user to the native gate |
| Install | Claude Code plugin install / marketplace | `hermes plugins install minitru/xchk-plugin` |

## Layout

```
xchk-plugin/
├── plugin.json              # Hermes head manifest (bootstrap-grade, says so)
├── mcp.json                 # Hermes: mounts the xchk status MCP server
├── .claude-plugin/
│   └── plugin.json          # Claude head manifest (enforcement-grade)
├── .mcp.json                # Claude: same MCP server
├── hooks/hooks.json         # Claude only: the gate wiring (mirrors curl-install)
├── gate/                    # VENDORED from xchk-app examples/claude-attestation-guardrails
│   ├── xchk_hook.py         #   — sync with scripts/sync-gate.sh, never edit here
│   ├── xchk_client.py
│   └── tests/               #   the gate's own tests, vendored with it
├── codex/ cursor/ antigravity/   # installers for the other harnesses (same gate, one dialect each)
├── mcp/xchk_mcp.py          # read-only status server (stdlib, stdio JSON-RPC)
├── skills/                  # adopt, ask-permission, proof, request-review (both heads read the same files)
├── MANIFEST.sha256          # the release's file hashes (plugin variant); MANIFEST.standalone.sha256 for the curl install
└── scripts/                 # sync-gate.sh (re-vendor), release-gate.sh and publish-release.sh (signed release)
```

## Invariants

- **`gate/` is vendored, not forked.** Source of truth stays
  `xchk-app/examples/claude-attestation-guardrails`; run `scripts/sync-gate.sh`
  to refresh. Heads are packaging.
- **Presence ≠ coverage.** The Hermes head cannot intercept; nothing in this
  package may describe a bootstrap-grade host as covered. The census
  distinguishes enforcement-grade from bootstrap-grade presence.
- **One machine, one instance.** The gate adopts an existing `~/.xchk`
  install; a head must never create a second recorder chain beside a live one,
  and exactly one hook wiring (plugin OR legacy settings.json) may be active.
- **The MCP server is read-only.** Enforcement is exclusively the hook.
- **Fail closed.** A hook that cannot reach the registry, cannot parse its input, or hits an error refuses; it
  never passes.

## Papers and formats

- [xChk: Bring Your Own Identity](https://arxiv.org/abs/2607.13369) (arXiv 2607.13369)
- [A Licensing and Accountability Layer for Inter-Agent Protocols](https://doi.org/10.5281/zenodo.21868527) (Zenodo)
- [xchk-scitt](https://github.com/minitru/xchk-scitt): the SCITT signed statement and its offline checker

xChk is Sean MacGuire's research project. Patents pending.

# xchk-plugin — one gate, two heads

Dual-head packaging of the xChk accountability gate. One repository is
simultaneously a **Claude Code plugin** (enforcement head) and a **Hermes
Portable Agent Plugins v1 package** (bootstrap head).

| | Claude Code head | Hermes portable head |
|---|---|---|
| Manifest | `.claude-plugin/plugin.json` | `plugin.json` (root) |
| MCP config | `.mcp.json` | `mcp.json` |
| Skills | `skills/xchk-adopt/SKILL.md` | same directory, same file |
| Interception | `hooks/hooks.json` → `gate/xchk_hook.py` (PreToolUse/Stop/SessionEnd/SessionStart) | **impossible** — Portable v1 has no middleware class |
| Grade | **enforcement-grade** — enabling the plugin IS the gate | **bootstrap-grade** — skill walks the user to the native gate (`hermes-xchk.sh setup`) |
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
│   └── xchk_client.py
├── mcp/xchk_mcp.py          # read-only status server (stdlib, stdio JSON-RPC)
├── skills/xchk-adopt/       # adoption skill (both heads read the same file)
└── scripts/sync-gate.sh     # re-vendor gate/ from the source of truth
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

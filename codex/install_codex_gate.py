#!/usr/bin/env python3
"""Register the xChk gate with Codex — host-global, one wiring, no duplicates (13 Sep 2026).

    python3 codex/install_codex_gate.py            # install / re-point
    python3 codex/install_codex_gate.py --remove   # uninstall
    python3 codex/install_codex_gate.py --print    # show, write nothing

WHY THIS EXISTS
The MCP wrapper (xchk-mcp) gates Codex's TOOL SERVERS. It never sees Codex's native tools: the
shell (`exec`), `apply_patch`, file reads. Sean tried `rm` from Codex Desktop on 13 Sep 2026 and
it ran ungated — expected under the wrapper alone. Codex has had hooks since v0.114 (March 2026):
PreToolUse fires for Bash (unified exec matches as Bash), apply_patch and MCP calls, takes
Claude's stdin payload (session_id, hook_event_name, tool_name, tool_input, cwd) and honours
Claude's decision shape (hookSpecificOutput.permissionDecision allow|deny, or exit 2). The gate
already speaks exactly that. So the same file is registered here, under XCHK_HARNESS=codex, and
reads ~/.xchk/codex.json + ~/.xchk/codex-runs (the gate derives both from the harness name).

WHERE
~/.codex/hooks.json — Codex's own user-level hook file (a repo's .codex/hooks.json overrides it).
Not ~/.codex/config.toml: Codex Desktop rewrites config.toml on update (it dropped the MCP
wrapper that way on 13 Sep 2026); hooks.json is ours alone.

EVENTS
PreToolUse with NO matcher: Bash, apply_patch AND MCP tools all go to the gate. The wrapper
notices (hookCoversMcp) and yields — records and forwards — so one call is one card.
SessionStart / Stop / SessionEnd for the run ticket, as on Claude Code.

AFTER INSTALLING
1. put the Codex install's API key in ~/.xchk/codex.json (same shape as ~/.xchk/claude.json)
2. Codex must TRUST a non-managed hook before it runs: open Codex, run /hooks, trust the xchk entry
   (trust is recorded against the hook's hash — a changed gate must be re-trusted)
3. restart Codex
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "gate" / "xchk_hook.py"
HOOKS = Path(os.environ.get("CODEX_HOOKS", "~/.codex/hooks.json")).expanduser()
MARKER = "xchk_hook.py"

# Long enough to outlast a human deciding on an attestation (Codex's default is 600 s; the Claude
# Code registration uses 660 so an approval prompt behaves the same on both).
ATTEST_TIMEOUT = 660

# Codex uses Claude's event names and Claude's GROUP shape: {"PreToolUse": [{"matcher"?, "hooks": [..]}]}
EVENTS = {
    "SessionStart": 30,
    "PreToolUse": ATTEST_TIMEOUT,
    "Stop": 10,
    "SessionEnd": 3,          # Codex caps SessionEnd at 3 s
}


LABELS = {
    "PreToolUse": "xChk: answers for this action under your licence (allow / refuse / ask a person)",
    "SessionStart": "xChk: opens the run ticket for this session",
    "Stop": "xChk: seals what this turn did onto the record",
    "SessionEnd": "xChk: closes the run ticket",
}


def hook_entry(timeout: int, event: str = "") -> dict:
    # XCHK_HARNESS is what keeps this install in its own (harness, guardedHost) slot, its own
    # credential and its own run-ticket state.
    return {"type": "command", "command": f'XCHK_HARNESS=codex python3 "{GATE}"', "timeout": timeout, **({"statusMessage": LABELS[event]} if event in LABELS else {})}


def load() -> dict:
    if not HOOKS.is_file():
        return {"hooks": {}}
    try:
        doc = json.loads(HOOKS.read_text() or "{}") or {}
    except ValueError:
        print(f"refusing to touch unparseable {HOOKS} — fix or move it first", file=sys.stderr)
        raise SystemExit(2)
    doc.setdefault("hooks", {})
    return doc


def strip_ours(doc: dict) -> int:
    """Remove only our entries, preserving anyone else's hooks. Handles both the group shape and a flat entry."""
    removed = 0
    for name, groups in list(doc.get("hooks", {}).items()):
        keep = []
        for g in groups:
            if not isinstance(g, dict):
                keep.append(g)
                continue
            if MARKER in str(g.get("command", "")):
                removed += 1
                continue
            inner = [h for h in (g.get("hooks") or []) if MARKER not in str((h or {}).get("command", ""))]
            removed += len(g.get("hooks") or []) - len(inner)
            if inner or not g.get("hooks"):
                g = {**g, "hooks": inner} if "hooks" in g else g
                keep.append(g)
        if keep:
            doc["hooks"][name] = keep
        else:
            doc["hooks"].pop(name)
    return removed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--remove", action="store_true")
    ap.add_argument("--print", dest="show", action="store_true")
    args = ap.parse_args()

    if not GATE.is_file():
        print(f"gate not found at {GATE}", file=sys.stderr)
        return 2

    doc = load()
    removed = strip_ours(doc)  # re-point cleanly rather than accumulate

    if not args.remove:
        for name, timeout in EVENTS.items():
            doc["hooks"].setdefault(name, []).append({"hooks": [hook_entry(timeout, name)]})   # no matcher: everything

    if args.show:
        print(json.dumps(doc, indent=2))
        return 0

    HOOKS.parent.mkdir(parents=True, exist_ok=True)
    HOOKS.write_text(json.dumps(doc, indent=2) + "\n")

    if args.remove:
        print(f"removed {removed} xchk hook(s) from {HOOKS}")
    else:
        print(f"registered {len(EVENTS)} xchk hooks in {HOOKS}" + (f" (replaced {removed} stale)" if removed else ""))
        print(f"gate: {GATE}")
        print("next: put the Codex install's API key in ~/.xchk/codex.json (same shape as ~/.xchk/claude.json),")
        print("      open Codex and run /hooks to TRUST the xchk hook, then restart Codex.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Register the xChk gate with Cursor — host-global, one wiring, no duplicates.

    python3 cursor/install_cursor_gate.py            # install / re-point
    python3 cursor/install_cursor_gate.py --remove   # uninstall
    python3 cursor/install_cursor_gate.py --print    # show, write nothing

WHY ~/.cursor/hooks.json AND NOT ~/.claude/settings.json
Cursor reads Claude Code's own registration out of .claude/settings.json, which
is how the compatibility was proven. It is still the wrong place to install:
Claude Code reads that file too, and this gate is already wired there by the
plugin. One entry, two readers, and every Claude Code action would be
authorized twice and recorded twice — two attestations for one act, on a chain
whose value is that it says what happened exactly once. Cursor's own file is
read by Cursor alone.

WHICH EVENTS, AND WHY NOT beforeShellExecution
preToolUse alone. Cursor fires BOTH preToolUse (tool_name 'Shell') and
beforeShellExecution for a single terminal command, and both for a single read;
registering both would double-authorize every one. preToolUse is the superset —
it carries Shell, Write and Read — so it is the one that gates.

Claude Code's registration is untouched by this script.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "gate" / "xchk_hook.py"
HOOKS = Path(os.environ.get("CURSOR_HOOKS", "~/.cursor/hooks.json")).expanduser()
MARKER = "xchk_hook.py"

# Long enough to outlast a human deciding on an attestation. Cursor honours a
# configured timeout well past its default (verified: a 90s block was waited
# out in full, then the decision applied), and this mirrors the 660s the Claude
# Code registration uses so an approval prompt behaves the same on both.
ATTEST_TIMEOUT = 660

EVENTS = {
    "sessionStart": 30,
    "preToolUse": ATTEST_TIMEOUT,
    "stop": 10,
    "sessionEnd": 15,
}


def entry() -> dict:
    # XCHK_HARNESS is what keeps this install in its own (harness, guardedHost)
    # slot and its own run-ticket state. The gate also sniffs cursor_version if
    # the variable is lost, but declaring it is the honest wiring.
    return {
        "type": "command",
        "command": f'XCHK_HARNESS=cursor python3 "{GATE}"',
    }


def load() -> dict:
    if not HOOKS.is_file():
        return {"version": 1, "hooks": {}}
    try:
        doc = json.loads(HOOKS.read_text() or "{}") or {}
    except ValueError:
        print(f"refusing to touch unparseable {HOOKS} — fix or move it first",
              file=sys.stderr)
        raise SystemExit(2)
    doc.setdefault("version", 1)
    doc.setdefault("hooks", {})
    return doc


def strip_ours(doc: dict) -> int:
    """Remove only our entries, preserving anyone else's hooks."""
    removed = 0
    for name, entries in list(doc.get("hooks", {}).items()):
        keep = [e for e in entries if MARKER not in str(e.get("command", ""))]
        removed += len(entries) - len(keep)
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
            e = dict(entry())
            e["timeout"] = timeout
            doc["hooks"].setdefault(name, []).append(e)

    if args.show:
        print(json.dumps(doc, indent=2))
        return 0

    HOOKS.parent.mkdir(parents=True, exist_ok=True)
    HOOKS.write_text(json.dumps(doc, indent=2) + "\n")

    if args.remove:
        print(f"removed {removed} xchk hook(s) from {HOOKS}")
    else:
        print(f"registered {len(EVENTS)} xchk hooks in {HOOKS}"
              + (f" (replaced {removed} stale)" if removed else ""))
        print(f"gate: {GATE}")
        print("next: put the Cursor install's API key in ~/.xchk/cursor.json "
              "(same shape as ~/.xchk/claude.json), then restart Cursor.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

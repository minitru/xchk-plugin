#!/usr/bin/env python3
"""Register the xChk gate with Google Antigravity — host-global, one group, no duplicates (13 Sep 2026).

    python3 antigravity/install_antigravity_gate.py            # install / re-point
    python3 antigravity/install_antigravity_gate.py --remove   # uninstall
    python3 antigravity/install_antigravity_gate.py --print    # show, write nothing

Antigravity (IDE 2.x + agy CLI) reads ~/.gemini/config/hooks.json: { "<name>": { enabled, PreToolUse: [...],
PreInvocation: [...], Stop: [...] } }. Its stdin payload names no event, so each entry passes `--event <Name>`;
the gate (0.1.13+) translates toolCall/conversationId into its own fields and answers {"decision","reason"}.
A launcher script carries XCHK_HARNESS=antigravity so nothing is assumed about the host's shell.
After installing: put the API key in ~/.xchk/antigravity.json (same shape as claude.json), restart Antigravity.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "gate" / "xchk_hook.py"
LAUNCHER = Path(__file__).resolve().parent / "antigravity-hook.sh"
HOOKS = Path(os.environ.get("ANTIGRAVITY_HOOKS", "~/.gemini/config/hooks.json")).expanduser()
EVENTS = {"PreToolUse": 660, "PreInvocation": 30, "Stop": 10}


def ensure_launcher() -> None:
    LAUNCHER.write_text(f'#!/bin/sh\nexport XCHK_HARNESS=antigravity\nexec python3 "{GATE}" "$@"\n')
    LAUNCHER.chmod(0o755)


def group() -> dict:
    g = {"enabled": True}
    for ev, timeout in EVENTS.items():
        g[ev] = [{"hooks": [{"type": "command", "command": f'"{LAUNCHER}" --event {ev}', "timeout": timeout}]}]   # no matcher: everything
    return g


def load() -> dict:
    if not HOOKS.is_file():
        return {}
    try:
        doc = json.loads(HOOKS.read_text() or "{}") or {}
    except ValueError:
        print(f"refusing to touch unparseable {HOOKS} — fix or move it first", file=sys.stderr)
        raise SystemExit(2)
    return doc if isinstance(doc, dict) else {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--remove", action="store_true")
    ap.add_argument("--print", dest="show", action="store_true")
    args = ap.parse_args()
    if not GATE.is_file():
        print(f"gate not found at {GATE}", file=sys.stderr)
        return 2
    doc = load()
    had = "xchk" in doc
    doc.pop("xchk", None)
    if not args.remove:
        doc["xchk"] = group()
    if args.show:
        print(json.dumps(doc, indent=2))
        return 0
    if not args.remove:
        ensure_launcher()
    HOOKS.parent.mkdir(parents=True, exist_ok=True)
    HOOKS.write_text(json.dumps(doc, indent=2) + "\n")
    if args.remove:
        print(f"removed the xchk group from {HOOKS}" if had else f"no xchk group in {HOOKS}")
    else:
        print(f"registered the xchk group ({', '.join(EVENTS)}) in {HOOKS}" + (" (replaced)" if had else ""))
        print(f"gate: {GATE}\nlauncher: {LAUNCHER}")
        print("next: put the Antigravity install's API key in ~/.xchk/antigravity.json (same shape as ~/.xchk/claude.json), then restart Antigravity.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""xChk session-intent hook (UserPromptSubmit) — AARM R2/R3 intent capture.

Every prompt the person types is an intent. This hook sends the registry a DIGEST of it
(sha256, length, a hash of the working directory) bound to this session's run, so a later
intent-alignment verdict has something to bind to. The prompt text never leaves the host.

Never blocks, never speaks: no output, exit 0 on every path. A failure here must not be able
to touch the conversation. Rewritten 12 Sep 2026 after the hand-placed original was wiped by
a re-fit (gap GR-2); it now ships with the release so that cannot happen again.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT))
sys.path.insert(0, str(PLUGIN_ROOT / "hooks"))

MAX_STDIN_BYTES = 512 * 1024


def main() -> None:
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return
    if not isinstance(data, dict):
        return
    prompt = data.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return
    try:
        import xchk_hook as gate   # the gate's own config, harness and run-ticket logic
        gate.apply_harness(gate.resolve_harness(data))
        cfg = gate.load_config()
        client = gate.make_client(cfg)
        if not getattr(client, "configured", False):
            return
        session_id = str(data.get("session_id") or "")
        run = gate.load_run(session_id) or gate.dispatch(client, session_id)
        tty = gate.controlling_tty()
        host = socket.gethostname().split(".")[0]
        cwd = str(data.get("cwd") or os.getcwd())
        body = {
            "promptHash": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "promptLength": len(prompt),
            "sessionRef": f"{tty or 'tty?'}@{host}#{session_id[:8]}",
            "cwdHash": hashlib.sha256(cwd.encode("utf-8")).hexdigest(),
            "harness": gate.HARNESS,
        }
        if run and run.get("runSeq") is not None:
            body["runSeq"] = run.get("runSeq")
        client.request("POST", "/api/agents/session-intent", body=body, timeout=5)
    except Exception:
        return


if __name__ == "__main__":
    main()
    sys.exit(0)

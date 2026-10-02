#!/usr/bin/env python3
"""xChk outcome hook (PostToolUse) — "allowed" is not "done". 2 Oct 2026.

The gate records that an action was AUTHORIZED. This hook, run by the harness after the tool has returned, tells
the registry how it ENDED: completed or failed, with a digest of the result the harness saw and the time. The
registry appends that as its own record linked to the decision (never an edit of it), and reconciliation counts the
decisions that ran and were never reported on — the "owned unknown" of an agent killed after dispatch.

Self-reported by the host, like the recorder: evidence for recovery and reconciliation, not proof of effect at
the target. Never blocks, never speaks: no output, exit 0 on every path. A failure here must not touch the session.
The tool's output itself never leaves the host — only its hash.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT))
sys.path.insert(0, str(PLUGIN_ROOT / "hooks"))

MAX_STDIN_BYTES = 4 * 1024 * 1024   # tool results can be large; the hash is taken over what the harness sent


def _status(resp) -> str:
    """completed | failed, from what the harness reports about the tool call. Conservative: only an explicit
    failure signal counts as failed."""
    if isinstance(resp, dict):
        for k in ("is_error", "isError", "error", "interrupted", "timed_out", "timedOut"):
            if resp.get(k):
                return "failed"
        code = resp.get("exit_code", resp.get("exitCode"))
        if isinstance(code, int) and code != 0:
            return "failed"
    return "completed"


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES)
        data = json.loads(raw.decode("utf-8", "replace") or "{}")
    except Exception:
        return
    if not isinstance(data, dict):
        return
    if str(data.get("hook_event_name") or "").lower() != "posttooluse":
        return
    tool_name = str(data.get("tool_name") or "")
    tool_input = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
    if not tool_name:
        return
    try:
        import xchk_hook as gate   # the gate's own config, harness, run state and summary — one home
        session_id = str(data.get("session_id") or data.get("conversation_id") or data.get("conversationId") or "")
        gate.apply_harness(gate.resolve_harness(data), session_id)
        cfg = gate.load_config()
        client = gate.make_client(cfg)
        if not getattr(client, "configured", False):
            return
        mapped = gate.TOOL_MAP.get(tool_name)
        if not mapped:
            if tool_name in gate.UNGATED_TOOLS:
                return   # never gated, so there is no decision to report on
            mapped = gate.CATCHALL_WIRE
        # The same summary the gate sent when it asked: that is how the registry finds the decision.
        summary = gate.summarize(tool_name, tool_input) or f"{gate.HARNESS_LABEL} {tool_name}"
        resp = data.get("tool_response")
        result_hash = hashlib.sha256(json.dumps(resp, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")).hexdigest()
        body = {
            "tool": mapped,
            "summary": summary[:400],
            "status": _status(resp),
            "resultHash": result_hash,
            "endedAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        }
        run = gate.load_run(session_id)
        if run and run.get("runSeq") is not None:
            body["runSeq"] = run["runSeq"]
        client.request("POST", "/api/agents/outcome", body=body, timeout=5)
    except Exception:
        return


if __name__ == "__main__":
    try:
        main()
    finally:
        if os.environ.get("XCHK_HARNESS") == "cursor":
            print(json.dumps({"continue": True}))
    sys.exit(0)

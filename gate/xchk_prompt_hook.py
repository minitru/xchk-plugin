#!/usr/bin/env python3
"""xChk session-intent hook (UserPromptSubmit) — AARM R2/R3 intent capture.

Every prompt the person types is an intent. This hook sends the registry a DIGEST of it
(sha256, length, a hash of the working directory) bound to this session's run, so a later
intent-alignment verdict has something to bind to.

The prompt text leaves the host in one case only (12 Oct 2026): the plate's owner turned request
sharing on, the registry said so when this run opened, and the session was told at its start. Then
the opening characters go too, unless they look like they hold a secret, a card, a bank detail or
personal data, in which case only the digest goes, as before. See objective_for.

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
WITHHELD_LABELS = {"CREDENTIALS", "HAS_PAYMENT", "HAS_PII", "HAS_BANKING"}


def objective_for(prompt: str, run, chars: int, classify) -> str | None:
    """The opening of a request, when this run may send it and it is safe to send; else None.
    Refuses on every doubt: no run, no true from the registry, a classifier that is missing or
    fails, or any label that says the text holds something that must not travel."""
    if not isinstance(run, dict) or run.get("sendObjective") is not True or classify is None:
        return None
    text = prompt.strip()[:chars]
    if not text:
        return None
    try:
        labels = classify(text)
    except Exception:
        return None
    if any((l or {}).get("label") in WITHHELD_LABELS for l in labels):
        return None
    return text


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
        # Cursor sends conversation_id; Antigravity-style payloads conversationId (27 Sep 2026)
        session_id = str(data.get("session_id") or data.get("conversation_id") or data.get("conversationId") or "")
        run = gate.load_run(session_id) or gate.dispatch(client, session_id)
        tty = gate.controlling_tty()
        host = socket.gethostname().split(".")[0]
        roots = data.get("workspace_roots") or data.get("workspacePaths") or []
        cwd = str(data.get("cwd") or (roots[0] if isinstance(roots, list) and roots else "") or os.getcwd())
        body = {
            "promptHash": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "promptLength": len(prompt),
            "sessionRef": f"{tty or 'tty?'}@{host}#{session_id[:8]}",
            "cwdHash": hashlib.sha256(cwd.encode("utf-8")).hexdigest(),
            "harness": gate.HARNESS,
        }
        if run and run.get("runSeq") is not None:
            body["runSeq"] = run.get("runSeq")
        try:
            import xchk_labels
            classify = xchk_labels.classify
        except Exception:
            classify = None
        objective = objective_for(prompt, run, gate.OBJECTIVE_CHARS, classify)
        if objective:
            body["declaredObjective"] = objective
        client.request("POST", "/api/agents/session-intent", body=body, timeout=5)
    except Exception:
        return


if __name__ == "__main__":
    try:
        main()
    finally:
        # Cursor reads this event's answer from stdout; this hook never blocks, so the answer is always "continue".
        if os.environ.get("XCHK_HARNESS") == "cursor":
            print(json.dumps({"continue": True}))
    sys.exit(0)

#!/usr/bin/env python3
"""xChk outcome hook (PostToolUse, PostToolUseFailure) — "allowed" is not "done". 2 Oct 2026.

The gate records that an action was AUTHORIZED. This hook, run by the harness after the tool has returned, tells
the registry how it ENDED: completed or failed, with a digest of the result the harness saw and the time. The
registry appends that as its own record linked to the decision (never an edit of it), and reconciliation counts the
decisions that ran and were never reported on — the "owned unknown" of an agent killed after dispatch.

Self-reported by the host, like the recorder: evidence for recovery and reconciliation, not proof of effect at
the target. Never blocks, never speaks: no output, exit 0 on every path. A failure here must not touch the session.
The tool's output itself never leaves the host — only its hash.

5 Oct 2026: when the tool wrote a file, the report also carries the sha256 of that file as it stands after the
write (`artifactHash`). Sealed with the outcome record, it lets anyone holding the file check it against the run
that wrote it. The file never leaves the host either.
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

# 13 Oct 2026: Claude Code tells a hook about a tool that FAILED on its own event, PostToolUseFailure, not on
# PostToolUse. This hook was registered for PostToolUse alone and refused any other event, so a failed tool was never
# reported and its decision read "outcome unknown" for good. Seen on ENG-WNP3: 47 tool calls that returned an error
# across about 1,700, 47 decisions with no ending, and not one outcome record marked failed for any tool.
ENDED_EVENTS = ("posttooluse", "posttoolusefailure")


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


MAX_ARTIFACT_BYTES = 256 * 1024 * 1024   # a file larger than this is not hashed: this hook must stay quick
FILE_WRITE_WIRES = ("write_file", "patch")


def _artifact_hash(tool_input: dict):
    """sha256 of the file a write tool just left on disk, or None. None means "not reported", never a guess: a
    missing path, a file that is not a regular file, one too large, or one that cannot be read."""
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not path or not isinstance(path, str):
        return None
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > MAX_ARTIFACT_BYTES:
            return None
        digest = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES)
        data = json.loads(raw.decode("utf-8", "replace") or "{}")
    except Exception:
        return
    if not isinstance(data, dict):
        return
    event = str(data.get("hook_event_name") or "").lower()
    if event not in ENDED_EVENTS:
        return
    tool_failed = event == "posttoolusefailure"
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
        # a failed tool has no response; what the harness says of the failure is what is hashed
        resp = {"error": data.get("error"), "is_interrupt": data.get("is_interrupt")} if tool_failed else data.get("tool_response")
        result_hash = hashlib.sha256(json.dumps(resp, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")).hexdigest()
        body = {
            "tool": mapped,
            "summary": summary[:400],
            "status": "failed" if tool_failed else _status(resp),
            "resultHash": result_hash,
            "endedAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        }
        if mapped in FILE_WRITE_WIRES and body["status"] == "completed":
            artifact = _artifact_hash(tool_input)
            if artifact:
                body["artifactHash"] = artifact
        run = gate.load_run(session_id)
        if run and run.get("runSeq") is not None:
            body["runSeq"] = run["runSeq"]
        client.request("POST", "/api/agents/outcome", body=body, timeout=5)
        # 17 Oct 2026: the answer stays on the host, for the act-against-content reading made at the next act
        # (xchk_act_reading.py). Cut at 6,000 characters, the paper's limit; past it the content is not read.
        try:
            import xchk_act_reading
            text = xchk_act_reading.answer_text(resp) if not tool_failed else ""
            keep = {"tool": mapped, "text": text[:xchk_act_reading.CONTENT_CHARS],
                    "cut": len(text) > xchk_act_reading.CONTENT_CHARS, "chars": len(text),
                    "hash": hashlib.sha256(text.encode("utf-8")).hexdigest(), "at": time.time()}
            sp = gate.state_path(session_id)
            p = sp.with_name(sp.stem + ".last-answer.json")
            gate.STATE_DIR.mkdir(parents=True, exist_ok=True)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(keep, f)
        except Exception:
            pass
    except Exception:
        return


if __name__ == "__main__":
    try:
        main()
    finally:
        if os.environ.get("XCHK_HARNESS") == "cursor":
            print(json.dumps({"continue": True}))
    sys.exit(0)

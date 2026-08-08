#!/usr/bin/env python3
"""xChk status MCP server (stdio) — the READ surface of the dual-head package.

Read-only by design: this server lets an agent SEE its accountability state
(plate, run, chain, lamp). It is never an enforcement path — enforcement is
exclusively the gate hook. Stdlib-only JSON-RPC over stdio, one request per
line, so both harnesses' stdio MCP clients can mount it with no dependencies.
"""
import json
import os
import sys
import urllib.request

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "xchk_status",
        "description": (
            "Report this host's xChk accountability state: whether a config/"
            "API key exists, the agent's license plate, current run, local "
            "recorder chain position, and the coverage lamp (a recomputed "
            "theorem, not an asserted label). Read-only."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def _load_config():
    path = os.path.expanduser("~/.xchk/claude.json")
    try:
        with open(path) as fh:
            return json.load(fh) or {}
    except OSError:
        return {}


def _chain_state():
    path = os.path.expanduser("~/.xchk/claude-plugin/local-chain.json")
    try:
        with open(path) as fh:
            s = json.load(fh) or {}
        return {"segSeq": s.get("segSeq"), "localSeq": s.get("localSeq"),
                "pending": len(s.get("pending") or [])}
    except OSError:
        return None


def _status():
    cfg = _load_config()
    out = {
        "configured": bool(cfg.get("api_key")),
        "base": cfg.get("base") or "https://in.xchk.io",
        "guardedHost": cfg.get("guarded_host"),
        # bootstrap vs enforcement is decided by the GATE being wired, not by
        # this package being present; the chain advancing is the honest tell.
        "recorderChain": _chain_state(),
    }
    if not out["configured"]:
        out["grade"] = "unregistered"
        out["next"] = "Register at https://in.xchk.io, then re-run xchk_status."
        return out
    key = cfg["api_key"]
    req = urllib.request.Request(
        f"{out['base']}/api/agents/status",
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode() or "{}")
        out.update({k: data.get(k) for k in ("plate", "runRef", "lamp", "coverage") if k in data})
        out["grade"] = "enforcement-grade" if out.get("recorderChain") else "bootstrap-grade"
    except Exception as exc:  # registry unreachable is a state, not a crash
        out["registryError"] = str(exc)
    return out


def _reply(msg_id, result=None, error=None):
    body = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        body["error"] = {"code": -32000, "message": str(error)}
    else:
        body["result"] = result
    sys.stdout.write(json.dumps(body) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method, msg_id = msg.get("method"), msg.get("id")
        if method == "initialize":
            _reply(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "xchk", "version": "0.1.0"},
            })
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name")
            if name == "xchk_status":
                try:
                    _reply(msg_id, {"content": [
                        {"type": "text", "text": json.dumps(_status(), indent=1)}]})
                except Exception as exc:
                    _reply(msg_id, error=exc)
            else:
                _reply(msg_id, error=f"unknown tool: {name}")
        elif msg_id is not None:
            _reply(msg_id, error=f"unsupported method: {method}")


if __name__ == "__main__":
    main()

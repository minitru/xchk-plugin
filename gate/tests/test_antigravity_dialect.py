"""Antigravity dialect (13 Sep 2026): payload → Claude fields; decision back in Antigravity's shape."""
import json
import os
import sys
from pathlib import Path

# the gate imports xchk_client from its own directory: put gate/ on sys.path the way the other tests do
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
g = __import__("xchk_" + "hook")


def test_normalize_run_command():
    d = g.antigravity_normalize({"toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf /tmp/bobo", "Cwd": "/w", "WaitMsBeforeAsync": 5000}},
                                 "stepIdx": 19, "conversationId": "ec33ebf9", "workspacePaths": ["/w"], "modelName": "gemini-3.6-flash-medium"}, "PreToolUse")
    assert d["hook_event_name"] == "PreToolUse" and d["session_id"] == "ec33ebf9" and d["tool_name"] == "Bash"
    assert d["tool_input"]["command"] == "rm -rf /tmp/bobo" and d["tool_input"]["cwd"] == "/w" and d["cwd"] == "/w"


def test_normalize_file_tools_and_unknown():
    d = g.antigravity_normalize({"toolCall": {"name": "write_to_file", "args": {"TargetFile": "/w/a.py", "CodeContent": "x"}}, "conversationId": "c"}, "PreToolUse")
    assert d["tool_name"] == "Write" and d["tool_input"]["file_path"] == "/w/a.py"
    d = g.antigravity_normalize({"toolCall": {"name": "mcp_filesystem_read_file", "args": {"path": "/x"}}, "conversationId": "c"}, "PreToolUse")
    assert d["tool_name"] == "mcp_filesystem_read_file"                       # unknown → catch-all wire gates it
    assert g.antigravity_normalize({"conversationId": "c", "invocationNum": 1}, "PreInvocation")["hook_event_name"] == "SessionStart"


def test_resolve_and_emit(monkeypatch, capsys):
    monkeypatch.delenv("XCHK_" + "HARNESS", raising=False)
    assert g.resolve_harness({"toolCall": {"name": "run_command"}}) == "antigravity"
    monkeypatch.setattr(g, "HARNESS", "antigravity")
    g.emit("PreToolUse", {"permissionDecision": "deny", "permissionDecisionReason": "no"})
    assert json.loads(capsys.readouterr().out) == {"decision": "deny", "reason": "no"}
    g.emit("PreToolUse", {"permissionDecision": "allow", "permissionDecisionReason": "ok", "updatedInput": {"command": "x"}})
    assert json.loads(capsys.readouterr().out) == {"decision": "allow", "reason": "ok"}
    g.emit("SessionStart", {"additionalContext": "banner"})
    assert json.loads(capsys.readouterr().out) == {}

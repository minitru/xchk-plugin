#!/usr/bin/env python3
"""Cursor-dialect regression tests for the gate. Stdlib only.

    python3 cursor/test_cursor_gate.py

These exist because the Cursor failure mode is silent. The gate installs, runs,
exits 0 and refuses nothing — indistinguishable from a healthy gate except that
nothing is ever recorded. Every test below asserts something whose breakage
would look like success.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "gate" / "xchk_hook.py"
sys.path.insert(0, str(GATE.parent))

import xchk_hook  # noqa: E402

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"{'ok  ' if cond else 'FAIL'} {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# --- event normalisation: the fail-open bug ---------------------------------
# Cursor delivers 'preToolUse'; the gate dispatches on 'PreToolUse'. Exact
# match => no branch taken => exit 0 => the action is ALLOWED. Unfixed, every
# gated action on Cursor passes while the console shows the harness covered.
for wire, canonical in [
    ("preToolUse", "PreToolUse"),
    ("PreToolUse", "PreToolUse"),
    ("sessionStart", "SessionStart"),
    ("SessionStart", "SessionStart"),
    ("sessionEnd", "SessionEnd"),
    ("stop", "Stop"),
    ("Stop", "Stop"),
]:
    check(f"event {wire!r} -> {canonical}",
          xchk_hook._EVENTS.get(wire.lower()) == canonical)

check("unknown event does not route",
      xchk_hook._EVENTS.get("beforemcpexecution") is None)

# --- tool vocabulary --------------------------------------------------------
check("Cursor Shell maps to terminal", xchk_hook.TOOL_MAP.get("Shell") == "terminal")
check("Write still maps to write_file", xchk_hook.TOOL_MAP.get("Write") == "write_file")

# --- harness resolution -----------------------------------------------------
# Guessing 'claude' for a Cursor session merges two harnesses into one install
# slot: revoke one key and the other is silently disarmed.
check("cursor_version implies cursor",
      xchk_hook.resolve_harness({"cursor_version": "3.14.7"}) == "cursor")
check("bare payload stays claude", xchk_hook.resolve_harness({}) == "claude")

# --- per-harness state isolation -------------------------------------------
xchk_hook.apply_harness("cursor")
cursor_state, cursor_cfg = xchk_hook.STATE_DIR, xchk_hook.CONFIG_PATH
check("cursor label", xchk_hook.HARNESS_LABEL == "Cursor")
xchk_hook.apply_harness("claude")
check("claude paths unchanged by the port",
      xchk_hook.STATE_DIR.name == "claude-runs" and xchk_hook.CONFIG_PATH.name == "claude.json",
      f"{xchk_hook.STATE_DIR} {xchk_hook.CONFIG_PATH}")
check("run state is per-harness",
      cursor_state != xchk_hook.STATE_DIR and cursor_cfg != xchk_hook.CONFIG_PATH)

# --- harness-internal scratch ----------------------------------------------
internal = "/Users/x/.cursor/projects/Users-x-proj/agent-tools/9d5041f4.txt"
check("cursor agent-tools scratch is internal",
      bool(xchk_hook.INTERNAL_PATH_RE.search(internal)))
check("a real file under a .cursor-named project is not",
      not xchk_hook.INTERNAL_PATH_RE.search("/Users/x/work/.cursorrules"))
check("user file is not internal",
      not xchk_hook.INTERNAL_PATH_RE.search("/Users/x/proj/README.md"))


# --- end to end: unconfigured gate must not answer for a real tool ----------
def run(payload: dict) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(GATE)],
        input=json.dumps(payload), capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp/xchk-test-home",
             "XCHK_HARNESS": "cursor", "XCHK_CONFIG": "/tmp/xchk-test-none.json"},
    )
    return p.returncode, p.stdout.strip()


rc, out = run({"hook_event_name": "preToolUse", "tool_name": "Write",
               "tool_input": {"file_path": internal},
               "session_id": "t1", "cursor_version": "3.14.7"})
check("internal scratch is deferred, not decided", rc == 0 and out == "",
      f"rc={rc} out={out!r}")

rc, out = run({"hook_event_name": "preToolUse", "tool_name": "SomeFutureTool",
               "tool_input": {}, "session_id": "t2", "cursor_version": "3.14.7"})
check("ungated tool is deferred", rc == 0 and out == "", f"rc={rc} out={out!r}")

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
    sys.exit(1)
print("all cursor gate tests passed")

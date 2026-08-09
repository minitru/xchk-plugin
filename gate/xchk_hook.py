#!/usr/bin/env python3
"""xChk license hook for Claude Code — one session = one run under the plate.

SessionStart  -> harness check-in + dispatch a run (PLATE.N) for this session
PreToolUse    -> authorize the proposed action under the run ticket
                 (allow / forbid / attest-with-human-approval)
SessionEnd    -> end the run

Security posture:
  - Config and run-ticket state live under ~/.xchk with 0700/0600 perms.
  - The API key is never logged, never placed in argv, never echoed to the model.
  - HTTPS is required; set XCHK_ALLOW_INSECURE=1 only for local development.
  - Tool input from the model is treated as data: it is JSON-encoded to the
    server, never shell-interpolated, and stdin is size-capped.
  - XCHK_FAIL_CLOSED=1 denies gated tools when the license server is
    unreachable (the licensing default; off here so a dev box degrades safely).
"""

from __future__ import annotations

import json
import os
import re
import socket
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT))

from xchk_client import XchkClient  # noqa: E402
try:
    from xchk_client import LocalRecorder  # noqa: E402
except Exception:  # pragma: no cover
    LocalRecorder = None

_LOCAL_CHAIN_PATH = str(PLUGIN_ROOT / "local-chain.json")


def _recorder():
    """Lazy, exception-safe local recorder — never affects a decision."""
    if LocalRecorder is None:
        return None
    try:
        return LocalRecorder(_LOCAL_CHAIN_PATH)
    except Exception:
        return None


def _record(auth_ref, tool, intent, client=None, params_hash=None):
    """Chain an executed action, then keep the chain CURRENT.

    Flushing only at Stop/SessionEnd is not enough: reconciliation grants an
    in-flight grace of one seal cadence, so during a long session entries
    would age past it while still sitting in pending and read as omissions.
    A false alarm discredits the real one, so the flush cadence must stay
    inside the grace — flush() self-rate-limits, this just gives it the
    chance. params_hash binds the entry to the authorized action (content
    fidelity)."""
    r = _recorder()
    if not r:
        return
    r.record(auth_ref, tool, intent, params_hash=params_hash)
    if client is not None and getattr(client, "configured", False):
        try:
            r.flush(client)
        except Exception:
            pass

PLUGIN_VERSION = "0.1.2"
MAX_STDIN_BYTES = 512 * 1024


def gate_integrity() -> dict:
    """Self-hash the gate against MANIFEST.sha256 at the plugin root.

    SELF-ATTESTED by construction: a compromised gate can lie here, and the
    design accepts that — the claim rides the signed status ping, bound to
    the run and dated, so the gate must either tell the truth (evident now)
    or lie on the record (evident later, against the issuer's known-good
    manifest). Tamper-EVIDENT, never tamper-proof. Absence of a manifest is
    the legacy curl-install, reported as such rather than alarmed on.

    Manifest lines: '<sha256>  <path relative to plugin root>'.
    """
    import hashlib
    root = Path(__file__).resolve().parent.parent
    manifest = root / "MANIFEST.sha256"
    if not manifest.is_file():
        return {"gateIntegrity": "unmanifested"}
    try:
        raw = manifest.read_bytes()
        status = "verified"
        for line in raw.decode().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            want, rel = line.split(None, 1)
            target = root / rel.strip()
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != want:
                status = "modified"
        return {
            "gateIntegrity": status,
            "gateManifestSha": hashlib.sha256(raw).hexdigest(),
        }
    except Exception:
        # An unreadable manifest is not silently "verified".
        return {"gateIntegrity": "modified"}
STATE_DIR = Path(os.environ.get("XCHK_STATE_DIR", "~/.xchk/claude-runs")).expanduser()
CONFIG_PATH = Path(os.environ.get("XCHK_CONFIG", "~/.xchk/claude.json")).expanduser()
SESSION_ID_RE = re.compile(r"[^A-Za-z0-9_-]")

# Claude Code tool -> xchk authorize vocabulary
TOOL_MAP = {
    "Bash": "terminal",
    "Write": "write_file",
    "Edit": "patch",
    "MultiEdit": "patch",
    "NotebookEdit": "patch",
    "Read": "read_file",
}


def load_config() -> dict:
    cfg = {}
    if CONFIG_PATH.exists():
        try:
            mode = CONFIG_PATH.stat().st_mode & 0o777
            if mode & 0o077:
                CONFIG_PATH.chmod(0o600)
            cfg = json.loads(CONFIG_PATH.read_text()) or {}
        except (OSError, ValueError):
            cfg = {}
    env = {
        "api_key": os.environ.get("XCHK_API_KEY"),
        "base": os.environ.get("XCHK_BASE"),
        "approver": os.environ.get("XCHK_APPROVER"),
        "fail_closed": os.environ.get("XCHK_FAIL_CLOSED"),
        "attest_timeout": os.environ.get("XCHK_ATTEST_TIMEOUT"),
    }
    for k, v in env.items():
        if v not in (None, ""):
            cfg[k] = v
    cfg["fail_closed"] = str(cfg.get("fail_closed", "0")).lower() in ("1", "true", "yes")
    try:
        cfg["attest_timeout"] = float(cfg.get("attest_timeout", 600))
    except (TypeError, ValueError):
        cfg["attest_timeout"] = 600.0
    return cfg


def make_client(cfg: dict) -> XchkClient:
    client = XchkClient(api_key=cfg.get("api_key"), base_url=cfg.get("base"))
    if client.base_url.startswith("http://") and os.environ.get("XCHK_ALLOW_INSECURE") != "1":
        # Refuse to send credentials or tickets in cleartext.
        client.api_key = None
    return client


def state_path(session_id: str) -> Path:
    safe = SESSION_ID_RE.sub("_", str(session_id or "unknown"))[:96]
    return STATE_DIR / f"{safe}.json"


def load_run(session_id: str) -> dict | None:
    p = state_path(session_id)
    if not p.exists():
        return None
    try:
        run = json.loads(p.read_text()) or None
    except (OSError, ValueError):
        return None
    if run and run.get("expiresAt", 0) > time.time() + 60:
        return run
    try:
        p.unlink()
    except OSError:
        pass
    return None


def save_run(session_id: str, run: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    p = state_path(session_id)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(run, f)


def drop_run(session_id: str) -> None:
    try:
        state_path(session_id).unlink()
    except OSError:
        pass


def controlling_tty() -> str | None:
    """Terminal of the nearest ancestor that still owns one — 'ttys003'.
    Hooks are spawned detached ('??'), but the claude binary or its shell
    up the chain holds the window; walk parents until we find it."""
    try:
        import subprocess
        pid = os.getppid()
        for _ in range(6):
            if pid <= 1:
                break
            parts = subprocess.run(
                ["ps", "-o", "tty=,ppid=", "-p", str(pid)],
                capture_output=True, text=True, timeout=5,
            ).stdout.split()
            if not parts:
                break
            tty = parts[0]
            if tty and tty != "??":
                return tty
            pid = int(parts[1]) if len(parts) > 1 else 0
    except Exception:
        pass
    return None


def dispatch(client: XchkClient, session_id: str) -> dict | None:
    # Routed work declares its assignment at dispatch (console "working on"
    # line); set by the start command's environment, absent otherwise.
    task_label = (os.environ.get("XCHK_TASK_LABEL") or "").strip() or None
    # sessionRef carries terminal attribution: "ttys003@bunnymini#6ba2c9f1"
    tty = controlling_tty()
    host = socket.gethostname().split(".")[0]
    session_ref = f"{tty or 'tty?'}@{host}#{(session_id or '')[:8]}"
    resp = client.dispatch_run(harness="claude", session_ref=session_ref,
                               task_label=task_label)
    if not resp:
        return None
    run_info = resp.get("run") or {}
    ttl_hint = run_info.get("expiresAt")
    try:
        expires = time.mktime(time.strptime(ttl_hint[:19], "%Y-%m-%dT%H:%M:%S")) if ttl_hint else time.time() + 8 * 3600
    except (TypeError, ValueError):
        expires = time.time() + 8 * 3600
    run = {
        "runSeq": run_info.get("runSeq"),
        "runRef": run_info.get("runRef"),
        "plate": run_info.get("agentPlate"),
        "ticket": resp.get("runTicket"),
        "startedAt": time.time(),
        "expiresAt": expires,
    }
    save_run(session_id, run)
    return run


def emit(event: str, extra: dict) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": event, **extra}}))


def decide(decision: str, reason: str) -> None:
    emit("PreToolUse", {"permissionDecision": decision, "permissionDecisionReason": reason[:500]})
    sys.exit(0)


def on_session_start(data: dict, cfg: dict, client: XchkClient) -> None:
    if not client.configured:
        return
    # Host identity: the configured guarded_host wins; otherwise the SHORT
    # hostname — macOS gethostname() returns "name.local", and reporting
    # that would mint a duplicate install slot beside "name".
    short = socket.gethostname().split(".")[0]
    host = (cfg.get("guarded_host") or "").strip() or short
    client.report_harness_install(
        "claude",
        pluginInstalled=True,
        apiKeyConfigured=True,
        approverConfigured=bool(cfg.get("approver")),
        ready=True,
        guardedHost=host,
        hostLabel=short,
        pluginVersion=PLUGIN_VERSION,
        **gate_integrity(),
    )
    session_id = data.get("session_id") or ""
    run = load_run(session_id) or dispatch(client, session_id)
    if run and run.get("runRef"):
        emit("SessionStart", {
            "additionalContext": (
                f"This session operates under xChk license {run.get('plate') or ''} "
                f"as run {run.get('runRef')}. Gated actions require authorization; "
                f"some will wait for human approval."
            ),
        })


def summarize(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Bash":
        return str(tool_input.get("command") or "")[:300]
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    return f"{tool_name} {path}"[:300]


def on_pre_tool_use(data: dict, cfg: dict, client: XchkClient) -> None:
    tool_name = data.get("tool_name") or ""
    tool_input = data.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    mapped = TOOL_MAP.get(tool_name)
    if not mapped:
        sys.exit(0)  # ungated tool — defer to normal permission flow

    if not client.configured:
        if cfg["fail_closed"]:
            decide("deny", "xchk: license client not configured and XCHK_FAIL_CLOSED is set")
        sys.exit(0)

    session_id = data.get("session_id") or ""
    run = load_run(session_id) or dispatch(client, session_id)
    ticket = (run or {}).get("ticket")
    run_ref = (run or {}).get("runRef") or "unlicensed"

    args = {}
    if mapped == "terminal":
        args["command"] = str(tool_input.get("command") or "")
    else:
        args["path"] = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")

    summary = summarize(tool_name, tool_input)
    auth = client.authorize(mapped, args, prompt=f"Claude Code {tool_name}", danger_desc=summary, run_ticket=ticket)

    if auth.get("skip") and auth.get("reason") == "invalid_run_ticket":
        drop_run(session_id)
        run = dispatch(client, session_id)
        ticket = (run or {}).get("ticket")
        auth = client.authorize(mapped, args, prompt=f"Claude Code {tool_name}", danger_desc=summary, run_ticket=ticket)

    if auth.get("skip"):
        if cfg["fail_closed"]:
            decide("deny", f"xchk: license server unavailable ({auth.get('reason')}) — failing closed")
        sys.exit(0)

    area = auth.get("area") or "?"
    if auth.get("disposition") == "allow":
        _record(auth.get("authRef"), mapped, summary or tool_name, client, auth.get("paramsHash"))
        decide("allow", f"xchk: allowed under {run_ref} (area {area})")
    if auth.get("disposition") == "forbid":
        decide("deny", f"xchk: forbidden by license grant (area {area}): {auth.get('reason') or 'forbid'}")

    # attest — human approval required
    approver = cfg.get("approver")
    if not approver:
        decide("ask", f"xchk: area {area} requires attestation and no remote approver is configured — asking locally")

    att_id, err = client.create_attestation(
        prompt=f"{run_ref} (via Claude Code) wants to {summary or tool_name}",
        target_email=approver,
        tool_name=mapped,
        args=args,
        action_summary=summary,
        auth=auth,
        ttl=int(cfg["attest_timeout"]),
    )
    if not att_id:
        if cfg["fail_closed"]:
            decide("deny", f"xchk: could not create attestation ({err}) — failing closed")
        decide("ask", f"xchk: could not reach approver ({err}) — asking locally")

    result = client.poll_attestation(att_id, timeout_seconds=cfg["attest_timeout"])
    if result.get("status") == "completed" and result.get("response") in (True, "true", "yes", 1, "approved"):
        _record(auth.get("authRef"), mapped, summary or tool_name, client, auth.get("paramsHash"))
        decide("allow", f"xchk: approved by {approver} (attestation {att_id}, area {area}, {run_ref})")
    if result.get("status") == "declined":
        decide("deny", f"xchk: DENIED by {approver} (attestation {att_id})")
    decide("deny", f"xchk: approval {result.get('status') or 'failed'} (attestation {att_id}) — not executing")


def elapsed_str(run: dict) -> str:
    secs = max(0, int(time.time() - (run.get("startedAt") or time.time())))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def on_heartbeat(data: dict, client: XchkClient) -> None:
    """Stop event — one terse work report per completed turn: 'RUNNING 0:10'.

    Also flushes the local recorder (MACG-004 triangle): submit this turn's
    accumulated local-chain entries so the registry can reconcile issued
    authRefs against executed actions.
    """
    run = load_run(data.get("session_id") or "")
    if run and run.get("runSeq") is not None and client.configured:
        client.report_run(run["runSeq"], f"RUNNING {elapsed_str(run)}")
    r = _recorder()
    if r and client.configured:
        # force_empty: a quiet turn still attests silence (rate-limited
        # inside flush) — the host half of bilateral provable silence.
        r.flush(client, run_ref=(run or {}).get("runRef"), force_empty=True)


def on_session_end(data: dict, client: XchkClient) -> None:
    session_id = data.get("session_id") or ""
    run = load_run(session_id)
    if run and run.get("runSeq") is not None and client.configured:
        client.report_run(run["runSeq"], f"ENDED {elapsed_str(run)}")
        client.end_run(run["runSeq"])
    r = _recorder()
    if r and client.configured:
        r.flush(client, run_ref=(run or {}).get("runRef"), force_empty=True)
    drop_run(session_id)


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES)
    try:
        data = json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        sys.exit(0)
    if not isinstance(data, dict):
        sys.exit(0)

    cfg = load_config()
    client = make_client(cfg)
    event = data.get("hook_event_name") or ""
    try:
        if event == "SessionStart":
            on_session_start(data, cfg, client)
        elif event == "PreToolUse":
            on_pre_tool_use(data, cfg, client)
        elif event == "Stop":
            on_heartbeat(data, client)
        elif event == "SessionEnd":
            on_session_end(data, client)
    except SystemExit:
        raise
    except Exception as e:  # never crash the harness; honor fail-closed for gated tools
        if event == "PreToolUse" and cfg.get("fail_closed"):
            decide("deny", f"xchk: hook error ({e.__class__.__name__}) — failing closed")
        sys.exit(0)


if __name__ == "__main__":
    main()

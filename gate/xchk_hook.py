#!/usr/bin/env python3
"""xChk license hook for Claude Code and Cursor — one session = one run.

SessionStart  -> harness check-in + dispatch a run (PLATE.N) for this session
PreToolUse    -> authorize the proposed action under the run ticket
                 (allow / forbid / attest-with-human-approval)
SessionEnd    -> end the run

TWO HARNESSES, ONE GATE. Cursor reads Claude Code's hook registration from
.claude/settings.json, maps the event names, and honours the nested
hookSpecificOutput.permissionDecision this file already emits — verified
empirically 2026-08-11 (a Write refused by this shape never reached disk).
What Cursor does NOT do is rename the payload: it arrives in Cursor's own
dialect, hook_event_name == 'preToolUse', lowercase. Exact-match dispatch
therefore matches nothing, exits 0, and ALLOWS EVERY GATED ACTION — a gate
that installs cleanly, runs without error, and refuses nothing. Event names
are normalised (see _EVENTS) for exactly that reason; the test asserting the
lowercase spellings route is not optional.

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

import calendar
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
SESSION_ID_RE = re.compile(r"[^A-Za-z0-9_-]")

# Harness tool -> xchk authorize vocabulary. Claude Code and Cursor happen to
# agree on Read/Write/Edit; Cursor calls the terminal "Shell". A name absent
# here is UNGATED, so this table is the coverage boundary: Cursor's editor
# surface is only proven for Write, and any further edit tool it ships (under
# whatever name) passes unauthorized until it is added and probed. Per-area
# coverage, not per-harness — see docs/multi-harness-runs.md.
TOOL_MAP = {
    "Bash": "terminal",
    "Shell": "terminal",          # Cursor
    "Write": "write_file",
    "Edit": "patch",
    "MultiEdit": "patch",
    "NotebookEdit": "patch",
    "Read": "read_file",
}

# Harness bookkeeping that arrives through the model's own Write tool. Cursor
# writes agent scratch to ~/.cursor/projects/<slug>/agent-tools/<uuid>.txt, and
# gating it would put the plate's name on the harness's internal filing — noise
# in the record at best, and at worst a human-approval prompt over a UUID no
# operator could adjudicate. Deferred to the harness's own permission flow,
# never recorded as an allow: it is not the agent acting on the user's work.
INTERNAL_PATH_RE = re.compile(r"/\.cursor/projects/[^/]+/agent-tools/")

# Wire name -> display name. The wire name keys the install slot, so a harness
# missing here would silently share Claude's slot; resolve_harness() defaults
# conservatively and the label is cosmetic.
HARNESS_LABELS = {"claude": "Claude Code", "cursor": "Cursor"}

# Set once in main() from the payload, before any path is resolved.
HARNESS = "claude"
HARNESS_LABEL = "Claude Code"
STATE_DIR = Path("~/.xchk/claude-runs").expanduser()
CONFIG_PATH = Path("~/.xchk/claude.json").expanduser()


def resolve_harness(data: dict) -> str:
    """Which harness is calling. XCHK_HARNESS wins (the hook registration sets
    it); otherwise sniff the payload, because the failure mode of guessing
    "claude" for a Cursor session is not cosmetic — both harnesses would report
    into ONE (harness, guardedHost) install slot, so revoking the key for one
    silently disarms the other, and the console would show a single covered
    surface where two are running."""
    env = (os.environ.get("XCHK_HARNESS") or "").strip().lower()
    if env:
        return env
    if data.get("cursor_version"):
        return "cursor"
    return "claude"


def apply_harness(harness: str) -> None:
    """Bind this process to one harness: label, config, run state. Separate
    state dirs matter — run tickets are per-install, and one dir would let a
    Cursor session load a Claude session's ticket on a session_id collision."""
    global HARNESS, HARNESS_LABEL, STATE_DIR, CONFIG_PATH
    HARNESS = harness or "claude"
    HARNESS_LABEL = HARNESS_LABELS.get(HARNESS, HARNESS.title())
    STATE_DIR = Path(
        os.environ.get("XCHK_STATE_DIR") or f"~/.xchk/{HARNESS}-runs"
    ).expanduser()
    CONFIG_PATH = Path(
        os.environ.get("XCHK_CONFIG") or f"~/.xchk/{HARNESS}.json"
    ).expanduser()


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
    resp = client.dispatch_run(harness=HARNESS, session_ref=session_ref,
                               task_label=task_label)
    if not resp:
        return None
    run_info = resp.get("run") or {}
    ttl_hint = run_info.get("expiresAt")
    # expiresAt is UTC ISO ("...Z"); timegm reads the struct as UTC. mktime
    # reads it as LOCAL, which put expiry hours late on any non-UTC host and
    # blinded the renew-before-expiry check in load_run() — the client went on
    # presenting a ticket the server had already expired.
    try:
        expires = (calendar.timegm(time.strptime(ttl_hint[:19], "%Y-%m-%dT%H:%M:%S"))
                   if ttl_hint else time.time() + 8 * 3600)
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


# Every spelling either harness delivers, folded to the canonical name this
# file dispatches on. Claude Code sends PascalCase; Cursor sends its own
# lowerCamel names for the same events. An unlisted spelling is not an error
# and not a refusal — it exits 0 — so this table is load-bearing for coverage.
_EVENTS = {
    "sessionstart": "SessionStart",
    "pretooluse": "PreToolUse",
    "stop": "Stop",
    "sessionend": "SessionEnd",
}


_LICENSE_HEADER = "X-Xchk-License"


def stamp_license_header(plate: str) -> None:
    """Put the plate into ~/.claude/settings.json env.ANTHROPIC_CUSTOM_HEADERS
    so EVERY claude session on this host — user-launched included — stamps
    'X-Xchk-License: <plate>' on every model call, for a corp gateway to log
    and query by plate. Claude Code reads that env once at startup, so this is
    static (plate scope, not run) and self-heals: the gate learns the plate at
    dispatch and writes it, and every session from then on carries it.

    Claude only. Cursor routes model calls through its own backend and Hermes
    through its own runtime; neither honours ANTHROPIC_CUSTOM_HEADERS, so their
    plate injection is a separate vector.

    Surgical: loads the whole settings file, touches only
    env.ANTHROPIC_CUSTOM_HEADERS, preserves every other env var and any other
    custom header lines, replaces (never duplicates) a prior X-Xchk-License,
    and writes only when the value actually changes — so it does not churn the
    user's settings on every session.
    """
    if HARNESS != "claude" or not plate:
        return
    path = Path("~/.claude/settings.json").expanduser()
    if not path.is_file():
        return  # the gate runs FROM this file — missing means don't conjure one
    try:
        settings = json.loads(path.read_text())
    except (OSError, ValueError):
        return  # never overwrite an unreadable/foreign settings file
    if not isinstance(settings, dict):
        return
    env = settings.get("env")
    if not isinstance(env, dict):
        env = {}
    raw = env.get("ANTHROPIC_CUSTOM_HEADERS") or ""
    # Header lines are newline-separated "Name: value"; keep everyone else's.
    kept = [ln for ln in raw.split("\n")
            if ln.strip() and not ln.strip().lower().startswith(_LICENSE_HEADER.lower() + ":")]
    kept.append(f"{_LICENSE_HEADER}: {plate}")
    new_value = "\n".join(kept)
    if raw == new_value:
        return  # already correct — do not rewrite the file
    env["ANTHROPIC_CUSTOM_HEADERS"] = new_value
    settings["env"] = env
    try:
        tmp = path.with_suffix(".json.xchk-tmp")
        tmp.write_text(json.dumps(settings, indent=2))
        tmp.replace(path)  # atomic — a half-written settings.json bricks claude
    except OSError:
        pass


def emit(event: str, extra: dict) -> None:
    # Cursor maps Claude Code's nested permissionDecision to its own permission
    # field, which is why one gate serves both — but that mapping covers the
    # DECISION only. additionalContext has no Cursor equivalent, so the licence
    # banner emitted in Claude's shape is silently dropped and a Cursor session
    # never learns it is licensed: no plate in context, nothing for the model
    # to cite, and an operator with no sign the gate is even there. Cursor's
    # own sessionStart contract is a flat {additional_context}.
    if HARNESS == "cursor" and "additionalContext" in extra:
        print(json.dumps({"additional_context": extra["additionalContext"]}))
        return
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
        HARNESS,
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
    # Stamp the plate into the host's model-call headers for the corp gateway.
    # Written every session but no-ops unless the value changed, so it settles
    # after the first dispatch and stays put.
    stamp_license_header((run or {}).get("plate"))
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

    target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    if mapped != "terminal" and target and INTERNAL_PATH_RE.search(target):
        sys.exit(0)  # harness's own scratch — see INTERNAL_PATH_RE

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
    auth = client.authorize(mapped, args, prompt=f"{HARNESS_LABEL} {tool_name}", danger_desc=summary, run_ticket=ticket)

    # Renew, don't refuse: an aged-out ticket on a live plate means only the
    # clock ran out, so re-dispatch for THIS session and carry on. A wrong or
    # revoked licence still refuses — that path returns a real forbid.
    if auth.get("skip") and auth.get("reason") == "invalid_run_ticket":
        drop_run(session_id)
        run = dispatch(client, session_id)
        ticket = (run or {}).get("ticket")
        # The old ref named an expired run; attribute to the successor.
        run_ref = (run or {}).get("runRef") or run_ref
        auth = client.authorize(mapped, args, prompt=f"{HARNESS_LABEL} {tool_name}", danger_desc=summary, run_ticket=ticket)

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
        prompt=f"{run_ref} (via {HARNESS_LABEL}) wants to {summary or tool_name}",
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

    apply_harness(resolve_harness(data))
    cfg = load_config()
    client = make_client(cfg)
    event = _EVENTS.get(str(data.get("hook_event_name") or "").lower(), "")
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

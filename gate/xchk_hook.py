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
  - Fail-closed is the default: gated tools are denied when the license
    server is unreachable. Set XCHK_FAIL_CLOSED=0 to degrade open on a dev box.
"""

from __future__ import annotations

import base64
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
try:
    from xchk_labels import classify_tool_input  # noqa: E402
except Exception:  # pragma: no cover - classification never breaks the gate
    classify_tool_input = None

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

PLUGIN_VERSION = "0.1.10"
MAX_STDIN_BYTES = 512 * 1024


# Written into the manifest header by the install scripts. Its presence means
# the manifest was generated on this host from files already on disk, so it
# cannot attest to issuer provenance — only to stability since install.
INSTALL_TIME_MANIFEST_MARKER = "provenance: install-time"


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
        text = raw.decode()
        # A manifest minted at INSTALL time hashes whatever arrived — including a
        # tampered download — so matching it proves only "unchanged since install",
        # never "matches what the issuer released". Reporting that as "verified"
        # is a false green: the console shows the strongest word for the weakest
        # claim. Such manifests carry an explicit provenance marker (written by
        # install-*-xchk.sh) and are reported as "self-manifested" instead —
        # still useful (it catches post-install tampering), just not a release
        # claim. See make-manifest.py, which forbids install-time generation for
        # this reason.
        self_minted = INSTALL_TIME_MANIFEST_MARKER in text
        status = "self-manifested" if self_minted else "verified"
        for line in text.splitlines():
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
# here is no longer ungated: unknown tools fall through to CATCHALL_WIRE and
# are authorized under the license like everything else (grants decide the
# disposition; an unconfigured area lands on the default, attest). Only names
# in UNGATED_TOOLS bypass the gate. Per-area coverage, not per-harness — see
# docs/multi-harness-runs.md.
TOOL_MAP = {
    "Bash": "terminal",
    "Shell": "terminal",          # Cursor
    "Write": "write_file",
    "Edit": "patch",
    "MultiEdit": "patch",
    "NotebookEdit": "patch",
    "Read": "read_file",
    # Subagent spawning IS a gated action: an ungated spawn is a delegation
    # edge that never touches the licence — the child works under the parent's
    # run with no authorization, no ledger entry, no delegationChain. "Task"
    # is Claude Code's classic name; "Agent" and "Workflow" are the newer
    # harness spellings for the same capability.
    "Task": "spawn_agent",
    "Agent": "spawn_agent",
    "Workflow": "spawn_agent",
}

# Tools that delegate work to a subagent. Their authorize call carries an
# explicit actionArea (area inference reads command/path text, and a spawn has
# neither) and a delegationChain naming this run as the parent, so the edge
# lands on the record in the registry's own vocabulary.
SPAWN_TOOLS = {"Task", "Agent", "Workflow"}
SPAWN_AREA = "operations"

# The coverage boundary, inverted: names listed here are the ONLY tools that
# bypass the license. Read-only introspection and harness bookkeeping — the
# harness asking the model questions or the model asking the human — where a
# plate on the record would be noise no approver could adjudicate. Everything
# else (MCP tools, WebFetch/WebSearch, tools shipped after this file) goes to
# the server under CATCHALL_WIRE with the raw tool name and a truncated input
# preview, so an email connector is gated the day it appears, not the day
# someone remembers to map it.
UNGATED_TOOLS = {
    "Glob", "Grep", "LS", "TodoWrite", "TodoRead", "AskUserQuestion",
    "BashOutput", "KillBash", "EnterPlanMode", "ExitPlanMode",
    "Skill", "SlashCommand", "ToolSearch",
}
CATCHALL_WIRE = "tool"

# Harness bookkeeping that arrives through the model's own Write tool. Cursor
# writes agent scratch to ~/.cursor/projects/<slug>/agent-tools/<uuid>.txt, and
# gating it would put the plate's name on the harness's internal filing — noise
# in the record at best, and at worst a human-approval prompt over a UUID no
# operator could adjudicate. Deferred to the harness's own permission flow,
# never recorded as an allow: it is not the agent acting on the user's work.
INTERNAL_PATH_RE = re.compile(r"/\.cursor/projects/[^/]+/agent-tools/")

# ── Gate self-protection ──────────────────────────────────────────────────────
# A grant is authority over the USER'S work, never over the gate itself. With
# disposition "allow" on the files or terminal area, one Write to
# ~/.xchk/claude.json (or an `echo XCHK_FAIL_CLOSED=0 >> ~/.zshrc`) silently
# disarms or redirects the gate at the next session start. Gate-critical paths
# are therefore hard-denied BEFORE grant evaluation — no grant, no approver,
# and no fail-open setting authorizes the agent to touch them. Changing them
# is done from a shell the agent does not drive.

SHELL_INIT_NAMES = (
    ".zshrc", ".zshenv", ".zprofile", ".zlogin",
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
)
# Distinctive enough to deny by basename wherever they live: the repo
# checkout, the installed copy, or a staged copy about to be swapped in.
# ".xchk" is the PROJECT MARKER: it names the plate a tree runs as (local
# identity broker). Letting the agent write it would let the agent choose
# its own identity, so it is denied by basename wherever it is written.
GATE_FILE_NAMES = ("xchk_hook.py", "xchk_client.py", ".xchk")
# Env vars that would disarm or redirect the gate in a future session.
GATE_ENV_NAMES = ("XCHK_FAIL_CLOSED", "XCHK_CONFIG", "XCHK_STATE_DIR",
                  "XCHK_BASE", "XCHK_ALLOW_INSECURE")


def protected_roots() -> list:
    """Files and directory prefixes no grant may authorize modification of.
    Computed per call, after apply_harness(): STATE_DIR and CONFIG_PATH honour
    their env overrides, so a redirected config is protected at its real
    location, not just the default one."""
    home = Path.home()
    return [
        home / ".xchk",                            # config, tickets, installed gate
        PLUGIN_ROOT,                               # this checkout of the gate
        STATE_DIR, CONFIG_PATH,                    # env-overridden locations too
        home / ".claude" / "settings.json",        # hook registration + env
        home / ".claude" / "settings.local.json",
        home / ".cursor" / "settings.json",        # Cursor-side registration
        home / ".cursor" / "hooks.json",
        *(home / n for n in SHELL_INIT_NAMES),     # future-session environment
    ]


def screened_roots() -> list:
    """Roots whose SPELLING is denied inside an unparsed shell command.

    Narrower than protected_roots() by exactly one member: PLUGIN_ROOT. The
    checkout holds no key and enforces nothing — it becomes the gate only
    through a signed install, which re-manifests it. Screening it denied
    `git log`, `ls`, and `grep` in the repo, i.e. the ordinary work of
    maintaining the gate, and a screen that fires on innocent commands is the
    fastest way to get the gate switched off.

    Write/Edit denial is UNCHANGED: is_protected_path() still consults
    protected_roots(), and GATE_FILE_NAMES still denies the gate files by
    basename wherever they are written.

    Known and accepted: a command reaching the checkout by glob without naming
    the files (`sed -i '' s/x/y/ .../gate/*.py`) now passes the screen. The
    checkout is not the gate; gate_integrity() reports "modified" if a tampered
    copy is ever installed. Tamper-evident, never tamper-proof.

    Computed per call, like protected_roots(): do NOT memoise. An env-redirected
    CONFIG_PATH/STATE_DIR must be screened at its real location.
    """
    plugin = _resolve(PLUGIN_ROOT)
    return [r for r in protected_roots() if _resolve(r) != plugin]


def _resolve(path) -> Path:
    """expandvars + expanduser + realpath: env-var spellings ($HOME,
    ${HOME}), ~, symlinks and ../ hops all land on the real target, and
    realpath tolerates a nonexistent tail (a Write creating the file).
    expandvars runs FIRST so an env-var spelling of a protected path
    resolves to the same target the shell would reach — F1: keep the
    file-path check at least as broad as the bash screen."""
    try:
        return Path(os.path.realpath(Path(os.path.expandvars(str(path))).expanduser()))
    except (OSError, ValueError):
        return Path(str(path))


def is_protected_path(target: str) -> bool:
    if not target:
        return False
    t = _resolve(target)
    # Fail-safe: a candidate that STILL contains "$" after expansion names
    # an env var unset in the gate's own process. We cannot know where it
    # points, so we must not clear it — treat an unexpanded $VAR/${VAR} in a
    # protected-path candidate as protected (F1).
    if "$" in str(t):
        return True
    if t.name in GATE_FILE_NAMES:
        return True
    return any(t == r or r in t.parents for r in map(_resolve, protected_roots()))


_BOUNDARY = r"(?:^|[\s\"'=:;|&(<>`])"


def bash_screen():
    """Spelling screen for shell commands. The command is an opaque string —
    the shell expands it, not us — so this matches SPELLINGS of the protected
    set (absolute, ~/, $HOME/, ${HOME}/ forms, bare basenames after a word
    boundary) plus the gate's env var names. Deliberately over-broad: a
    `cat ~/.zshrc` is denied alongside an `echo ... >> ~/.zshrc`, because
    read vs write cannot be told apart in an unparsed string, and ~/.xchk
    holds the API key besides. Fail-safe wins; the denial reason says why."""
    home = str(Path.home())
    forms = set(GATE_FILE_NAMES) | set(SHELL_INIT_NAMES) | set(GATE_ENV_NAMES)
    forms.add(".xchk")
    for root in screened_roots():
        s = str(root)
        forms.add(s)
        if s.startswith(home):
            rel = s[len(home):]
            forms.update(("~" + rel, "$HOME" + rel, "${HOME}" + rel))
    alts = "|".join(sorted(map(re.escape, forms), key=len, reverse=True))
    return re.compile(_BOUNDARY + "(?:" + alts + ")")


def _deobfuscate(command: str) -> str:
    """Best-effort static expansion of common encodings in a shell command, so
    the spelling screen also sees a protected path an agent tried to HIDE from
    it (e.g. `echo <base64> | base64 -d`). Closes the demonstrated F2 evasion
    without over-denying: it only ADDS matchable text, and only a decode that
    reconstructs a protected spelling changes any outcome. NOT complete — a
    name assembled at runtime (`${V}_CLOSED`), read from a file, or produced by
    a wrapper binary stays opaque to static analysis; that residual is F2's
    stated limit, addressed by recording the attempt, not a bigger regex.
    See bypass-detection-benchmark-results.md, finding F2."""
    if not command:
        return ""
    shadow = []
    for blob in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", command):
        try:
            dec = base64.b64decode(blob, validate=True).decode("utf-8")
        except Exception:
            continue
        if dec.isprintable():
            shadow.append(dec)
    for hexrun in re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", command):
        try:
            dec = bytes.fromhex(hexrun.replace("\\x", "")).decode("utf-8")
        except Exception:
            continue
        if dec.isprintable():
            shadow.append(dec)
    return " ".join(shadow)


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


def _broker_resolve(harness: str) -> None:
    """LOCAL identity broker (identity-resolution architecture, increment 3).

    If this session was not handed an explicit credential, walk up from cwd
    to the nearest `.xchk` PROJECT MARKER (a plain FILE naming a plate; a
    `.xchk` directory is ignored — only the file form is basename-protected
    from agent writes) and load that plate's envelope from the resident
    manager's store. The envelope supplies key / state dir / base /
    approver / per-plate config, injected through the SAME env vars the
    explicit path uses — so downstream path computation, the session
    credential-scope rule, and protected-roots are unchanged. Two sessions
    in two trees resolve to two plates: coexistence with no host-global
    credential, and the approver rides in with the envelope.

    Precedence: an explicit XCHK_API_KEY wins (deliberate override).
    Trust: the marker only NAMES a plate — authority comes from the
    envelope the operator's manager stored (mode 600, under a protected
    root). No marker, no envelope, or any error -> unchanged behavior;
    brokering must never break the gate.
    """
    if os.environ.get("XCHK_API_KEY"):
        return
    try:
        here = Path.cwd()
        marker = None
        for d in (here, *here.parents):
            cand = d / ".xchk"
            if cand.is_file():
                marker = cand
                break
        if marker is None:
            return
        raw = marker.read_text().strip()
        try:
            plate = str(json.loads(raw).get("plate") or "").strip().upper()
        except ValueError:
            plate = raw.split()[0].strip().upper() if raw else ""
        if not plate or not re.fullmatch(r"[A-Z0-9-]{3,16}", plate):
            return
        mgr = Path(os.environ.get("XCHK_MANAGER_DIR", "~/.xchk/manager")).expanduser()
        env_path = mgr / "envelopes" / f"{plate}.json"
        if not env_path.is_file():
            return
        mode = env_path.stat().st_mode & 0o777
        if mode & 0o077:
            env_path.chmod(0o600)
        envd = json.loads(env_path.read_text()) or {}
        key = envd.get("api_key")
        if not key:
            return
        os.environ["XCHK_API_KEY"] = str(key)
        if not os.environ.get("XCHK_STATE_DIR"):
            state = envd.get("state_dir") or str(
                Path("~/.xchk").expanduser() / f"{(harness or 'claude')}-runs-{plate}")
            os.environ["XCHK_STATE_DIR"] = state
        for env_name, field in (("XCHK_BASE", "base"),
                                ("XCHK_APPROVER", "approver"),
                                ("XCHK_CONFIG", "config")):
            if envd.get(field) and not os.environ.get(env_name):
                os.environ[env_name] = str(envd[field])
    except (OSError, ValueError):
        return


def apply_harness(harness: str) -> None:
    """Bind this process to one harness: label, config, run state. Separate
    state dirs matter — run tickets are per-install, and one dir would let a
    Cursor session load a Claude session's ticket on a session_id collision."""
    # Resolve brokered identity FIRST, so STATE_DIR/CONFIG_PATH below are
    # computed from the envelope's env exactly as from an explicit launch.
    _broker_resolve(harness)
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
        # Session-scoped iff this session was handed BOTH its own
        # credential and its own chain state. Sharing the harness-wide
        # state directory means sharing a chain, which is not a separate
        # install no matter whose key it holds.
        "credential_scope": (
            "session"
            if os.environ.get("XCHK_API_KEY") and os.environ.get("XCHK_STATE_DIR")
            else "host"
        ),

    }
    file_fail_closed = cfg.get("fail_closed")
    for k, v in env.items():
        if v not in (None, ""):
            cfg[k] = v
    cfg["fail_closed"] = str(cfg.get("fail_closed", "1")).lower() in ("1", "true", "yes")
    _record_posture(cfg["fail_closed"], env.get("fail_closed"), file_fail_closed)
    try:
        cfg["attest_timeout"] = float(cfg.get("attest_timeout", 600))
    except (TypeError, ValueError):
        cfg["attest_timeout"] = 600.0
    return cfg


def _record_posture(effective: bool, env_value, file_value) -> None:
    """Record the fail-closed value the gate ACTUALLY enforced, and its source.

    The registry cannot learn this any other way. Only this process sees the
    environment the harness handed it, which is exactly the channel a shell-rc
    disarm travels on — so a value derived anywhere else would report the
    config file's claim rather than the enforced truth, and a console that
    reports a claim as if it were enforcement is worse than one that reports
    nothing.

    Written on change only: the hook runs on every gated tool call, and this
    would otherwise be a disk write per call for a value that moves about once
    a quarter.
    """
    source = ("env" if env_value not in (None, "")
              else "config" if file_value is not None
              else "default")
    posture = {
        "fail_closed": bool(effective),
        "source": source,
        # Kept apart from the effective value so the console can say "config
        # says closed, environment says open" — the state worth shouting
        # about, and the one a single boolean hides.
        "config_fail_closed": (None if file_value is None
                               else str(file_value).lower() in ("1", "true", "yes")),
        "env_fail_closed": (None if env_value in (None, "")
                            else str(env_value).lower() in ("1", "true", "yes")),
    }
    try:
        path = STATE_DIR / "posture.json"
        if path.exists():
            try:
                prior = json.loads(path.read_text())
                if {k: prior.get(k) for k in posture} == posture:
                    return
            except (OSError, ValueError):
                pass
        from datetime import datetime, timezone
        posture["at"] = datetime.now(timezone.utc).isoformat()
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(posture, sort_keys=True))
        tmp.replace(path)
        path.chmod(0o600)
    except OSError:
        # Never fail a tool call to record telemetry about a tool call.
        pass


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


def decide(decision: str, reason: str, updated_input: dict | None = None) -> None:
    out = {"permissionDecision": decision, "permissionDecisionReason": reason[:500]}
    if updated_input is not None:
        # APPROVE WITH CHANGES: what runs is the amended input, not the
        # original — Claude Code honours hookSpecificOutput.updatedInput.
        out["updatedInput"] = updated_input
    emit("PreToolUse", out)
    sys.exit(0)


def apply_amendment(mapped: str, tool_input: dict, amendment: dict | None) -> tuple[dict | None, str | None]:
    """The host's half of gap AM (6 Sep 2026). Returns (updated_input, error).
    Only a terminal command can be amended; the amended text goes through the
    same gate-critical screen as any command; Cursor has no updatedInput, so
    an amendment there is refused rather than silently running the original."""
    cmd = (amendment or {}).get("command") if isinstance(amendment, dict) else None
    if not cmd:
        return None, None
    if mapped != "terminal":
        return None, "amendment applies to shell commands only"
    if HARNESS == "cursor":
        return None, "this harness cannot run an amended command — approve unchanged, or decline"
    _scr = bash_screen()
    if _scr.search(cmd) or _scr.search(_deobfuscate(cmd)):
        return None, "the amended command references gate-critical paths or gate env vars"
    return {**tool_input, "command": str(cmd)}, None


RUNS_DIR = Path("~/.xchk/runs").expanduser()


def stamp_terminal_title(run: dict | None) -> None:
    """Put the run ref in the terminal title.

    The console can tell you FIN-RKPC.104 is the busy plate; nothing on the
    machine could tell you which window that was, so the answer involved
    correlating pids. The title bar is where a human already looks to identify
    a window.

    Writes to the controlling TTY, never stdout: stdout carries this hook's
    JSON protocol back to the harness, and an escape sequence in it corrupts
    the gate's own response. Failure is silent by design — a cosmetic title
    must never be able to affect a gate decision.
    """
    ref = (run or {}).get("runRef")
    if not ref:
        return
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(f"\033]2;{ref} · {HARNESS_LABEL}\007")   # window title
            tty.write(f"\033]1;{ref}\007")                     # tab / icon title
            tty.flush()
    except OSError:
        pass          # no controlling tty: daemon, CI, piped — nothing to title
    if os.environ.get("TMUX"):
        try:
            import subprocess
            subprocess.run(["tmux", "rename-window", ref],
                           timeout=2, capture_output=True, check=False)
        except Exception:
            pass


def write_run_file(run: dict | None, cfg: dict) -> None:
    """Declare this session's plate binding on disk, for the supervisor.

    Replaces inference. xchk_manager.scan_running() reconstructs which plate a
    process belongs to by string-matching `ps -axo command` for '-p <profile>
    chat', and _default_profile_holder() resolves the bare session by matching
    an API key on disk to an install. Both are guesses at a fact this process
    already knows, and the manager's own comments say the failure mode is
    reporting a live agent as idle — the console contradicting the machine.

    The harness owns the session; this hook is invoked per-event and exits, so
    the pid recorded is the PARENT — the long-lived harness process — not our
    own. A run file naming a dead helper is worse than no run file.

    Exception-safe throughout: this is bookkeeping for another process, and it
    must never be able to fail a SessionStart.
    """
    ref = (run or {}).get("runRef")
    if not ref:
        return
    try:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        pid = os.getppid()
        payload = {
            "runRef": ref,
            "plate": (run or {}).get("plate"),
            "profile": cfg.get("profile") or "default",
            # Which credential this install holds: "session" when the
            # operator handed it its own key AND its own chain state,
            # "host" when it is the harness-wide shared registration.
            # The registry lets differently-profiled SESSION installs
            # coexist; anything reporting "host" keeps displacing, so a
            # half-configured launch fails toward the old behaviour.
            "credentialScope": cfg.get("credential_scope") or "host",
            "harness": HARNESS,
            "pid": pid,
            "tty": os.ttyname(0) if os.isatty(0) else None,
            "cwd": os.getcwd(),
            "host": socket.gethostname().split(".")[0],
            "startedAt": time.time(),
        }
        # Atomic: a reader must never catch a half-written file and conclude
        # the binding is malformed.
        tmp = RUNS_DIR / f".{pid}.tmp"
        tmp.write_text(json.dumps(payload))
        tmp.replace(RUNS_DIR / f"{pid}.json")
    except Exception:
        pass


def drop_run_file() -> None:
    """Remove this session's run file. Best-effort only — a kill -9 or a crash
    leaves it behind, so readers must still check whether the pid is alive
    rather than trusting the file's existence."""
    try:
        (RUNS_DIR / f"{os.getppid()}.json").unlink(missing_ok=True)
    except Exception:
        pass


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
    stamp_terminal_title(run)
    write_run_file(run, cfg)
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
    if tool_name in SPAWN_TOOLS:
        # Task/Agent: {description, prompt, subagent_type}. Workflow: a script
        # whose meta carries name/description; fall back to the prompt head so
        # an approver always sees WHAT is being delegated, not just that
        # something is.
        kind = str(tool_input.get("subagent_type") or tool_input.get("name") or "").strip()
        what = str(tool_input.get("description") or tool_input.get("prompt")
                   or tool_input.get("script") or "").strip()
        return f"spawn subagent{f' [{kind}]' if kind else ''}: {what}"[:300]
    if tool_name not in TOOL_MAP:
        # Catch-all tools (MCP connectors, WebFetch, anything unmapped): show
        # the most intent-bearing field so the approver adjudicates an action,
        # not a bare tool name.
        what = str(tool_input.get("url") or tool_input.get("query")
                   or tool_input.get("command") or tool_input.get("prompt")
                   or tool_input.get("description") or "").strip()
        if not what:
            what = ", ".join(f"{k}={str(v)[:40]}" for k, v in list(tool_input.items())[:4])
        return f"{tool_name}: {what}"[:300]
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    return f"{tool_name} {path}"[:300]


def parent_chain(run: dict | None) -> list | None:
    """This run's identity as a one-entry delegationChain — the parent edge
    of the spawn being authorized. Field names are the server's
    normalizeDelegationChain vocabulary; entries with no identity at all are
    dropped server-side, so an unlicensed session simply declares nothing."""
    plate = (run or {}).get("plate")
    run_ref = (run or {}).get("runRef")
    if not (plate or run_ref):
        return None
    return [{
        "agentPlate": plate,
        "agentName": run_ref or plate,
        "role": "parent",
    }]



# ===== xChk engine-block + destructive-fs (applied by apply-engine-block.py) =====
import re as _xk_re
import shlex as _xk_shlex

_XK_CTX_WINDOWS = [("[1m]", 1_000_000), ("-1m", 1_000_000)]
_XK_CTX_DEFAULT = 200_000
_XK_TAIL_BYTES = 512 * 1024


def _xk_ctx_window(model):
    m = (model or "").lower()
    for marker, size in _XK_CTX_WINDOWS:
        if marker in m:
            return size
    return _XK_CTX_DEFAULT


def model_telemetry(hook_input):
    try:
        path = (hook_input or {}).get("transcript_path")
        if not path or not os.path.isfile(path):
            return {}
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - _XK_TAIL_BYTES))
            tail = f.read().decode("utf-8", "replace")
        best = None
        for line in reversed(tail.splitlines()):
            line = line.strip()
            if not line or '"assistant"' not in line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            msg = row.get("message") or {}
            usage = msg.get("usage") or {}
            if msg.get("model") and usage.get("input_tokens") is not None:
                best = (msg["model"], usage)
                break
        if not best:
            return {}
        model, usage = best
        t_in = int(usage.get("input_tokens") or 0)
        t_out = int(usage.get("output_tokens") or 0)
        t_cache = int(usage.get("cache_read_input_tokens") or 0)
        t_create = int(usage.get("cache_creation_input_tokens") or 0)
        used = t_in + t_cache + t_create
        ctx = max(0, min(100, round(used * 100 / _xk_ctx_window(model))))
        return {"model": str(model)[:64], "tokensIn": t_in, "tokensOut": t_out,
                "tokensCacheRead": t_cache, "contextPct": ctx}
    except Exception:
        return {}


_XK_SCRATCH = ("/tmp/", "/private/tmp/", "/var/folders/", "/dev/null")
_XK_DESTRUCTIVE = [_xk_re.compile(r"^rm$"), _xk_re.compile(r"^rmdir$"),
                   _xk_re.compile(r"^shred$"), _xk_re.compile(r"^unlink$")]
_XK_DESTRUCTIVE_COMPOUND = [
    ("find", lambda rest: "-delete" in rest),
    ("git", lambda rest: rest[:1] == ["clean"] and any(a.startswith("-") and "f" in a for a in rest)),
    ("git", lambda rest: (rest[:2] == ["reset", "--hard"]) or ("reset" in rest[:1] and "--hard" in rest)),
    ("git", lambda rest: rest[:1] == ["checkout"] and ("--" in rest or any(a in (".", "-f", "--force") for a in rest))),
]


def _xk_resolve(path, cwd):
    if not path or path.startswith("-"):
        return None if path is None else "-flag-"
    if _xk_re.search(r"[$`\\]", path):
        return None
    p = os.path.expanduser(path)
    p = os.path.normpath(p if os.path.isabs(p) else os.path.join(cwd or "/", p))
    return p


def _xk_under_scratch(p):
    return any(p == r.rstrip("/") or p.startswith(r) for r in _XK_SCRATCH)


def classify_destructive_fs(command_text, cwd=None):
    seg_cwd = cwd
    for seg in _xk_re.split(r"(?:\|\||&&|;|\|)", command_text or ""):
        seg = seg.strip()
        if not seg:
            continue
        try:
            argv = _xk_shlex.split(seg)
        except ValueError:
            if _xk_re.search(r"\b(rm|rmdir|shred|unlink)\b", seg):
                return "attest"
            continue
        if not argv:
            continue
        if argv[0] == "cd" and len(argv) > 1:
            nxt = _xk_resolve(argv[1], seg_cwd)
            seg_cwd = nxt or seg_cwd
            continue
        head, rest = argv[0], argv[1:]
        hit = any(rx.match(head) for rx in _XK_DESTRUCTIVE) or \
            any(head == h and pred(rest) for h, pred in _XK_DESTRUCTIVE_COMPOUND)
        if not hit:
            continue
        targets = [a for a in rest if not a.startswith("-")]
        if not targets:
            return "attest"
        for t in targets:
            rp = _xk_resolve(t, seg_cwd)
            if rp == "-flag-":
                continue
            if rp is None or not _xk_under_scratch(rp):
                return "attest"
    return None


def _xk_escalate(mapped, args, data):
    try:
        if mapped == "terminal" and classify_destructive_fs(
                (args or {}).get("command") or "", (data or {}).get("cwd")) == "attest":
            return "destructive filesystem command outside scratch roots"
    except Exception:
        pass
    return None
# ===== end xChk engine-block =====

# ---------------------------------------------------------------------------
# EMERGENCY STOP, VERIFIED ON THE HOST.
#
# The registry's 403 code=lockdown carries a statement it SIGNED. The host
# verifies it against the registry's published key and remembers the epoch in
# STATE_DIR/lockdown.json. From then on a plain "allow" is not enough to
# resume: the host asks for the signed CLEAR of a strictly higher epoch and
# verifies that too. A tampered database, a spoofed reply, or a registry that
# simply forgot cannot resume a halted agent. Absence never resumes.
# Every step degrades to DENY — the safe direction for a kill switch.
# ---------------------------------------------------------------------------
LOCKDOWN_AUD = "xchk-lockdown"
LOCKDOWN_KIND = "xchk.lockdown.v1"
_KEYS_TTL_SEC = 6 * 3600


def _lockdown_ledger_path() -> Path:
    return STATE_DIR / "lockdown.json"


def _lockdown_ledger_read() -> dict:
    try:
        return json.loads(_lockdown_ledger_path().read_text()) or {}
    except (OSError, ValueError):
        return {}


def _lockdown_ledger_write(ledger: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        p = _lockdown_ledger_path()
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(ledger, sort_keys=True))
        tmp.replace(p)
        p.chmod(0o600)
    except OSError:
        pass


def _registry_keys(client: XchkClient, refresh: bool = False) -> list:
    """Published registry JWKs, cached in STATE_DIR (never in the agent's
    reach). refresh=True bypasses the cache — used once after a signature
    failure, in case the registry rotated its key."""
    cache = STATE_DIR / "registry-keys.json"
    if not refresh:
        try:
            doc = json.loads(cache.read_text())
            if time.time() - float(doc.get("fetchedAt") or 0) < _KEYS_TTL_SEC and doc.get("keys"):
                return doc["keys"]
        except (OSError, ValueError):
            pass
    keys = client.get_registry_keys() or []
    if keys:
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".json.tmp")
            tmp.write_text(json.dumps({"fetchedAt": time.time(), "keys": keys}))
            tmp.replace(cache)
            cache.chmod(0o600)
        except OSError:
            pass
    return keys


def _verify_statement(client: XchkClient, token: str) -> dict:
    """Verify with cached keys; on a signature failure refetch once."""
    from xchk_client import verify_registry_jwt
    try:
        return verify_registry_jwt(token, _registry_keys(client), LOCKDOWN_AUD, kind=LOCKDOWN_KIND)
    except ValueError:
        return verify_registry_jwt(token, _registry_keys(client, refresh=True), LOCKDOWN_AUD, kind=LOCKDOWN_KIND)


def _lockdown_guard(auth: dict, cfg: dict, client: XchkClient) -> dict:
    """Runs on every authorize result. Records verified kills; refuses to
    honour an allow/attest while a recorded kill has no verified clear."""
    ledger = _lockdown_ledger_read()

    # 1. A halt: verify the signed statement and remember its epoch.
    if auth.get("disposition") == "forbid" and auth.get("code") == "lockdown":
        stmt = auth.get("lockdownStatement")
        note = "statement absent — halt recorded from the registry's word alone"
        if stmt:
            try:
                p = _verify_statement(client, stmt)
                if p.get("action") == "kill" and p.get("scope") and p.get("target"):
                    key = f"{p['scope']}:{p['target']}"
                    prior = ledger.get(key) or {}
                    if int(p.get("epoch") or 0) >= int(prior.get("epoch") or 0):
                        ledger[key] = {"epoch": int(p.get("epoch") or 0), "clearedEpoch": None,
                                       "reason": p.get("reason"), "at": p.get("at"), "verified": True}
                        _lockdown_ledger_write(ledger)
                    note = f"registry-signed statement verified (scope {p['scope']}, epoch {p.get('epoch')})"
                else:
                    note = "statement verified but is not a kill — halt stands"
            except Exception as e:  # deny either way; say which
                note = f"statement did NOT verify ({e}) — halt stands"
        decide("deny", f"xchk: EMERGENCY STOP in effect — {auth.get('reason') or 'agent halted'}; {note}")

    # 2. Not a halt. Is there a recorded kill with no verified clear?
    outstanding = {k: v for k, v in ledger.items()
                   if v.get("clearedEpoch") is None or int(v["clearedEpoch"]) <= int(v.get("epoch") or 0)}
    if not outstanding:
        return auth

    problems = []
    try:
        doc = client.get_lockdown_statements()
        if not isinstance(doc, dict):
            raise ValueError("registry did not return statements")
        # A newer verified kill on any scope re-arms the ledger.
        for a in doc.get("active") or []:
            try:
                p = _verify_statement(client, a.get("statementJwt") or "")
                if p.get("action") == "kill":
                    key = f"{p.get('scope')}:{p.get('target')}"
                    ledger[key] = {"epoch": int(p.get("epoch") or 0), "clearedEpoch": None,
                                   "reason": p.get("reason"), "at": p.get("at"), "verified": True}
                    outstanding[key] = ledger[key]
            except Exception as e:
                problems.append(f"active statement unverifiable ({e})")
        # A verified clear of strictly higher epoch releases exactly its scope.
        for c in doc.get("cleared") or []:
            key = f"{c.get('scope')}:{c.get('target')}"
            if key not in outstanding:
                continue
            try:
                p = _verify_statement(client, c.get("clearStatementJwt") or "")
                held = int(outstanding[key].get("epoch") or 0)
                if (p.get("action") == "clear" and f"{p.get('scope')}:{p.get('target')}" == key
                        and int(p.get("epoch") or 0) > held and int(p.get("clears") or -1) >= held):
                    ledger[key]["clearedEpoch"] = int(p.get("epoch"))
                    ledger[key]["clearedBy"] = p.get("approvers")
                    del outstanding[key]
                else:
                    problems.append(f"clear for {key} does not release epoch {held}")
            except Exception as e:
                problems.append(f"clear for {key} unverifiable ({e})")
    except Exception as e:
        problems.append(str(e))
    _lockdown_ledger_write(ledger)

    if outstanding:
        held = ", ".join(f"{k} epoch {v.get('epoch')}" for k, v in outstanding.items())
        why = ("; ".join(problems) or "no registry-signed clear on file")
        if cfg.get("fail_closed", True):
            decide("deny", f"xchk: EMERGENCY STOP was set ({held}) and no registry-signed clear verifies — {why}; refusing to resume on an unsigned word")
        # fail-open dev box: say so and carry on
        sys.stderr.write(f"xchk: lockdown clear unverified ({why}); XCHK_FAIL_CLOSED=0 so continuing\n")
    return auth


def on_pre_tool_use(data: dict, cfg: dict, client: XchkClient) -> None:
    tool_name = data.get("tool_name") or ""
    tool_input = data.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    mapped = TOOL_MAP.get(tool_name)
    if not mapped:
        if tool_name in UNGATED_TOOLS:
            sys.exit(0)  # explicitly ungated — defer to normal permission flow
        mapped = CATCHALL_WIRE  # unknown tool: gate it, let grants decide

    target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")

    # Gate self-protection: hard deny BEFORE any grant is consulted, and
    # before the configured/fail-open branch — an unlicensed dev box still
    # refuses to let the agent rewrite the gate. See "Gate self-protection".
    if mapped in ("write_file", "patch") and is_protected_path(target):
        decide("deny", f"xchk: '{target}' is gate-critical (gate code/config, hook registration, or shell init) — no grant authorizes modifying the gate")
    if mapped == "terminal":
        _cmd = str(tool_input.get("command") or "")
        _scr = bash_screen()
        if _scr.search(_cmd) or _scr.search(_deobfuscate(_cmd)):
            decide("deny", "xchk: command references gate-critical paths or gate env vars (~/.xchk, gate code, hook registration, shell init, XCHK_*) — no grant authorizes this; run it from a shell the agent does not drive. Encoded spellings (base64, hex) are expanded before screening.")
    if mapped == "read_file" and target:
        t = _resolve(target)
        if any(t == r or r in t.parents
               for r in map(_resolve, (Path.home() / ".xchk", CONFIG_PATH, STATE_DIR))):
            decide("deny", "xchk: ~/.xchk holds the license key and run tickets — never readable by the agent")

    if mapped != "terminal" and target and INTERNAL_PATH_RE.search(target):
        sys.exit(0)  # harness's own scratch — see INTERNAL_PATH_RE

    if not client.configured:
        if cfg["fail_closed"]:
            decide("deny", "xchk: license client not configured — failing closed (set XCHK_FAIL_CLOSED=0 to degrade open)")
        sys.exit(0)

    session_id = data.get("session_id") or ""
    run = load_run(session_id) or dispatch(client, session_id)
    ticket = (run or {}).get("ticket")
    run_ref = (run or {}).get("runRef") or "unlicensed"

    args = {}
    if mapped == "terminal":
        args["command"] = str(tool_input.get("command") or "")
    elif mapped == "spawn_agent":
        args["prompt"] = str(tool_input.get("prompt") or tool_input.get("script") or "")[:500]
    elif mapped == CATCHALL_WIRE:
        # The raw name plus a bounded input preview: enough for server-side
        # area inference and for an approver to adjudicate, never the full
        # (possibly huge, possibly secret-bearing) tool input.
        args["tool"] = tool_name
        try:
            args["input"] = json.dumps(tool_input, default=str)[:500]
        except (TypeError, ValueError):
            args["input"] = str(tool_input)[:500]
    else:
        args["path"] = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")

    # A spawn declares its area (nothing in it for the server to infer an
    # area FROM) and its delegation edge: this run is the parent.
    area_hint = SPAWN_AREA if mapped == "spawn_agent" else None
    chain = parent_chain(run) if mapped == "spawn_agent" else None

    # Tier 1 classification, in-process (docs/label-pipeline.md). Degrades to
    # "detected nothing" — never to "clean" — if the module is absent or raises.
    labels = []
    if classify_tool_input is not None:
        try:
            labels = classify_tool_input(tool_input)
        except Exception:
            labels = []
    label_note = f" [{', '.join(l['label'] for l in labels)}]" if labels else ""

    summary = summarize(tool_name, tool_input)
    auth = client.authorize(mapped, args, telemetry=model_telemetry(data), escalate=_xk_escalate(mapped, args, data), prompt=f"{HARNESS_LABEL} {tool_name}", danger_desc=summary,
                            run_ticket=ticket, action_area=area_hint,
                            delegation_chain=chain, labels=labels)

    # Renew, don't refuse: an aged-out ticket on a live plate means only the
    # clock ran out, so re-dispatch for THIS session and carry on. A wrong or
    # revoked licence still refuses — that path returns a real forbid.
    if auth.get("skip") and auth.get("reason") == "invalid_run_ticket":
        drop_run(session_id)
        run = dispatch(client, session_id)
        ticket = (run or {}).get("ticket")
        # The old ref named an expired run; attribute to the successor —
        # including the delegation edge, which names the NEW run as parent.
        run_ref = (run or {}).get("runRef") or run_ref
        chain = parent_chain(run) if mapped == "spawn_agent" else None
        auth = client.authorize(mapped, args, telemetry=model_telemetry(data), escalate=_xk_escalate(mapped, args, data), prompt=f"{HARNESS_LABEL} {tool_name}", danger_desc=summary,
                                run_ticket=ticket, action_area=area_hint,
                                delegation_chain=chain, labels=labels)

    if auth.get("skip"):
        if cfg["fail_closed"]:
            decide("deny", f"xchk: license server unavailable ({auth.get('reason')}) — failing closed")
        sys.exit(0)

    # Emergency Stop, verified on the host: records a signed kill, and
    # refuses to honour an allow/attest until a signed clear verifies.
    auth = _lockdown_guard(auth, cfg, client)

    area = auth.get("area") or "?"
    if auth.get("disposition") == "allow":
        _record(auth.get("authRef"), mapped, summary or tool_name, client, auth.get("paramsHash"))
        decide("allow", f"xchk: allowed under {run_ref} (area {area})")
    if auth.get("disposition") == "forbid":
        decide("deny", f"xchk: forbidden by license grant (area {area}): {auth.get('reason') or 'forbid'}")

    # attest — human approval required
    approver = cfg.get("approver")
    if not approver:
        # A licensed plate reaching attest with no approver is a malformed
        # install: this action requires a human, and there is no independent
        # human to ask. The local terminal prompt would be answered by the
        # agent's own operator — a self-approval with no server-side record,
        # the exact rubber-stamp this system exists to detect. Fail closed
        # and name the fix, rather than launder a self-approval as an
        # attestation. (Unlicensed sessions never reach this branch —
        # authorize has already succeeded.)
        decide("deny", f"xchk: area {area} requires attestation but this licence has no approver configured — denying rather than self-approving. Fix: set an approver on the licence so approvals route to an independent human.")

    att_id, err = client.create_attestation(
        prompt=f"{run_ref} (via {HARNESS_LABEL}) wants to {summary or tool_name}{label_note}",
        target_email=approver,
        tool_name=mapped,
        args=args,
        action_summary=summary,
        auth=auth,
        delegation_chain=chain,
        ttl=int(cfg["attest_timeout"]),
    )
    if not att_id:
        if cfg["fail_closed"]:
            decide("deny", f"xchk: could not create attestation ({err}) — failing closed")
        # The licence HAS an approver; the attestation just could not be
        # created. A transient failure must not downgrade "a human must
        # approve" into "the operator approves themselves" — fail closed
        # and retry when the registry is reachable (authorize succeeded
        # moments ago, so this is rare and short-lived).
        decide("deny", f"xchk: could not create the attestation ({err}) — denying rather than self-approving; retry shortly")

    result = client.poll_attestation(att_id, timeout_seconds=cfg["attest_timeout"])
    if result.get("status") == "completed" and result.get("response") in (True, "true", "yes", 1, "approved"):
        amend = result.get("amendment")
        if amend:
            updated, aerr = apply_amendment(mapped, tool_input, amend)
            if aerr:
                decide("deny", f"xchk: approved WITH CHANGES by {approver} but the amendment cannot run here ({aerr}) — not executing the original either (attestation {att_id})")
            import hashlib as _ah
            amended_cmd = updated.get("command", "")
            _record(auth.get("authRef"), mapped, f"amended by {amend.get('byEmail') or approver}: {amended_cmd[:300]}", client,
                    _ah.sha256(amended_cmd.encode("utf-8")).hexdigest())
            decide("allow", f"xchk: approved WITH CHANGES by {amend.get('byEmail') or approver} — running the amended command (attestation {att_id}, area {amend.get('area') or area}, {run_ref})", updated)
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
    drop_run_file()


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

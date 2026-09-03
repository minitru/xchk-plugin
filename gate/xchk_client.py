"""
Stdlib xChk client for Hermes guardrails and standalone demos.

Same agent API key for authorize, attestation create, and poll.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

XCHK_BASE = os.environ.get("XCHK_BASE", "https://in.xchk.io").rstrip("/")
POLL_INTERVAL_SEC = float(os.environ.get("XCHK_POLL_INTERVAL", "2"))
POLL_TIMEOUT_SEC = float(os.environ.get("XCHK_POLL_TIMEOUT", "660"))
ATTESTATION_TTL_SEC = int(os.environ.get("XCHK_ATTESTATION_TTL", "600"))

_UID_PROBE_RE = re.compile(
    r"^\(\s*(?P<cmd>.+?)\s*\)\s*;\s*echo\s+__XCHK_UID__:.*$",
    re.DOTALL,
)


def normalize_terminal_command(command: str) -> str:
    """Strip xChk UID probe wrapper before server policy routing."""
    cmd = (command or "").strip()
    m = _UID_PROBE_RE.match(cmd)
    if m:
        return m.group("cmd").strip()
    return cmd


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


class XchkClient:
    """Minimal xChk agent API client."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key or os.environ.get("XCHK_API_KEY") or os.environ.get("xchk_api_key")
        self.base_url = (base_url or XCHK_BASE).rstrip("/")
        self._ssl = _ssl_context()

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        timeout: int = 15,
    ) -> Tuple[int, Optional[dict]]:
        if not self.api_key:
            return (0, {"error": "no_api_key"})

        data = None
        headers = {"X-API-Key": self.api_key}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ssl) as resp:
                raw = resp.read().decode("utf-8")
                return (resp.status, json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                parsed = {"error": raw}
            return (e.code, parsed)
        except Exception as e:
            return (-1, {"error": str(e)})

    def authorize(
        self,
        tool_name: str,
        args: dict,
        prompt: str,
        danger_desc: str = "",
        run_ticket: Optional[str] = None,
        action_area: Optional[str] = None,
        delegation_chain: Optional[list] = None,
        labels: Optional[list] = None,
        telemetry: Optional[dict] = None,
        escalate: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/agents/authorize. Returns disposition or skip for legacy keys."""
        if not self.configured:
            return {"skip": True, "reason": "no_api_key"}

        body: Dict[str, Any] = {
            "tool": tool_name,
            "prompt": prompt,
            "summary": danger_desc or prompt,
        }
        if run_ticket:
            body["runTicket"] = run_ticket
        # actionArea short-circuits the server's text inference — used for
        # actions (subagent spawns) whose body has no command/path to infer
        # from. The server validates against its own area vocabulary; an
        # unknown value degrades to 'global', never errors.
        if action_area:
            body["actionArea"] = action_area
        # The caller-declared delegation edge (parent run identity). The
        # server normalizes and records it; content binding rides `summary`,
        # which is part of the server's paramsHash.
        if delegation_chain:
            body["delegationChain"] = delegation_chain
        # What the gate detected in what this call would write, run, or send.
        # Sent ONLY when something was found: an empty array would assert
        # "examined and found clean", which is a stronger claim than a
        # precision-first inline tier is entitled to make.
        if labels:
            body["labels"] = labels
        if telemetry:
            body.update(telemetry)
        if escalate:
            body["escalate"] = escalate
        if tool_name == "terminal":
            body["command"] = normalize_terminal_command(args.get("command") or "")
        elif tool_name in ("write_file", "patch", "read_file"):
            body["path"] = args.get("path")
        elif tool_name == "execute_code":
            body["command"] = (args.get("code") or "")[:500]

        status, data = self.request("POST", "/api/agents/authorize", body=body)
        if status <= 0:
            return {"skip": True, "reason": (data or {}).get("error", "request_failed")}

        disposition = (data or {}).get("disposition")
        if status == 403 and (data or {}).get("error") == "Agent API key required":
            return {"skip": True, "reason": "not_agent_key"}

        # A stale run ticket is a clock problem, not a policy one: the plate is
        # valid and nothing about its authority changed. The server answers 403
        # + disposition:'forbid' + code:'invalid_run_ticket', so this MUST be
        # checked before the forbid branch below — otherwise it reads as a hard
        # refusal and the caller's re-dispatch path can never run.
        if (data or {}).get("code") == "invalid_run_ticket":
            return {"skip": True, "reason": "invalid_run_ticket"}

        # authRef/actionSeq: the registry's per-action reference (MACG-004
        # dashcam) — carried up so the local recorder can chain it.
        # paramsHash: the registry's content hash of the AUTHORIZED action;
        # the recorder binds entry.intentHash to it so reconciliation can
        # verify the local record describes that action ([0021B] content
        # fidelity) — dropping it here left every entry misbound.
        ref = {
            "authRef": (data or {}).get("authRef"),
            "actionSeq": (data or {}).get("actionSeq"),
            "paramsHash": (data or {}).get("paramsHash"),
        }
        if status == 200 and disposition == "allow":
            return {"disposition": "allow", "area": (data or {}).get("area"), **ref}
        if status == 403 and disposition == "forbid":
            return {
                "disposition": "forbid",
                "area": (data or {}).get("area"),
                "reason": (data or {}).get("reason") or (data or {}).get("error") or "forbidden",
                # code=lockdown rides with the registry-SIGNED statement, so the
                # host can verify the halt itself and remember its epoch.
                "code": (data or {}).get("code"),
                "lockdownStatement": (data or {}).get("lockdownStatement"),
                **ref,
            }
        if status == 202 or disposition == "attest":
            return {
                "disposition": "attest",
                "area": (data or {}).get("area"),
                "authorizeSessionId": (data or {}).get("authorizeSessionId"),
                **ref,
            }

        return {"skip": True, "reason": (data or {}).get("error") or f"http_{status}"}

    def create_attestation(
        self,
        *,
        prompt: str,
        target_email: str,
        tool_name: Optional[str] = None,
        args: Optional[dict] = None,
        action_summary: Optional[str] = None,
        auth: Optional[Dict[str, Any]] = None,
        objective: Optional[str] = None,
        task_id: Optional[str] = None,
        delegation_chain: Optional[list] = None,
        policy_id: Optional[str] = None,
        policy_name: Optional[str] = None,
        levels: Optional[list] = None,
        ttl: Optional[int] = None,
        post_execution_alert: bool = False,
    ) -> tuple[Optional[str], Optional[str]]:
        """POST /api/attestations. Returns (attestationId, errorReason)."""
        body: Dict[str, Any] = {
            "user": target_email,
            "prompt": prompt,
            "type": "t/f",
            "ttl": ttl if ttl is not None else ATTESTATION_TTL_SEC,
        }
        if objective:
            body["objective"] = objective[:500]
        if task_id:
            body["taskId"] = task_id[:128]
        if tool_name:
            body["tool"] = tool_name
        if action_summary:
            body["actionSummary"] = action_summary[:500]
        if args:
            if tool_name == "terminal" and args.get("command"):
                body["command"] = normalize_terminal_command(str(args.get("command")))[:500]
            elif tool_name in ("write_file", "patch", "read_file") and args.get("path"):
                body["path"] = str(args.get("path"))[:500]
        if auth and not auth.get("skip"):
            if auth.get("disposition"):
                body["authorizeDisposition"] = auth.get("disposition")
            if auth.get("area"):
                body["authorizeArea"] = auth.get("area")
            if auth.get("authorizeSessionId"):
                body["authorizeSessionId"] = auth.get("authorizeSessionId")
        if delegation_chain:
            body["delegationChain"] = delegation_chain
        if post_execution_alert:
            body["postExecutionAlert"] = True
        if policy_id:
            body["policyId"] = policy_id
        elif policy_name:
            body["policyName"] = policy_name
        elif levels:
            body["levels"] = levels
        else:
            area = (auth or {}).get("area") or "operations"
            email = target_email.lower().strip()
            body["levels"] = [
                {
                    "n": 1,
                    "minLevel": 1,
                    "area": area,
                    "members": [email],
                    "preferred": [email],
                    "autoEscalate": False,
                }
            ]

        status, data = self.request("POST", "/api/attestations", body=body, timeout=45)
        if status in (200, 201) and data:
            return data.get("attestationId"), None
        reason = None
        if isinstance(data, dict):
            reason = data.get("error") or data.get("reason")
        if not reason:
            reason = f"http_{status}" if status > 0 else "request_failed"
        return None, reason

    def _attestation_poll_result(self, att_id: str, data: dict) -> Dict[str, Any]:
        result = {
            "status": data.get("status"),
            "response": data.get("response"),
            "attestation_id": att_id,
            "sha256": data.get("sha256"),
            "bindingClass": data.get("bindingClass"),
        }
        grant = data.get("elevationGrant")
        if grant:
            result["elevation_grant"] = grant
        return result

    def build_action_verify_body(self, tool_name: str, args: dict) -> Dict[str, Any]:
        body: Dict[str, Any] = {"tool": tool_name}
        if tool_name == "terminal":
            body["command"] = normalize_terminal_command(args.get("command") or "")
        elif tool_name in ("write_file", "patch", "read_file"):
            body["path"] = args.get("path")
        elif tool_name == "execute_code":
            body["command"] = (args.get("code") or "")[:500]
        return body

    def verify_elevation_grant(
        self,
        grant: str,
        tool_name: str,
        args: dict,
        consume: bool = True,
    ) -> Dict[str, Any]:
        """POST /api/agents/elevation/verify — redeem signed post-approve grant."""
        if not grant:
            return {"valid": False, "error": "missing_grant"}
        body = {
            "grant": grant,
            "consume": consume,
            **self.build_action_verify_body(tool_name, args),
        }
        status, data = self.request("POST", "/api/agents/elevation/verify", body=body)
        if status == 200 and isinstance(data, dict) and data.get("valid"):
            return data
        return {
            "valid": False,
            "error": (data or {}).get("error") if isinstance(data, dict) else f"http_{status}",
        }

    def get_attestation(self, att_id: str) -> Dict[str, Any]:
        """GET /api/attestations/:id once (no poll loop)."""
        status, data = self.request("GET", f"/api/attestations/{att_id}", timeout=10)
        if status == 403:
            return {
                "status": "error",
                "reason": "poll_not_authorized — use the agent API key that created this attestation",
            }
        if status == 200 and data:
            return self._attestation_poll_result(att_id, data)
        return {"status": "error", "reason": (data or {}).get("error") or f"http_{status}"}

    def poll_attestation(
        self,
        att_id: str,
        timeout_seconds: Optional[float] = None,
    ) -> Dict[str, Any]:
        """GET /api/attestations/:id until terminal state."""
        deadline = time.time() + (timeout_seconds if timeout_seconds is not None else POLL_TIMEOUT_SEC)
        while time.time() < deadline:
            status, data = self.request("GET", f"/api/attestations/{att_id}", timeout=10)
            if status == 403:
                return {
                    "status": "error",
                    "reason": "poll_not_authorized — use the agent API key that created this attestation",
                }
            if status == 200 and data:
                poll_status = data.get("status")
                if poll_status in ("completed", "declined", "expired"):
                    return self._attestation_poll_result(att_id, data)
            time.sleep(POLL_INTERVAL_SEC)
        return {"status": "timeout", "reason": "timed out waiting for approval"}

    def report_hermes_install(self, **fields: Any) -> bool:
        """POST /api/agents/harness-report — sync this Hermes install's status to in.xchk.io."""
        if not self.configured:
            return False
        body = {k: v for k, v in fields.items() if v is not None}
        body.setdefault("harness", "hermes")
        status, _data = self.request("POST", "/api/agents/harness-report", body=body)
        return status == 200

    def report_harness_install(self, harness: str, **fields: Any) -> bool:
        """POST /api/agents/harness-report for an arbitrary harness (claude, cursor, …)."""
        if not self.configured:
            return False
        body = {k: v for k, v in fields.items() if v is not None}
        body["harness"] = harness
        status, _data = self.request("POST", "/api/agents/harness-report", body=body)
        return status == 200

    def dispatch_run(
        self,
        harness: Optional[str] = None,
        session_ref: Optional[str] = None,
        task_label: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        grant_mask: Optional[list] = None,
        revoke_on: Optional[list] = None,
    ) -> Optional[Dict[str, Any]]:
        """POST /api/agents/runs — mint a run under this plate.

        Returns {"run": {..., "runSeq", "agentPlate", "runRef"}, "runTicket": str}
        or None. The raw ticket is returned exactly once; the server keeps only
        its hash.

        revoke_on declares the conditions that END this run — the registry
        evaluates them on every authorize and kills the delegation itself
        (forbid, omission, manager_dark, host_dark). The owner's fleet default
        is unioned in server-side, so asking for fewer never gets you fewer.
        """
        if not self.configured:
            return None
        body: Dict[str, Any] = {}
        if harness:
            body["harness"] = harness
        if session_ref:
            body["sessionRef"] = str(session_ref)[:128]
        if task_label:
            body["taskLabel"] = str(task_label)[:140]
        if ttl_seconds is not None:
            body["ttlSeconds"] = int(ttl_seconds)
        if grant_mask:
            body["grantMask"] = grant_mask
        if revoke_on:
            body["revokeOn"] = list(revoke_on)
        status, data = self.request("POST", "/api/agents/runs", body=body, timeout=20)
        if status in (200, 201) and isinstance(data, dict) and data.get("runTicket"):
            return data
        return None

    def report_run(self, run_seq: Any, report: str) -> bool:
        """POST /api/agents/runs/:runSeq/report — terse work report ("RUNNING 0:10").

        Status word + elapsed only; command content never crosses this channel.
        """
        if not self.configured or run_seq in (None, ""):
            return False
        status, _data = self.request(
            "POST",
            f"/api/agents/runs/{run_seq}/report",
            body={"report": str(report or "").strip()[:32]},
            timeout=10,
        )
        return status == 200

    def end_run(self, run_seq: Any) -> bool:
        """POST /api/agents/runs/:runSeq/end — idempotent."""
        if not self.configured or run_seq in (None, ""):
            return False
        status, _data = self.request("POST", f"/api/agents/runs/{run_seq}/end", body={})
        return status == 200

    def poll_pending_command(self) -> Optional[dict]:
        """GET /api/agents/commands/pending — claim one queued command for this agent."""
        if not self.configured:
            return None
        status, data = self.request("GET", "/api/agents/commands/pending", timeout=20)
        if status != 200 or not data:
            return None
        return data.get("command")

    def submit_command_result(self, command_id: str, result: dict) -> bool:
        """POST /api/agents/commands/:id/result — report local execution outcome."""
        if not self.configured or not command_id:
            return False
        body = {
            "ok": bool(result.get("ok")),
            "exitCode": result.get("exitCode"),
            "output": result.get("output") or "",
            "error": result.get("error"),
        }
        status, _data = self.request(
            "POST",
            f"/api/agents/commands/{command_id}/result",
            body=body,
            timeout=30,
        )
        return status == 200


    def get_lockdown_statements(self) -> Optional[dict]:
        """GET /api/agents/lockdown/statements — the registry-signed kill and
        clear statements for this plate's scopes. Public claims; the signature
        is what the host trusts, never this JSON."""
        if not self.configured:
            return None
        status, data = self.request("GET", "/api/agents/lockdown/statements", timeout=10)
        if status == 200 and isinstance(data, dict):
            return data
        return None

    def get_registry_keys(self) -> Optional[list]:
        """GET /.well-known/xchk-registry — the registry's published signing
        keys (JWK). Unauthenticated by design: anyone may verify."""
        req = urllib.request.Request(f"{self.base_url}/.well-known/xchk-registry", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ssl) as resp:
                doc = json.loads(resp.read().decode("utf-8") or "{}")
            keys = doc.get("keys")
            return keys if isinstance(keys, list) else None
        except Exception:
            return None

    def submit_local_segment(self, segment: dict) -> Optional[dict]:
        """POST /api/agents/local-segment — host half of the MACG-004 triangle.

        Returns the body on 200 AND on 400: a continuity rejection carries
        expectedPrevSegHead, which LocalRecorder.flush() uses to rebase a
        reset chain and resume submitting instead of wedging forever."""
        if not self.configured:
            return None
        status, data = self.request(
            "POST", "/api/agents/local-segment", body={"segment": segment}, timeout=20
        )
        if status in (200, 400) and isinstance(data, dict):
            return data
        return None


# ---------------------------------------------------------------------------
# Registry-signed statement verification — stdlib only.
#
# The Emergency Stop (MACG-004 kill switch) is a registry-signed statement
# {kind:'xchk.lockdown.v1', action:'kill'|'clear', scope, target, epoch, …}
# as an RS256 JWT. The host verifies it against the registry's published
# JWK (RSASSA-PKCS1-v1_5 / SHA-256, RFC 8017 §8.2.2) so that a tampered
# database or a spoofed "not locked down" reply cannot forge a resume.
# Pure-Python RSA is acceptable for VERIFICATION: no secret material, so
# timing side channels do not apply; correctness is what matters.
# ---------------------------------------------------------------------------
import hashlib as _vhashlib
import hmac as _vhmac
import base64 as _vbase64

_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64u_decode(s: str) -> bytes:
    s = str(s or "")
    s += "=" * (-len(s) % 4)
    return _vbase64.urlsafe_b64decode(s.encode("ascii"))


def _rsa_pkcs1v15_sha256_verify(n: int, e: int, sig: bytes, msg: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n)
    em = m.to_bytes(k, "big")
    t = _SHA256_DIGESTINFO + _vhashlib.sha256(msg).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return _vhmac.compare_digest(em, expected)


def verify_registry_jwt(token: str, keys: list, audience: str,
                        kind: Optional[str] = None, now: Optional[float] = None) -> dict:
    """Verify an RS256 JWT against a JWK list; return its payload or raise
    ValueError. Checks: structure, alg, kid→key, signature, aud, exp, kind."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    h_raw, p_raw, s_raw = parts
    header = json.loads(_b64u_decode(h_raw).decode("utf-8"))
    if header.get("alg") != "RS256":
        raise ValueError(f"alg {header.get('alg')!r} not RS256")
    kid = header.get("kid")
    cands = [k for k in (keys or []) if k.get("kty") == "RSA" and (kid is None or k.get("kid") == kid)]
    if not cands:
        raise ValueError("no matching registry key")
    msg = f"{h_raw}.{p_raw}".encode("ascii")
    sig = _b64u_decode(s_raw)
    ok = False
    for k in cands:
        n = int.from_bytes(_b64u_decode(k["n"]), "big")
        e = int.from_bytes(_b64u_decode(k["e"]), "big")
        if _rsa_pkcs1v15_sha256_verify(n, e, sig, msg):
            ok = True
            break
    if not ok:
        raise ValueError("signature does not verify")
    payload = json.loads(_b64u_decode(p_raw).decode("utf-8"))
    aud = payload.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError(f"audience {aud!r}")
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < (now if now is not None else time.time()):
        raise ValueError("statement expired")
    if kind is not None and payload.get("kind") != kind:
        raise ValueError(f"kind {payload.get('kind')!r}")
    return payload


# ---------------------------------------------------------------------------
# LocalRecorder — the host side of the MACG-004 "dashcam" triangle.
#
# One local hash-chain entry per authorized tool call, carrying the registry's
# issued authRef + an intent hash. Segments are submitted to the registry,
# which reconciles: every authRef it issued must appear here (omission-evidence)
# and every entry here must map to an issued authRef (fabrication-evidence).
# Two ledgers, two custody domains, forced to agree. Exception-safe by design:
# recording NEVER affects an authorization decision.
# ---------------------------------------------------------------------------
import hashlib as _hashlib


def _canonical(value: Any) -> str:
    """Byte-match the server's canonicalJson (sorted keys, null kept)."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        raise ValueError("non-integer number outside sealed profile")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _canonical(value[k]) for k in keys) + "}"
    raise ValueError(f"uncanonicalizable {type(value)}")


def _sha(s: str) -> str:
    return _hashlib.sha256(s.encode("utf-8")).hexdigest()


class LocalRecorder:
    """Multi-writer safe: a hook process, the harness plugin, and the resident
    manager may all touch one chain file. Every mutation runs under an
    exclusive file lock with a fresh read of the state, so no writer can
    clobber another's just-appended entry — a lost entry would later read as
    a false omission, the exact lie the recorder exists to prevent."""

    HEARTBEAT_SEC = 300.0  # attest silence no more often than the seal cadence
    MAX_ENTRIES_PER_SEGMENT = 200  # stay under the server's JSON body limit;
    # a chain that backed up while wedged delivers as multiple segments

    _ENTRY_KEYS = ("localSeq", "authRef", "tool", "intentHash", "resultHash",
                   "startedAt", "endedAt")

    def __init__(self, state_path: str, profile: Optional[str] = None) -> None:
        self.path = state_path
        self.profile = profile
        self.state = {"localSeq": 0, "segSeq": 0, "prevSegHead": None,
                      "pending": [], "lastFlushAt": 0}

    def _read(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                self.state.update(json.load(fh))
        except Exception:
            pass

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh)
        os.replace(tmp, self.path)

    def _locked(self, fn):
        """EX-lock -> fresh reload -> mutate -> save. Exception-safe: recording
        must never affect an authorization decision."""
        try:
            import fcntl
            with open(self.path + ".lock", "w") as lk:
                fcntl.flock(lk, fcntl.LOCK_EX)
                try:
                    self._read()
                    out = fn()
                    self._save()
                    return out
                finally:
                    fcntl.flock(lk, fcntl.LOCK_UN)
        except Exception:
            return None

    def record(self, auth_ref: str, tool: Optional[str], intent: str,
               params_hash: Optional[str] = None) -> None:
        """Append one local entry for an authorized action carrying its authRef.

        CONTENT FIDELITY (MACG-004): when the authorize response carries the
        action's paramsHash, bind the entry's intentHash to THAT authoritative
        value rather than to a hash of a free-text summary. The registry then
        verifies each local record describes the action that was actually
        authorized under its reference — not merely that it cites a real one.
        Falls back to the summary hash for legacy callers (reported by the
        registry as unverified, never as covered)."""
        if not auth_ref:
            return

        def _do():
            self.state["localSeq"] += 1
            pending = self.state["pending"]
            prev = pending[-1]["entryHash"] if pending else self.state.get("prevSegHead")
            body = {
                "localSeq": self.state["localSeq"],
                "authRef": auth_ref,
                "tool": tool or None,
                "intentHash": params_hash or (_sha(intent) if intent else None),
                "resultHash": None,
                "startedAt": None,
                "endedAt": None,
                "prevHash": prev,
            }
            entry = dict(body)
            entry["entryHash"] = _sha(_canonical(body))
            pending.append(entry)

        self._locked(_do)

    def _rebase(self, pending: list, new_prev: Optional[str]) -> list:
        """Re-chain PENDING (never-accepted) entries onto a different head.
        Used when the registry reports our chain file was reset (reinstall):
        accepted history is never rewritten — only unsubmitted entries move."""
        rebased = []
        prev = new_prev
        for e in pending:
            body = {k: e.get(k) for k in self._ENTRY_KEYS}
            body["prevHash"] = prev
            ne = dict(body)
            ne["entryHash"] = _sha(_canonical(body))
            rebased.append(ne)
            prev = ne["entryHash"]
        return rebased

    def flush(self, client: "XchkClient", run_ref: Optional[str] = None,
              force_empty: bool = False) -> Optional[dict]:
        """Submit accumulated entries as a segment; advance the chain on ack.

        force_empty: when idle, submit an EMPTY segment (rate-limited to
        HEARTBEAT_SEC) — the host half of bilateral provable silence."""

        def _submit_chunk(chunk, run_ref_):
            """One segment attempt; rebase-and-retry once on a continuity
            rejection. Returns the response (ok or not)."""
            segment = {
                "segSeq": self.state["segSeq"] + 1,
                "prevSegHead": self.state.get("prevSegHead"),
                "runRef": run_ref_,
                "profile": self.profile,
                "entries": chunk,
            }
            resp = client.submit_local_segment(segment)
            if resp and not resp.get("ok") and resp.get("expectedPrevSegHead"):
                # Rebase the ENTIRE pending chain, not just this chunk — the
                # remainder's prevHash pointers link through the chunk's
                # hashes and would dangle off the pre-rebase values.
                expected = resp["expectedPrevSegHead"]
                rebased = self._rebase(self.state.get("pending") or [], expected)
                self.state["prevSegHead"] = expected
                self.state["pending"] = rebased
                chunk[:] = rebased[: len(chunk)]
                segment["prevSegHead"] = expected
                segment["entries"] = chunk
                resp = client.submit_local_segment(segment)
            return resp

        def _pending_chain_intact() -> bool:
            """Do the pending entries chain correctly off prevSegHead? False
            after any partial rebase or interrupted write — the recoverable
            states a shared file can land in."""
            prev = self.state.get("prevSegHead")
            for e in self.state.get("pending") or []:
                if e.get("prevHash") != prev:
                    return False
                body = {k: e.get(k) for k in self._ENTRY_KEYS}
                body["prevHash"] = prev
                if _sha(_canonical(body)) != e.get("entryHash"):
                    return False
                prev = e.get("entryHash")
            return True

        def _do():
            now = time.time()
            if not (self.state.get("pending") or []):
                stale = now - float(self.state.get("lastFlushAt") or 0) >= self.HEARTBEAT_SEC
                if not (force_empty and stale):
                    return None
            # Self-heal before submitting: pending entries are NOT yet
            # evidence (never accepted anywhere), so re-chaining them onto
            # the current head is bookkeeping, not history rewriting.
            if not _pending_chain_intact():
                self.state["pending"] = self._rebase(
                    self.state.get("pending") or [], self.state.get("prevSegHead"))
            last = None
            # Deliver in chunks: a chain that backed up while unreachable can
            # exceed the server's request-size limit as one segment. Each
            # accepted chunk advances persisted state, so a mid-run failure
            # loses nothing — the remainder goes next flush.
            while True:
                pending = self.state.get("pending") or []
                chunk = pending[: self.MAX_ENTRIES_PER_SEGMENT]
                resp = _submit_chunk(chunk, run_ref)
                last = resp or last
                if not (resp and resp.get("ok") and resp.get("segHead")):
                    break
                # Re-read from state: a continuity rebase inside
                # _submit_chunk replaces the whole pending list.
                remainder = (self.state.get("pending") or [])[len(chunk):]
                self.state["segSeq"] = int(resp.get("segSeq") or (self.state["segSeq"] + 1))
                self.state["prevSegHead"] = resp["segHead"]
                self.state["pending"] = remainder
                self.state["lastFlushAt"] = now
                self._save()
                if not remainder:
                    break
            return last

        return self._locked(_do)

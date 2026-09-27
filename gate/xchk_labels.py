#!/usr/bin/env python3
"""Inline content classification for the gate — stdlib only, precision first.

This is the FIRST of two tiers described in docs/label-pipeline.md. It runs
in-process on every gated tool call, so it must be cheap and dependency-free.
The second tier (Presidio for PII/PHI, Gitleaks for secrets) runs as a local
sidecar and covers the recall this tier deliberately gives up.

DESIGN RULE: PRECISION OVER RECALL, ALWAYS.

A false positive stops a person's work and teaches them the gate is noise. A
false negative is invisible here and is caught — or honestly not caught — by
the sidecar. So this tier only claims what it can nearly prove: checksummed
card numbers, key material with unmistakable headers, vendor token formats
with fixed prefixes, and structurally valid SSNs. Deliberately ABSENT:
free-text names, street addresses, phone numbers and bare email addresses,
all of which are common enough in ordinary work that flagging them would
train operators to override every label they ever see.

WHAT ABSENCE MEANS. Returning [] means "this tier detected nothing", never
"this content is clean". The registry records the distinction and the console
must render it as such — a classifier that renders silence as safety
manufactures confidence it has not earned.
"""

from __future__ import annotations

import base64
import re

DETECTOR = "xchk-inline"
DETECTOR_VERSION = "1.2.2"

# Cap the scanned text. Tool inputs are normally small; a pathological one
# must not turn every tool call into a regex benchmark.
MAX_SCAN_BYTES = 256 * 1024


def _luhn_ok(digits: str) -> bool:
    """Checksum used by every major card network — this is what makes
    HAS_PAYMENT a near-proof rather than 'sixteen digits appeared'."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Card-shaped runs, allowing spaces/hyphens as humans and exports write them.
_CARD_RE = re.compile(r"(?<![0-9])(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6011)"
                      r"[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,4}(?![0-9])")

# SSA structural rules: area 000/666/900-999 are never issued, and neither
# group 00 nor serial 0000. Applying them turns a 9-digit match from noise
# into something worth a person's attention.
_SSN_RE = re.compile(r"(?<![0-9-])(?!000|666|9[0-9]{2})([0-8][0-9]{2})"
                     r"-(?!00)([0-9]{2})-(?!0000)([0-9]{4})(?![0-9-])")

# Key material and vendor tokens: fixed, self-announcing formats. A hit here
# is not a heuristic — these strings do not occur by accident.
_SECRET_PATTERNS = (
    ("pem-private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("github-token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}")),
    ("openai-key", re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9])")),
    ("stripe-key", re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
)


def _label(name, confidence_pct, spans, detail=None):
    return {
        "label": name,
        "source": "derived",
        "detector": f"{DETECTOR}:{detail}" if detail else DETECTOR,
        "detectorVersion": DETECTOR_VERSION,
        "confidencePct": confidence_pct,
        "spanCount": spans,
    }


# ── HAS_BANKING (detector 1.1.0, 15 Sep 2026: the "Banking & payments watch" package) ──────────────────
# Bank-side identifiers and transfer intent. IBAN and ABA carry checksums (near-proof); an account number
# needs its cue word; a transfer verb needs an amount beside it. Each is scored on its own.
_IBAN_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)(?![A-Z0-9])")
_ABA_RE = re.compile(r"(?i)(?:routing|aba|rtn|transit)[^0-9]{0,20}(?<![0-9])([0-9]{9})(?![0-9])")
_ACCT_RE = re.compile(r"(?i)\b(?:account|acct|a/c)\s*(?:number|no\.?|num|#)\s*[:#]?\s*(?<![0-9])([0-9][0-9 -]{5,20}[0-9])(?![0-9])")
_XFER_RE = re.compile(r"(?i)\b(?:wire|ach|remit(?:tance)?|payout|transfer|disburse|send)\b[^\n]{0,60}?(?:[$€£]\s?[0-9][0-9,]*(?:\.[0-9]{2})?|[0-9][0-9,]*(?:\.[0-9]{2})?\s?(?:usd|eur|gbp|cad|dollars))")


def _iban_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in moved)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _aba_ok(d: str) -> bool:
    if len(d) != 9 or not d.isdigit():
        return False
    w = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    return sum(int(c) * k for c, k in zip(d, w)) % 10 == 0 and d[:2] not in ("00",)


def classify_banking(blob: str) -> list:
    """HAS_BANKING labels for a blob. Never raises."""
    try:
        out = []
        ibans = [m.group(1) for m in _IBAN_RE.finditer(blob) if _iban_ok(m.group(1))]
        if ibans:
            out.append(_label("HAS_BANKING", 95, len(ibans), "iban"))
        abas = [m.group(1) for m in _ABA_RE.finditer(blob) if _aba_ok(m.group(1))]
        if abas:
            out.append(_label("HAS_BANKING", 90, len(abas), "aba-routing"))
        accts = _ACCT_RE.findall(blob)
        if accts:
            out.append(_label("HAS_BANKING", 70, len(accts), "account-number"))
        xfers = _XFER_RE.findall(blob)
        if xfers:
            out.append(_label("HAS_BANKING", 60, len(xfers), "transfer-intent"))
        return out
    except Exception:
        return []


# INJECTION WATCH (17 Sep 2026, SP-3 cheap step; 1.2.1 on 21 Sep after the Murtaza bench; 1.2.2 on 24 Sep after the
# Reversec spikee bench). Phrases that only make sense as an instruction aimed at the model, appearing in what a tool
# is about to WRITE, RUN or SEND. A signal, never a block: the label asks a person. Precision rule holds: each pattern
# needs the imperative AND its object; "ignore" alone never fires. Families are byte-identical to xchk_compact_screen.py.
_INJECTION_PATTERNS = (
    ("override-instructions", re.compile(r"(?i)\b(ignore|disregard|forget)\b[^\n.]{0,40}\b(previous|prior|above|all|your|system|developer)\b[^\n.]{0,30}\b(instructions?|prompts?|rules?|guidelines?|messages?)\b")),
    ("role-hijack", re.compile(r"(?i)\byou are (now|freed?|no longer)\b[^\n.]{0,80}\b(unrestricted|jailbroken|developer mode|DAN|without (any )?(rules|restrictions|limits)|roles?|identit(y|ies)|bind|obligation)\b|\b(DAN|AI|assistant|model|you|it|I)\s+(has|have|had)\s+no\s+(restrictions|rules|limits|filters|guidelines)\b|\bdo anything now\b")),
    ("hide-from-user", re.compile(r"(?i)\b(do not|don't|never|avoid)\b[^\n.]{0,24}\b(tell|show|reveal|mention|disclose|surface)\b[^\n.]{0,24}\b(the )?(user|human|operator|reviewer)\b|\b(conceal|hide)\b[^\n.]{0,30}\b(mistake|error|failure|misalign)")),
    ("exfil-secret", re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|forward)\b[^\n.]{0,50}\b(api[ _-]?keys?|tokens?|passwords?|credentials?|secrets?|\.env|ssh keys?)\b[^\n.]{0,50}\b(to|at)\b\s*(https?://|[a-z0-9.-]+\.[a-z]{2,})")),
    ("tool-coercion", re.compile(r"(?i)\b(assistant|agent|model|AI|successor|next context)\b[^\n.]{0,30}\b(must|should|will)\b[^\n.]{0,30}\b(run|execute|call|invoke)\b[^\n.]{0,40}\b(without (asking|approval|confirmation)|immediately|silently)\b")),
    ("system-tag-spoof", re.compile(r"(?i)</?\s*(system|assistant|developer|tool_result|function_results)\s*>|\[\s*(SYSTEM|INST|ADMIN|DEVELOPER)\b[^\]\n]{0,60}(\]|:)|\b(new|additional|updated|override)\s+instructions?\s+from\s+(the\s+)?(admin|system|developer|operator|owner)\b|\[\s*end of (search results|tool output|document|context|results)\b")),
    ("prompt-extraction", re.compile(r"(?i)\b(repeat|print|output|reveal|show|display|echo|paste|write out|recite)\b[^\n.]{0,30}\b(the (text|prompt|instructions?|message|content) above|everything above|your (system|initial|original|hidden|secret) (prompt|instructions?|message)|the (system|initial|developer) (prompt|instructions?|message))\b")),
    ("decode-and-follow", re.compile(r"(?i)\b(decode|decrypt|unscramble|deobfuscate|translate|rot13)\b[^\n.]{0,80}\b(and|then)\s+(follow|execute|obey|do|run|carry out|comply with|act on|perform)\b")),
    ("task-override", re.compile(r"(?i)\b(ignore|disregard|skip|abandon|drop|stop)\b[^\n.]{0,12}\b(the|your|this|any)\s+(?:\w+\s+){0,2}(task|job|assignment|request|question)\b[^\n]{0,40}\b(instead|only|rather)\b")),
    # 1.2.2 — the four families the spikee (Reversec) cybersec payloads walked past: goal injections with no authority claim.
    ("output-shaping", re.compile(r"""(?i)\b(include|insert|add|append|embed|put|place|print|render|display|output|write)\b[^\n.]{0,60}\b(in|into|to|at the (end|start|beginning|top|bottom) of)\s+(your|the|this|its|each|every)\s+(response|answer|reply|output|summary|result|message)\b[^\n]{0,80}\b(the following|exactly as|verbatim|word for word|this (string|text|tag|anchor|image|link|code))\b|\b(the following|exactly as it is|verbatim)\b[^\n]{0,80}\b(in|into|to)\s+(your|the)\s+(response|answer|reply|output|summary)\b|\brepeat\b[^\n.]{0,80}\b(\d{2,}|hundred|thousand)\s+times\b""")),
    ("markdown-image-exfil", re.compile(r"""(?i)!\[[^\]\n]{0,80}\]\(\s*https?:\/\/[^\s)]{0,200}\?[^\s)]{0,160}(\[[A-Z_]{2,}\]|\{\{?[A-Za-z_]+\}?\}|<[A-Za-z_]+>|PLACEHOLDER|%s)[^\s)]{0,80}\)|!\[[^\]\n]{0,80}\]\(\s*https?:\/\/[^\s)]{0,200}\?[^\s)]{0,240}\)[^\n]{0,160}\b(base64|encoded?|url-?encode|substitute|replace)\b""")),
    ("html-in-output", re.compile(r"""(?i)<\s*script\b[^>]*>[^<\n]{0,80}\b(alert|fetch|eval|document\.cookie)\s*\(|\bon(error|load)\s*=\s*['"]?[^\n'">]{0,120}\b(console\.log|alert|fetch|eval|document\.cookie|document\.location|window\.location|location\.href)\b|<\s*svg\b[^>\n]{0,120}\bon[a-z]{3,20}\s*=|\bjavascript:\s*(console\.log|alert|fetch|eval|document\.|window\.|location)\b""")),
    ("instruction-banner", re.compile(r"""\*{3,}\s*[A-ZÀ-Þ][A-ZÀ-Þ0-9'’\- ]{8,60}\*{3,}|\b[Tt]his is a test\b[^\n]{0,50}\b(execute|run|generate|include|respond|answer|print|output|insert)\b|\b[Tt]o enable debugging\b[^\n.]{0,50}\b(execute|run|include|print|output|insert)\b|\b[Ss]pecial case:\s*[^\n.]{0,90}\b(instead|include|insert|print|output)\b|\b[Ss]orry,? [Ii] made a mistake\b[^\n.]{0,80}\binstructions?\b|\b([Ii]f|[Ww]hen) you are (told|asked) to (summari[sz]e|answer|translate|respond)\b[^\n.]{0,60}\b(instead|ignore)\b|\b[Pp]lease execute:\s*\S""")),
)
# encoded-text: base64 that decodes to prose (>= 24 chars) or to printable text (>= 80 chars). Not a data-URI image.
# Matches 4k+2 / 4k+3 bodies with padding too — a quads-only rule misses two thirds of real base64.
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2,3})?={0,2}(?![A-Za-z0-9+/=])")


def _encoded_prose(blob: str) -> list:
    """[(start, decoded)] for the first base64 run that decodes to readable text; [] otherwise. Never raises."""
    try:
        for m in _B64_RE.finditer(blob):
            if "data:image/" in blob[max(0, m.start() - 30):m.start()]:
                continue
            raw = m.group(0)
            try:
                dec = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
            except Exception:  # noqa: BLE001
                continue
            long = len(raw) >= 80 and re.fullmatch(r"[\t\n\r\x20-\x7e]{20,}", dec) is not None
            prose = re.fullmatch(r"[\t\n\r\x20-\x7e]{12,}", dec) is not None and dec.count(" ") >= 2 and len(re.findall(r"[A-Za-z]{3,}", dec)) >= 3
            if long or prose:
                return [(m.start(), dec)]
    except Exception:  # noqa: BLE001
        pass
    return []


def classify_injection(blob: str) -> list:
    """Detector 1.2.2: instruction-shaped text in tool content. Returns at most one label."""
    hits = 0
    kinds = []
    for kind, pattern in _INJECTION_PATTERNS:
        n = len(pattern.findall(blob))
        if n:
            hits += n
            kinds.append(kind)
    enc = _encoded_prose(blob)
    if enc:
        hits += len(enc)
        kinds.append("encoded-text")
    if not hits:
        return []
    # Two distinct pattern families, or a tag spoof, read stronger than one phrase.
    conf = 75 if (len(kinds) >= 2 or "system-tag-spoof" in kinds) else 60
    return [_label("HAS_INJECTION_SIGNAL", conf, hits, ",".join(kinds)[:60])]


def classify(text: str) -> list:
    """Labels for a blob of text. Never raises: a classifier that can crash
    the gate is a denial-of-service on the user's own tooling, and the honest
    degradation is 'detected nothing' — which the caller already knows how to
    represent."""
    try:
        if not text:
            return []
        blob = str(text)[:MAX_SCAN_BYTES]
        out = []

        secret_hits = 0
        kinds = []
        for kind, pattern in _SECRET_PATTERNS:
            n = len(pattern.findall(blob))
            if n:
                secret_hits += n
                kinds.append(kind)
        if secret_hits:
            # Fixed formats: as close to certainty as this tier gets.
            out.append(_label("CREDENTIALS", 99, secret_hits, ",".join(sorted(kinds))[:40]))

        cards = [m.group(0) for m in _CARD_RE.finditer(blob)]
        valid = [c for c in cards if _luhn_ok(re.sub(r"[- ]", "", c))]
        if valid:
            out.append(_label("HAS_PAYMENT", 95, len(valid), "luhn"))

        ssns = _SSN_RE.findall(blob)
        if ssns:
            # Structurally valid, but a formatted 9-digit number is still
            # occasionally something else; scored below the checksummed cases.
            out.append(_label("HAS_PII", 80, len(ssns), "ssn"))

        out.extend(classify_banking(blob))   # detector 1.1.0: the banking & payments watch
        out.extend(classify_injection(blob))  # detector 1.2.2: the injection watch (SP-3 cheap step)
        return out
    except Exception:
        return []


# Which parts of a tool's input are content worth scanning. Paths and flags
# are not scanned: a filename is not the file, and scanning argv would flag
# the very redaction commands an operator runs to clean something up.
_CONTENT_KEYS = ("content", "new_string", "command", "prompt", "script", "replace_all_string")


def classify_tool_input(tool_input: dict) -> list:
    """Classify what a tool call would actually write, run, or send."""
    if not isinstance(tool_input, dict):
        return []
    parts = []
    for key in _CONTENT_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    return classify("\n".join(parts)) if parts else []

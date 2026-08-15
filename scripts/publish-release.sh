#!/usr/bin/env bash
# Publish this build's MANIFEST.sha256 to the registry as the known-good copy
# for its version.
#
# WHY THIS IS A SEPARATE STEP, RUN BY A HUMAN
#
# gate_integrity() self-hashes the installed files and reports a verdict. That
# is worth something only because the ISSUER holds an independent copy to
# contradict a lie against. If this ran automatically from a build box using a
# token the build box also uses for anything else, "independent" would be doing
# no work — the same pipeline that produced the bytes would be certifying them.
# It takes a siteAdmin session, deliberately, and the registry refuses agent
# keys outright.
#
# Run AFTER sync-gate.sh and AFTER the signed tag, so what is published is what
# was released:
#   ./scripts/sync-gate.sh
#   git commit && git tag -s vX.Y.Z -m "xchk-plugin vX.Y.Z" && git push --follow-tags
#   XCHK_ADMIN_TOKEN=... ./scripts/publish-release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${XCHK_BASE:-https://in.xchk.io}"
HARNESS="${1:-claude}"
MANIFEST="$ROOT/MANIFEST.sha256"

[[ -f "$MANIFEST" ]] || { echo "no MANIFEST.sha256 — run ./scripts/sync-gate.sh first" >&2; exit 1; }
[[ -n "${XCHK_ADMIN_TOKEN:-}" ]] || {
  echo "XCHK_ADMIN_TOKEN is required (a siteAdmin session token)." >&2
  echo "Agent API keys are refused by the registry: a gate must not be able to" >&2
  echo "declare its own known-good hashes." >&2
  exit 1
}

# The version the GATE reports, not the tag. The tag is how humans find a
# release; pluginVersion is what the running code says about itself, and that
# is what an install report will be matched on.
VERSION="$(sed -n 's/^PLUGIN_VERSION = "\(.*\)"$/\1/p' "$ROOT/gate/xchk_hook.py")"
[[ -n "$VERSION" ]] || { echo "could not read PLUGIN_VERSION from gate/xchk_hook.py" >&2; exit 1; }

# Refuse to publish a dirty tree: what goes on the shelf must be what was
# committed, or the record describes bytes that exist nowhere.
if ! git -C "$ROOT" diff --quiet || ! git -C "$ROOT" diff --cached --quiet; then
  echo "working tree is dirty — commit first, so the published manifest matches a commit" >&2
  exit 1
fi
TAG="$(git -C "$ROOT" describe --tags --exact-match 2>/dev/null || true)"
[[ -n "$TAG" ]] || echo "warning: HEAD is not tagged; publishing anyway with sourceTag=null" >&2

echo "publishing $HARNESS $VERSION${TAG:+ ($TAG)} to $BASE"
python3 - "$MANIFEST" "$HARNESS" "$VERSION" "$TAG" "$BASE" <<'PY'
import json, os, sys, urllib.request, urllib.error
manifest_path, harness, version, tag, base = sys.argv[1:6]
raw = open(manifest_path, encoding="utf-8").read()
body = json.dumps({
    "harness": harness,
    "pluginVersion": version,
    "manifest": raw,                       # RAW text: the hash is of these bytes
    "sourceTag": tag or None,
}).encode()
req = urllib.request.Request(
    base.rstrip("/") + "/api/gate-releases", data=body, method="POST",
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + os.environ["XCHK_ADMIN_TOKEN"]})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        out = json.load(r)
    print(f"  published: {out['harness']} {out['pluginVersion']}")
    print(f"  manifestSha: {out['manifestSha']}")
    print(f"  files: {out['files']}")
except urllib.error.HTTPError as e:
    detail = e.read().decode(errors="replace")
    if e.code == 409:
        # Already published. Not an error worth failing a release over, but it
        # must be loud: it means this version's known-good copy was set by an
        # earlier run, and THAT is what installs are being checked against.
        print(f"  already published (409) — the existing record stands: {detail}")
        sys.exit(0)
    print(f"  FAILED {e.code}: {detail}", file=sys.stderr)
    sys.exit(1)
PY

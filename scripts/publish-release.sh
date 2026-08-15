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

# Python builds the JSON — it has to, because the manifest is multi-line text
# that must be escaped exactly — but curl does the transport.
#
# urllib was doing both, and that made the release depend on the local Python
# having a CA bundle. python.org's framework build on macOS does not use the
# system keychain, so it fails with CERTIFICATE_VERIFY_FAILED until someone
# runs "Install Certificates.command". A release step is the wrong place to
# discover that; curl uses the system trust store and is already assumed
# everywhere else in this stack.
BODY="$(mktemp)"; trap 'rm -f "$BODY"' EXIT
python3 - "$MANIFEST" "$HARNESS" "$VERSION" "$TAG" > "$BODY" <<'PY'
import json, sys
manifest_path, harness, version, tag = sys.argv[1:5]
sys.stdout.write(json.dumps({
    "harness": harness,
    "pluginVersion": version,
    "manifest": open(manifest_path, encoding="utf-8").read(),  # RAW: hashed as-is
    "sourceTag": tag or None,
}))
PY

OUT="$(mktemp)"; trap 'rm -f "$BODY" "$OUT"' EXIT
CODE="$(curl -sS -o "$OUT" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${XCHK_ADMIN_TOKEN}" \
  --data-binary "@$BODY" \
  "${BASE%/}/api/gate-releases")"

case "$CODE" in
  # Heredoc, not python3 -c: inside bash single quotes a \" stays a literal
  # backslash-quote, and Python rejects it inside an f-string expression. The
  # POST had already succeeded when this blew up, which is the worst kind of
  # reporting bug — it says "failed" about something that worked.
  201) python3 - "$OUT" <<'PY'
import json, sys
o = json.load(open(sys.argv[1]))
print(f"  published: {o['harness']} {o['pluginVersion']}")
print(f"  manifestSha: {o['manifestSha']}")
print(f"  files: {o['files']}")
PY
       ;;
  409) # Already published. Not worth failing a release over, but loud: this
       # version's known-good copy was set by an earlier run, and THAT is what
       # installs are being checked against.
       echo "  already published (409) — the existing record stands:"; cat "$OUT"; echo ;;
  *)   echo "  FAILED $CODE:" >&2; cat "$OUT" >&2; echo >&2; exit 1 ;;
esac

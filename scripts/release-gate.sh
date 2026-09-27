#!/usr/bin/env bash
# release-gate.sh — ONE script for the whole gate release, with a hard
# checkpoint after every step. Run from YOUR shell (it touches gate code,
# the live install, git tags, and the registry — all things the agent is
# rightly barred from).
#
#   export XCHK_ADMIN_TOKEN='<siteAdmin Firebase ID token>'
#   bash ~/Downloads/release-gate.sh 0.1.8
#
# What it does, in order (stops dead on the first failure, says why):
#   1. bump PLUGIN_VERSION in the SOURCE OF TRUTH hook (xchk-app examples/)
#      and "version" in the plugin's plugin.json files
#   2. commit + push xchk-app (explicit paths — never -A)
#   3. scripts/sync-gate.sh  → re-vendor gate/ + regenerate both manifests
#      CHECK: manifests hash the exact bytes of the source hook/client
#   4. commit the plugin
#   5. signed tag v<ver> (moving it if a same-named tag already exists),
#      push --follow-tags
#   6. publish BOTH variants to the registry (plugin + standalone)
#      CHECK: the registry's public GET returns our manifest sha
#   7. install to the LIVE gate: hook, client, standalone manifest (backups)
#      CHECK: live bytes == source bytes; live manifest == published manifest
# Then the gate's next status ping should report verified / matches-release.
set -euo pipefail

NEW_VER="${1:-}"
RESUME="${2:-}"   # "publish" = steps 1-5 already done; do only publish + install
[[ -n "$NEW_VER" ]] || { echo "usage: release-gate.sh <version e.g. 0.1.8> [publish]"; exit 2; }
[[ "$NEW_VER" =~ ^[0-9]+(\.[0-9]+)+$ ]] || { echo "version must be dotted numeric"; exit 2; }
: "${XCHK_ADMIN_TOKEN:?export XCHK_ADMIN_TOKEN=<siteAdmin Firebase ID token> first (see notes at bottom)}"
# A pasted token often carries a wrapped newline or stray spaces; curl refuses
# a header with CR/LF as "(43) bad argument". Strip ALL whitespace.
XCHK_ADMIN_TOKEN="$(printf '%s' "$XCHK_ADMIN_TOKEN" | tr -d '[:space:]')"
export XCHK_ADMIN_TOKEN
[[ ${#XCHK_ADMIN_TOKEN} -gt 100 ]] || { echo "XCHK_ADMIN_TOKEN looks too short (${#XCHK_ADMIN_TOKEN} chars) to be a Firebase ID token"; exit 2; }

APP="${XCHK_APP:-/Volumes/2TB-FAST/sean-overflow/src/xchk/xchk-app}"
SRC="$APP/examples/claude-attestation-guardrails"
PLUG="${XCHK_PLUGIN:-$HOME/src/xchk/xchk-plugin}"
LIVE="${XCHK_LIVE:-$HOME/.xchk/claude-plugin}"
BASE="${XCHK_BASE:-https://in.xchk.io}"
STAMP="$(date +%Y%m%d-%H%M%S)"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   ✓ %s\n' "$*"; }
die()  { printf '\n\033[31mFAIL — %s\033[0m\n' "$*"; exit 1; }
sha()  { shasum -a 256 "$1" | cut -d' ' -f1; }

# ---------- preflight ----------
say "preflight"
for f in "$SRC/hooks/xchk_hook.py" "$SRC/xchk_client.py" "$PLUG/scripts/sync-gate.sh" \
         "$PLUG/scripts/publish-release.sh" "$LIVE/hooks/xchk_hook.py" "$LIVE/xchk_client.py"; do
  [[ -f "$f" ]] || die "missing: $f"
done
ok "all trees present"

if [[ "$RESUME" == "publish" ]]; then
  say "RESUME: steps 1-5 assumed done — publishing + installing v$NEW_VER only"
  grep -qE "^PLUGIN_VERSION\s*=\s*[\"']$NEW_VER[\"']" "$SRC/hooks/xchk_hook.py" \
    || die "source hook does not say PLUGIN_VERSION $NEW_VER — steps 1-5 did not complete; run without 'publish'"
  ( cd "$PLUG" && git rev-parse -q --verify "refs/tags/v$NEW_VER" >/dev/null ) \
    || die "tag v$NEW_VER does not exist — steps 1-5 did not complete; run without 'publish'"
  ok "source says $NEW_VER and tag v$NEW_VER exists"
else
[[ "$(sha "$SRC/hooks/xchk_hook.py")" == "$(sha "$LIVE/hooks/xchk_hook.py")" ]] \
  || die "source hook and LIVE hook differ BEFORE we start — they must already be identical (patch both first)"
ok "source hook == live hook (pre-bump)"

CUR_VER="$(grep -E '^PLUGIN_VERSION\s*=' "$SRC/hooks/xchk_hook.py" | head -1 | sed -E 's/.*["'"'"']([^"'"'"']+)["'"'"'].*/\1/')"
[[ -n "$CUR_VER" ]] || die "could not find a line like PLUGIN_VERSION = \"x.y.z\" in $SRC/hooks/xchk_hook.py — paste: grep -n VERSION $SRC/hooks/xchk_hook.py"
ok "current PLUGIN_VERSION = $CUR_VER  →  releasing $NEW_VER"
[[ "$CUR_VER" != "$NEW_VER" ]] || die "source already says $NEW_VER — pick a new version or clear the bump"

# ---------- 1. bump ----------
say "1. bump version in source of truth + plugin.json files"
sed -i '' -E "s/^(PLUGIN_VERSION[[:space:]]*=[[:space:]]*)[\"'][^\"']+[\"']/\1\"$NEW_VER\"/" "$SRC/hooks/xchk_hook.py"
grep -qE "^PLUGIN_VERSION\s*=\s*[\"']$NEW_VER[\"']" "$SRC/hooks/xchk_hook.py" || die "hook version bump did not take"
ok "hook PLUGIN_VERSION = $NEW_VER"
for j in "$PLUG/plugin.json" "$PLUG/.claude-plugin/plugin.json"; do
  if [[ -f "$j" ]]; then
    python3 - "$j" "$NEW_VER" <<'PY'
import json, sys
p, v = sys.argv[1], sys.argv[2]
d = json.load(open(p))
if "version" in d:
    d["version"] = v
    json.dump(d, open(p, "w"), indent=2); open(p, "a").write("\n")
    print(f"   ✓ {p}: version = {v}")
else:
    print(f"   · {p}: no version key, left alone")
PY
  fi
done
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$SRC/hooks/xchk_hook.py" || die "hook no longer parses after bump"

# ---------- 2. commit source of truth ----------
say "2. commit + push xchk-app source of truth"
( cd "$APP" \
  && for f in hooks/xchk_hook.py hooks/xchk_prompt_hook.py hooks/xchk_compact_screen.py xchk_client.py xchk_labels.py install-claude-xchk.sh; do \
       if [[ -f "examples/claude-attestation-guardrails/$f" ]]; then git add "examples/claude-attestation-guardrails/$f"; fi; done \
  && if [[ -f examples/hermes-attestation-guardrails/xchk_labels.py ]]; then git add examples/hermes-attestation-guardrails/xchk_labels.py; fi \
  && git commit -q -m "gate source: PLUGIN_VERSION $NEW_VER" \
  && git push -q && ok "xchk-app $(git log --oneline -1)" ) || die "xchk-app commit/push failed"

# ---------- 3. re-vendor + manifests ----------
say "3. sync-gate.sh (re-vendor gate/ from source, regenerate manifests)"
( cd "$PLUG" && rm -f gate/*.bak.enginepatch.* && scripts/sync-gate.sh ) || die "sync-gate.sh failed"
HOOK_SHA="$(sha "$SRC/hooks/xchk_hook.py")"; CLI_SHA="$(sha "$SRC/xchk_client.py")"
grep -q "$HOOK_SHA  gate/xchk_hook.py"   "$PLUG/MANIFEST.sha256"            || die "MANIFEST.sha256 does not carry the source hook's hash"
grep -q "$CLI_SHA  gate/xchk_client.py"  "$PLUG/MANIFEST.sha256"            || die "MANIFEST.sha256 does not carry the source client's hash"
grep -q "$HOOK_SHA  hooks/xchk_hook.py"  "$PLUG/MANIFEST.standalone.sha256" || die "standalone manifest does not carry the source hook's hash"
grep -q "$CLI_SHA  xchk_client.py"       "$PLUG/MANIFEST.standalone.sha256" || die "standalone manifest does not carry the source client's hash"
ok "both manifests hash the exact source bytes (hook ${HOOK_SHA:0:12}…, client ${CLI_SHA:0:12}…)"
# sync-gate also regenerates the standalone manifest inside the source tree — commit that too
( cd "$APP" && git add examples/claude-attestation-guardrails/MANIFEST.standalone.sha256 2>/dev/null \
  && git commit -q -m "gate source: standalone manifest for $NEW_VER" 2>/dev/null && git push -q && ok "xchk-app standalone manifest committed" ) || ok "xchk-app standalone manifest unchanged"

# ---------- 4. commit plugin ----------
say "4. commit xchk-plugin"
( cd "$PLUG" \
  && git add gate/ MANIFEST.sha256 MANIFEST.standalone.sha256 \
  && { [[ -f plugin.json ]] && git add plugin.json || true; } \
  && { [[ -f .claude-plugin/plugin.json ]] && git add .claude-plugin/plugin.json || true; } \
  && git commit -q -m "xchk-plugin v$NEW_VER — engine-block telemetry + destructive-fs escalation; manifests match the running gate" \
  && ok "xchk-plugin $(git log --oneline -1)" ) || die "xchk-plugin commit failed (nothing to commit is also a failure here — the bump should have changed files)"

# ---------- 5. signed tag ----------
say "5. signed tag v$NEW_VER + push --follow-tags"
( cd "$PLUG"
  if git rev-parse -q --verify "refs/tags/v$NEW_VER" >/dev/null; then
    echo "   · tag v$NEW_VER already exists (pointing at older bytes) — moving it"
    git tag -d "v$NEW_VER" >/dev/null
    git push -q origin ":refs/tags/v$NEW_VER" || true
  fi
  git tag -s "v$NEW_VER" -m "xchk-plugin v$NEW_VER — engine-block telemetry + destructive-fs escalation; manifests match the running gate"
  git push -q --follow-tags
  ok "tag v$NEW_VER → $(git rev-parse --short "v$NEW_VER^{commit}") pushed" ) || die "tagging/push failed (is your signing key available?)"
fi  # end of steps 1-5 (skipped on resume)

# shas of what is being published/installed — recomputed here so the resume
# path has them too; they must equal what the manifests carry.
HOOK_SHA="$(sha "$SRC/hooks/xchk_hook.py")"; CLI_SHA="$(sha "$SRC/xchk_client.py")"
grep -q "$HOOK_SHA  hooks/xchk_hook.py" "$PLUG/MANIFEST.standalone.sha256" \
  || die "standalone manifest does not match the source hook — re-run scripts/sync-gate.sh, then resume"

# ---------- 6. publish both variants ----------
say "6. publish known-good manifests to $BASE"
( cd "$PLUG" && OUT="$(XCHK_BASE="$BASE" ./scripts/publish-release.sh claude 2>&1)"; echo "$OUT" | sed 's/^/   /'
  echo "$OUT" | grep -q "$NEW_VER" || die "publish (plugin) did not mention $NEW_VER — the script reads the version from somewhere not bumped; paste: sed -n '30,60p' scripts/publish-release.sh"
  echo "$OUT" | grep -qiE "FAILED|error" && die "publish (plugin) failed — see above"; true ) || exit 1
( cd "$PLUG" && OUT="$(XCHK_BASE="$BASE" VARIANT=standalone MANIFEST_OVERRIDE="$PLUG/MANIFEST.standalone.sha256" ./scripts/publish-release.sh claude 2>&1)"; echo "$OUT" | sed 's/^/   /'
  echo "$OUT" | grep -qiE "FAILED|error" && die "publish (standalone) failed — see above"; true ) || exit 1
STAND_SHA="$(sha "$PLUG/MANIFEST.standalone.sha256")"
REG="$(curl -s "$BASE/api/gate-releases/claude/$NEW_VER?variant=standalone")"
echo "$REG" | grep -q "\"manifestSha\":\"$STAND_SHA\"" \
  || die "registry's standalone manifest for $NEW_VER is not ours. registry said: $REG"
ok "registry holds our standalone manifest for $NEW_VER (${STAND_SHA:0:12}…) — public, verifiable by anyone"

# ---------- 6b. deploy the app tree the installers FETCH FROM ----------
# A re-fit runs `curl <registry>/examples/claude-attestation-guardrails/... | bash`, i.e. it
# takes the hook from the registry's checkout of xchk-app — NOT from the manifest published in
# step 6. On 12 Sep 2026 a re-fit two minutes after a release laid down the previous version
# because this checkout had not been pulled. Pull it on every registry before anyone re-fits.
say "6b. deploy xchk-app on the registries (the tree re-fits fetch from)"
for h in ${XCHK_DEPLOY_HOSTS:-in.xchk.io xchk.me}; do
  ssh -o ConnectTimeout=15 "sean@$h" "cd /var/www/xchk-app && git pull -q && grep -m1 '^PLUGIN_VERSION' examples/claude-attestation-guardrails/hooks/xchk_hook.py" \
    | grep -q "\"$NEW_VER\"" && ok "$h serves $NEW_VER" || die "$h does not serve $NEW_VER — pull /var/www/xchk-app there before any re-fit"
done

# ---------- 7. install to live ----------
say "7. install to LIVE gate ($LIVE)"
cp "$LIVE/hooks/xchk_hook.py" "$LIVE/hooks/xchk_hook.py.bak.release.$STAMP"
cp "$LIVE/xchk_client.py"     "$LIVE/xchk_client.py.bak.release.$STAMP"
cp "$SRC/hooks/xchk_hook.py"  "$LIVE/hooks/xchk_hook.py"
cp "$SRC/xchk_client.py"      "$LIVE/xchk_client.py"
LIVE_MAN="$(ls "$LIVE" | grep -i '^MANIFEST' | head -1 || true)"
if [[ -n "$LIVE_MAN" ]]; then
  cp "$LIVE/$LIVE_MAN" "$LIVE/$LIVE_MAN.bak.release.$STAMP"
  cp "$PLUG/MANIFEST.standalone.sha256" "$LIVE/$LIVE_MAN"
  ok "live manifest ($LIVE_MAN) replaced with the published standalone manifest"
else
  echo "   ! no MANIFEST* file in $LIVE — the gate will report 'unmanifested'. Copying standalone manifest as MANIFEST.sha256 (tell Claude if the hook expects another name)."
  cp "$PLUG/MANIFEST.standalone.sha256" "$LIVE/MANIFEST.sha256"
fi
rm -rf "$LIVE/__pycache__" "$LIVE/hooks/__pycache__"
[[ "$(sha "$LIVE/hooks/xchk_hook.py")" == "$HOOK_SHA" ]] || die "live hook != source after install"
[[ "$(sha "$LIVE/xchk_client.py")" == "$CLI_SHA" ]]      || die "live client != source after install"
ok "live hook/client are byte-identical to the released source"

say "RELEASED v$NEW_VER"
echo "   The gate's next status ping should report gateIntegrity=verified and the"
echo "   registry's verdict matches-release. Run any gated command, then have Claude"
echo "   read the panel: the 'Gate integrity' row should flip ALARM → ENGAGED."
echo
echo "   Backups: *.bak.release.$STAMP beside each replaced live file."

# NOTES — getting XCHK_ADMIN_TOKEN
#   The publish route wants a Bearer token that resolves to a User with
#   siteAdmin=true: your own Firebase ID token from a logged-in console
#   session. In the console (pewpew.html) open DevTools → Console and run:
#       await getIdToken()
#   copy the string (valid ~1 hour), then in your terminal:
#       export XCHK_ADMIN_TOKEN='<paste>'
#   Agent API keys are refused by design — the gate must never bless itself.

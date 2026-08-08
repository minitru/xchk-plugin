#!/usr/bin/env bash
# Re-vendor gate/ from the source of truth in xchk-app. Heads are packaging,
# never forks — do not edit gate/ files in this repo.
set -euo pipefail
SRC="${XCHK_APP:-/Volumes/2TB-FAST/sean-overflow/src/xchk/xchk-app}/examples/claude-attestation-guardrails"
DST="$(cd "$(dirname "$0")/.." && pwd)/gate"
cp "$SRC/hooks/xchk_hook.py" "$DST/xchk_hook.py"
cp "$SRC/xchk_client.py" "$DST/xchk_client.py"
python3 - "$DST" <<'EOF'
import ast, pathlib, sys
for p in pathlib.Path(sys.argv[1]).glob("*.py"):
    ast.parse(p.read_text())
print("gate/ synced and syntax-checked")
EOF

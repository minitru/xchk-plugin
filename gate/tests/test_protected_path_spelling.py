#!/usr/bin/env python3
"""Regression test for finding F1: the file-path self-protection check must be
at least as broad as the bash spelling screen.

    python3 gate/tests/test_protected_path_spelling.py

is_protected_path() feeds the Write/Edit/Read self-protection denial. Before the
fix it called _resolve(), which expanded ~ but NOT env vars, so a
`$HOME/.xchk/claude.json` (or `${HOME}/...`) spelling resolved to a literal path
and slipped the check while the ~ and absolute spellings were denied. Self-
protection is meant to be grant-independent; it must not depend on whether the
executing tool happens to expand env vars. Every protected root and gate file is
asserted True under its absolute, ~, $HOME, and ${HOME} spellings.

Stdlib only, no network, no gate mutation.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

GATE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GATE))

# Run from a neutral cwd OUTSIDE the checkout. _resolve() calls realpath, which
# resolves a still-relative (unexpanded) "$HOME/..." against cwd; run from inside
# PLUGIN_ROOT that accident lands the path under the plugin root and masks the
# F1 bug. A neutral cwd exposes the real behaviour the executing tool would see.
os.chdir(os.path.dirname(os.path.realpath(os.sep)) or os.sep)

import xchk_hook  # noqa: E402

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"{'ok  ' if cond else 'FAIL'} {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def spellings(abs_path: str) -> list[tuple[str, str]]:
    """Every equivalent spelling of an absolute path under $HOME."""
    home = str(Path.home())
    out = [("absolute", abs_path)]
    if abs_path.startswith(home):
        rel = abs_path[len(home):]
        out += [
            ("tilde", "~" + rel),
            ("$HOME", "$HOME" + rel),
            ("${HOME}", "${HOME}" + rel),
        ]
    return out


def main() -> int:
    home = Path.home()

    # Concrete files under each protected root, plus the gate files by basename.
    targets = [
        home / ".xchk" / "claude.json",
        home / ".xchk" / "config.json",
        xchk_hook.PLUGIN_ROOT / "gate" / "xchk_hook.py",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".cursor" / "settings.json",
        home / ".cursor" / "hooks.json",
    ]
    # Each directory root itself, and each shell-init file.
    for r in xchk_hook.protected_roots():
        targets.append(Path(r))

    for target in targets:
        for label, spelled in spellings(str(target)):
            check(
                f"protected: {spelled}",
                xchk_hook.is_protected_path(spelled),
                f"{label} spelling of {target} was NOT protected",
            )

    # Env-var spellings must hold even when the variable is unset in-process:
    # a residual $ after expansion is fail-safe protected.
    saved = os.environ.pop("HOME", None)
    try:
        check(
            "unset-HOME fail-safe: $HOME/.xchk/claude.json",
            xchk_hook.is_protected_path("$HOME/.xchk/claude.json"),
            "unresolved env-var spelling must fail safe to protected",
        )
        check(
            "unset-HOME fail-safe: ${HOME}/.xchk/claude.json",
            xchk_hook.is_protected_path("${HOME}/.xchk/claude.json"),
            "unresolved env-var spelling must fail safe to protected",
        )
    finally:
        if saved is not None:
            os.environ["HOME"] = saved

    # Sanity: an ordinary unrelated path is NOT protected (no false positives).
    check(
        "not protected: ~/notes/todo.txt",
        not xchk_hook.is_protected_path("~/notes/todo.txt"),
        "unrelated path must not be protected",
    )

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("all protected-path spelling checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

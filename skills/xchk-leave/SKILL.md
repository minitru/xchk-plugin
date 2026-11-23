---
name: xchk-leave
description: Take xChk off this machine the way the registry says to — fetch the registry's own agent-readable leave page and follow it, then read its last lines back. Use when the user asks to leave xChk, uninstall it, take the plate off this machine, or remove the gate.
---

# Leave xChk on this machine

The leave is one line, and the registry serves the instructions for it as a
page an agent reads (23 Nov 2026). This skill is thin on purpose: the page is
the skill, and the registry that issued the plate is the one home of what
leaving does and what must be gone afterwards.

## Steps

1. Find the registry. Read `~/.xchk/claude.json` and take its `base` field;
   if there is no such file or no `base`, use `https://in.xchk.io`. Never
   print the `api_key` beside it.
2. Fetch `<base>/api/agent-leave` and follow it, as written, in order: it has
   you tell the person what goes and what stays, read the script, ask for a
   yes, run the one line, check what must be gone, and report.
3. When the script has finished, read the person its "Removed" and "Kept"
   lists and its last lines, exactly as printed: the `Next:` line names the
   wall, where this machine's section is gone, and `Add a machine` to come
   back.

## What this skill never does

It does not mint an install code, answer an approval, or retire a plate or a
machine licence. A plate the script marks STILL LIVE is the person's to retire
on `<base>/setup.html` → Leave; say so and stop. Anything that needs a
sign-in, a passkey or a code: ask your person.

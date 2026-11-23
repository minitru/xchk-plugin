---
name: xchk-next
description: Say in one line what this machine's xChk plate is, where its wall is, and the one thing to do next. Use when the user asks "what now", "what's my plate", "where do I see it", "is xchk set up", or after an install or a first session when nothing seems to be happening.
---

# What is next

The install ends with a plate on the record and a terminal that stops (the
"Bryan problem", 22 Nov 2026). This skill answers it in one line, from the
config on this machine.

## Steps

1. Read `~/.xchk/claude.json`: the `plate` and `base` fields. Never print the
   `api_key`.
2. If there is no such file, xChk is not on this machine for this agent: say
   so, and point the person at `<base>/api/agent-install` (base
   `https://in.xchk.io` by default), which they can ask you to read and follow.
3. Otherwise say, in one line: the plate, and its wall at
   `<base>/wall.html#plate=<plate>`, where its record and its lamp are.
4. Add the one next step:
   - a learner's plate (`DLR-…`) nobody has claimed: the person opens the link
     the installer printed and signs in; until then the plate has nobody to ask
     and gated actions are refused.
   - a plate with a person: start a new session and do real work; the wall
     shows each step. A gated action asks them on their phone.
   - to leave: `/xchk-leave`.

## What this skill never does

It does not mint an install code, answer an approval, or retire a plate.
Anything that needs a sign-in, a passkey or a code: ask your person.

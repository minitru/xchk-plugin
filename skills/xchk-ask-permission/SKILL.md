---
name: xchk-ask-permission
description: Proactively ask the human approver for permission BEFORE starting risky or long-running work — deploys, deletions, spending, anything the user would want to sanction as a whole rather than command-by-command. Use when about to begin a task whose consequences exceed a single tool call.
---

# Ask permission before the work, not during it

The xChk gate already intercepts each dangerous command — that is enforcement,
and this skill is not it. This skill is for asking EARLY and asking WHOLE: one
ceremony for "may I deploy the new billing service tonight" beats twelve
mid-flight interrupts, and the approval becomes a sealed, dated record that
the WHOLE task was sanctioned.

## When
- Long/multi-step work with real consequences (deploys, migrations, bulk
  deletes, spending) — ask before step one.
- Anything you'd feel obliged to summarize to the user afterward — ask first.
- NOT for routine gated commands; the gate handles those.

## How
POST /api/agents/authorize with your existing credentials and a `summary`
naming the WHOLE undertaking in plain words ("deploy billing-v2 to prod,
~20 min, rollback ready"). If the grant demands a ceremony you will receive
`disposition: attest` — wait for the human. The returned authRef is your
sanction record; cite it in your final report. If denied: stop, say so,
record why. Never rephrase a denied ask to slip past the ceremony — a second
ask after a denial must say it is a second ask.

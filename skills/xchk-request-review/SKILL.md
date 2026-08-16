---
name: xchk-request-review
description: Send an artifact to another principal's desk for a sealed review verdict (an xChk interchange brief) — code, documents, decisions that deserve a second pair of human eyes. Use when the user asks for an external review, or when work product warrants independent sign-off.
---

# Request a review — a sealed second opinion

An outbound brief crosses to another registry's reviewer. Nothing is blocked
while it is out; the verdict comes back as a dual-sealed receipt (their chain
and yours, mutually citing) with the reviewer's commentary as cargo.

## How
1. Hash the exact artifact bytes (sha256) — the verdict binds to that hash;
   a changed byte is a different review.
2. Ask your human to send it from the console's Ask page (review mode), OR use
   the interchange briefs API if your grant allows. State the area honestly and
   ask ONE answerable question.
3. Do not poll. The receipt lands in the sender's bell; status is queryable at
   /api/interchange/receipts-mine (inFlight = in their court).
4. When the verdict returns: report it VERBATIM — verdict word, conditions,
   and the reviewer's note. A "changes" verdict is instructions, not an insult.
   The proof bundle for the auditor is one click on the receipt card.

# What changed, in plain English

For anyone who needs the short version of why benign tool calls were being blocked.

## The setup

Your agent is not one thing. It is a small team of specialist agents. When a question
comes in, a "front desk" agent decides who should handle it and passes the conversation
along - to the billing agent, the claims agent, and so on.

That handoff is a function call named `transfer_to_agent`, and the whole message is tiny:

```json
{"agent_name": "Billing_Agent"}
```

That is it. No member data, no user question, no medical information. It is the agent
equivalent of writing a name on a sticky note and passing it to a coworker.

## What was going wrong

Our integration code sent **every** function call to Prisma AIRS for inspection,
including those internal sticky notes. Two of the AIRS detectors then misjudged them.

**Detector one thought the sticky note was computer code.** AIRS has a detector that
watches for source code leaving your environment. Programming code is full of words
joined by underscores, like `agent_name` and `Billing_Agent`. So does the sticky note.
The detector saw the pattern and said "that looks like code," and the request was blocked.

The proof this is a misjudgment and not a real finding: `{"city": "Philadelphia"}` sails
right through, but `{"city": "Billing_Agent"}` gets blocked. Same structure, same size,
different words. Nothing dangerous happened in either one.

**Detector two was asked a question it had no way to answer.** You also configured
custom topic rules for things your assistant should refuse to discuss, written for real
conversations with real members. Those rules were being applied to the sticky note too.
With only two words to go on, the rule engine had to guess, and it guessed badly: a
handoff to `Agent_X` - a name that means nothing at all - was flagged as a cross-tenant
data access attempt.

## Why everyone thought it was a prompt injection attack

Two things stacked up.

First, when AIRS blocks any tool call, its summary field always says "context poisoning,"
no matter which detector actually fired. Even when the only thing that fired was the
source-code detector, the summary still says "context poisoning."

Second, our code turned every block into the same sentence: `"Tool call blocked by
security policy."` One message for all causes.

So the logs said "context poisoning," the app said "blocked by security policy," and
everyone reasonably concluded the system was catching prompt injection attacks. It was
not. The injection detector never fired once.

## What we changed

**1. We stopped sending the internal sticky notes to AIRS.** `transfer_to_agent` is your
agent talking to itself. It carries no user content, so inspecting it protected nothing.
Now it is skipped entirely. Real tools - the ones that look up orders, query systems, or
call outside services - are still fully inspected, on both the request and the result.

**2. The tool layer can now use its own security profile.** Model conversations and tool
calls look nothing alike, so they should not be judged by the same rules. You can now
point tool inspection at a profile without the source-code pattern and without the
conversational topic rules, while your main profile stays exactly as it is.

**3. Block messages now say which detector fired.** Instead of one generic sentence, a
block now reports `"airs_detections": ["source_code"]`. If this happens again, you will
know in seconds whether it was a real threat or a misfire, without opening a ticket.

**4. We stopped inspecting the same content twice.** Previously the request arguments
were sent for inspection twice - once before the tool ran and once after. Now the
arguments are checked once and the result is checked once. Half the calls, half the
delay, and half the chances of a mistaken block.

## What this means for you

- The false positives on agent handoffs are gone.
- Real security coverage is unchanged. Prompt injection, malicious code, toxic content,
  bad URLs, and sensitive data detection all still run on every real tool call and every
  model conversation. We tested this: a genuine injection attempt hidden in tool
  arguments is still caught and blocked.
- Your agents will be a little faster and use fewer scan credits, because we removed
  inspections that were never protecting anything.

## One thing to set up on your side

Create a second security profile for the tool layer and set `AIRS_TOOL_PROFILE_NAME` to
its name. Build it from your current profile with two changes: use a data-protection
profile that does not include the Source Code pattern, and leave the custom topics off.
Keep everything else switched on.

If you skip this step, the code still works and the handoff false positives are still
fixed - you would just remain exposed to the same misjudgment on your other tools'
arguments.

---

Verified against a live AIRS tenant on 2026-08-24. Run `python verify.py` to reproduce;
checks `[5a]` through `[5c]` cover exactly this issue.

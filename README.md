# Prisma AIRS AI Runtime for Google ADK (no gateway)

Inline Prisma AIRS protection for [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/)
agents, with **no gateway or proxy in the path**. The integration is a small set of
ADK callbacks that scan prompts, model responses, and tool calls/results against the
Prisma AIRS AI Runtime API and block in-process.

**Unofficial example. Not a Palo Alto Networks product and not supported by Palo Alto Networks. Provided as-is, without warranty, for reference and testing only.**

```
                 your ADK agent
   user  ->  before_model_callback  ->  model  ->  after_model_callback  ->  user
                     |                                      |
              scan the prompt                       scan the response
                     |                                      |
             before_tool_callback  ->  tool  ->  after_tool_callback
                     |                                      |
            scan the tool call (pre-exec)         scan the tool result
                                  \              /
                            Prisma AIRS AI Runtime API
```

Because the scan happens inside the agent, AIRS sees not just prompt and response text
but the **tool calls themselves** (as AIRS `tool_event`s), which a model-proxy gateway
cannot. That makes this the stronger pattern for agentic / tool-using workloads.

## Disclaimer and support

This is an independent, community-maintained **example**, created to illustrate the
integration pattern. It is **not a Palo Alto Networks product**, is **not supported by
Palo Alto Networks** (or by the author), and is provided **as-is, without warranty of
any kind**. Review and harden it yourself before any production use.

## Why no gateway

A gateway (for example an AIRS guardrail on an LLM proxy) is simple and needs no agent
code, but it only sees the prompt and the response as text. Scanning **inside** the
agent additionally covers the tool layer - the part of an agent that actually takes
actions - and lets you scan tool arguments before a tool runs and tool results before
they re-enter the model. See [`prisma-airs-adk-litellm`](https://github.com/scthornton/prisma-airs-adk-litellm)
for the gateway pattern; use whichever fits, or both.

## What it does

| Hook | Scans | On block |
|------|-------|----------|
| `before_model_callback` | the user prompt | skips the model, returns a safe message |
| `after_model_callback` | the model response | replaces the response with a safe message |
| `before_tool_callback` | the tool call + arguments (as an AIRS `tool_event`) | the tool does not run; returns an error result |
| `after_tool_callback` | the tool result (as an AIRS `tool_event` with output) | withholds the result |

Detections come from your AIRS security profile: prompt injection, jailbreaks, toxic
content, malicious code and URLs, sensitive-data / DLP, and agent / tool-call threats
(context poisoning, malicious tool invocation, credential leakage).

## Try it in 2 minutes

You only need your AIRS API key and profile name. **No model or LLM key is required** -
the check uses a built-in fake model, so it runs anywhere.

```bash
git clone https://github.com/scthornton/prisma-airs-adk-runtime
cd prisma-airs-adk-runtime
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export AIRS_API_KEY="<your x-pan-token from Strata Cloud Manager>"
export AIRS_API_PROFILE_NAME="<your AIRS security profile name>"

python verify.py
```

You should see a benign prompt allowed, and a prompt injection, a harmful response, and
a malicious tool call each blocked by AIRS - all inside a running ADK agent.

To run a real agent against a live model (defaults to Gemini, needs `GOOGLE_API_KEY`):

```bash
python example_agent.py
```

## Use it in your agent

```python
from google.adk.agents import Agent
from airs_guard import AirsGuard

guard = AirsGuard()  # reads AIRS_API_KEY, AIRS_API_PROFILE_NAME from env

agent = Agent(
    name="assistant",
    model="gemini-2.0-flash",          # or LiteLlm(...) for Azure/Bedrock/etc.
    tools=[...],
    before_model_callback=guard.before_model,
    after_model_callback=guard.after_model,
    before_tool_callback=guard.before_tool,
    after_tool_callback=guard.after_tool,
)
```

That is the whole integration. `airs_guard.py` is a single dependency-light file
(`httpx` + ADK) you can copy into your project.

## Validation results

Verified end-to-end against a live Prisma AIRS tenant using a deterministic fake model
(so the result depends only on the AIRS + ADK wiring), with `google-adk` 1.3.0 and
`httpx`.

| Scenario | Result |
|----------|--------|
| Benign prompt | allowed; model answer returned |
| Prompt injection | blocked before the model is called |
| Toxic / harmful model response | blocked before it reaches the user |
| Benign tool call | allowed |
| Malicious tool-call arguments | blocked as an AIRS `tool_event` (the tool never runs) |

Reproduce with `python verify.py`.

## Configuration

`AirsGuard()` accepts (env defaults in brackets):

| Arg | Default | Meaning |
|-----|---------|---------|
| `api_key` | `AIRS_API_KEY` | AIRS API key (x-pan-token) |
| `profile_name` | `AIRS_API_PROFILE_NAME` | AIRS security profile name |
| `api_base` | `AIRS_API_BASE` or US region | AIRS scan endpoint (set for other regions) |
| `timeout` | `30.0` | per-scan timeout, seconds |
| `fail_open` | `False` | if True, allow on scan error; default is fail-closed (block) |
| `block_message` | safe text | message returned to the agent on a block |
| `tool_profile_name` | `AIRS_TOOL_PROFILE_NAME`, else `profile_name` | security profile used for tool_event scans |
| `skip_tools` | `{"transfer_to_agent"}` | tool names never sent to AIRS |

## Give the tool layer its own profile

The model layer and the tool layer see different content and need different policy.
Point `tool_profile_name` at a profile that does **not** include the Source Code DLP
data pattern and does **not** carry conversational custom topics:

```python
guard = AirsGuard(tool_profile_name="my-app-tool-layer")
```

Keep prompt injection, malicious code, URL, toxic content, and real PII/PHI DLP on.

**Why.** Tool arguments are JSON with identifier-style keys by protocol definition, and
the DLP source-code detector reads that as code: `{"agent_name": "Billing_Agent"}` and
`{"member_id": "A12345"}` both block as `source_code`, while `{"city": "Philadelphia"}`
passes. It is a classifier rather than a regex, so renaming arguments is not a reliable
workaround. Separately, custom topics authored for user conversation have almost nothing
to classify in a short tool payload and will guess. Verified live 2026-08-24.

## Orchestration hops are not scanned

`skip_tools` defaults to `{"transfer_to_agent"}` - the agent framework's own sub-agent
delegation primitive. It is not an MCP server tool: it is the framework talking to
itself, and its arguments are pure orchestration metadata carrying no user content.
Scanning it adds no security coverage while generating false positives, latency, and
token spend. Add your own framework-internal control functions to the set as needed.

Real MCP server tools and application tools are unaffected and still scanned on both
the call and the result.

## Reading a block

A tool block now reports which detector actually fired:

```json
{"error": "Tool call blocked by security policy",
 "airs_scan_id": "9663975c-...",
 "airs_detections": ["source_code"]}
```

Use `airs_detections`. Do **not** read `tool_detected.summary.threats`: AIRS stamps
`"context poisoning"` there for *any* malicious tool_event verdict, even when the only
detection is `source_code`. That label is the reason DLP and topic misfires are
routinely reported as prompt injection.

## Notes

- **Fail-closed by default.** If the AIRS service cannot be reached, requests are
  blocked rather than passed unprotected. Set `fail_open=True` to invert this.
  Note the operational consequence: if the API key is revoked or removed, every
  request blocks. Alert on a sustained block rate rather than discovering it from users.
- **The call arguments are scanned once.** `before_tool` scans the arguments;
  `after_tool` scans only the result. Sending both at both points doubles token cost
  and latency and gives the same content two chances to false-positive.
- **Regions.** Set `AIRS_API_BASE` to the regional scan endpoint that matches your
  tenant (US, EU/Germany, India, Singapore).
- **DLP.** To block sensitive data, the AIRS security profile must actually select the
  data patterns (PII, PHI, payment data), not only set the block action.
- **Enterprise TLS.** In an SSL-inspecting network, point Python at your corporate CA
  bundle (`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`) so the scan calls succeed.
- **ADK version.** `google-adk` 1.3.4 is not on public PyPI; this was verified on 1.3.0.
  The callback API is stable across ADK 1.x. Newer ADK also has a plugin system
  (`google.adk.plugins`) - you can wrap these same `AirsGuard` methods in a `BasePlugin`
  to protect every agent from one place.

## Files

| File | Purpose |
|------|---------|
| `airs_guard.py` | the integration - copy this into your project |
| `example_agent.py` | runnable ADK agent wired with all four callbacks |
| `verify.py` | end-to-end verification against your AIRS tenant (fake model) |
| `.env.example` | required environment variables |
